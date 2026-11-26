"""The adoption registry: what you approved, and whether it changed since.

WHY: a scan is true for one moment. A skill that was clean when you
installed it can change later, through an update or because another tool
rewrote it. The registry records a hash of every file at the moment you
approved a skill. A check compares the files on disk to that record and
says exactly what was added, removed or changed. Nothing in the registry
is trusted from the skill itself; it holds paths, hashes and rule ids.

A change is one of three things, and the report says which:
- updated: a plugin whose installed version is newer than the one approved.
- tampered: the same version, with different files. Somebody touched them.
- changed: a plain skill folder whose files differ (it has no version).

Rules that tests check:
1. A skill whose verdict is "do not install" is never recorded.
2. A "caution" skill is recorded only with an explicit acceptance, and the
   record keeps what was accepted.
3. A check never changes what was approved. Approving a change is a new adopt.
   The one thing a check may add is the file list of a record that was
   carried in as a single hash, once the files on disk matched that hash.
4. The hook line is written by code from hashes. It quotes nothing from
   the skills, so a skill cannot use it to speak to the agent.
5. The registry file is written atomically, under a lock, and never
   outside its folder.
6. The registry can be carried to another machine or session as one small
   file. That file is checked for damage when it is read, and nothing in it
   is taken as an instruction. It is as trusted as the place you kept it.
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import os
import stat
import time

from common import SKILL_DIR, TOOL_VERSION, clean_snippet, dump_json, load_json, rule_file

SCHEMA = "1.1"
FULL_CHECK_DAYS = 7
SETTINGS_KEYS = ("hooks", "mcpServers", "env", "apiKeyHelper", "statusLine", "enabledPlugins",
                 "extraKnownMarketplaces")
SKIP_DIRS = {".git"}
CARRY_KIND = "skill-rentgen-registry"
CARRY_NAME = "skill-rentgen-registry.json"
CARRY_CAP = 8 * 1024 * 1024
_KEY = "0123456789abcdef"
VERDICTS = ("approve", "approve_with_notes", "caution")


def home_dir(override=None):
    """Where the registry lives: --home, then SKILL_RENTGEN_HOME, then
    ~/.skill-rentgen."""
    chosen = override or os.environ.get("SKILL_RENTGEN_HOME") or os.path.join(
        os.path.expanduser("~"), ".skill-rentgen")
    return os.path.abspath(chosen)


def short_lived(environ=None):
    """The name of the sign that this machine's disk does not outlast the
    session (a cloud session, a build runner). Empty when there is none."""
    environ = os.environ if environ is None else environ
    for name in rule_file("places.json").get("short_lived_env", []):
        if environ.get(name):
            return name
    return ""


def registry_path(home):
    return os.path.join(home, "registry.json")


def _empty():
    return {"schema_version": SCHEMA, "skills": {}, "settings": {}, "agent_settings": {}}


def load(home):
    try:
        data = load_json(registry_path(home))
    except (OSError, ValueError):
        return _empty()
    if not isinstance(data, dict) or not isinstance(data.get("skills"), dict):
        return _empty()
    data.setdefault("settings", {})
    data.setdefault("agent_settings", {})
    data["schema_version"] = SCHEMA
    return data


@contextlib.contextmanager
def locked(home, wait=10):
    """One writer at a time. A lock older than a minute is taken as abandoned."""
    os.makedirs(home, exist_ok=True)
    try:
        os.chmod(home, 0o700)
    except OSError:
        pass
    path = os.path.join(home, "registry.lock")
    deadline = time.time() + wait
    handle = None
    while handle is None:
        try:
            handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                if time.time() - os.stat(path).st_mtime > 60:
                    os.unlink(path)
                    continue
            except OSError:
                continue
            if time.time() > deadline:
                raise OSError("the registry is locked by another run")
            time.sleep(0.1)
    try:
        yield
    finally:
        os.close(handle)
        try:
            os.unlink(path)
        except OSError:
            pass


def save(home, data):
    data["schema_version"] = SCHEMA
    with locked(home):
        dump_json(data, registry_path(home))


def state_path(home):
    return os.path.join(home, "state.json")


def load_state(home):
    """Bookkeeping that is not an approval: when a full check last ran, and
    which never-checked skills were already mentioned."""
    try:
        data = load_json(state_path(home))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("full_check", {})
    data.setdefault("noted", [])
    return data


def save_state(home, state):
    try:
        os.makedirs(home, exist_ok=True)
        dump_json(state, state_path(home))
    except OSError:
        pass


def skill_id(path, plugin_key=""):
    """A plugin is known by its name and marketplace, so that an update to
    a new folder is still the same record. A plain skill is known by its path."""
    basis = "plugin:" + plugin_key if plugin_key else os.path.realpath(path)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def quick_stats(path):
    """Size and change time of every regular file, without reading any.
    Follows the same walk as the scan: no links, no .git folder."""
    out, stack = {}, [""]
    while stack:
        rel_dir = stack.pop()
        try:
            entries = list(os.scandir(os.path.join(path, rel_dir)))
        except OSError:
            return None
        for entry in entries:
            rel = (rel_dir + "/" + entry.name) if rel_dir else entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                return None
            if stat.S_ISDIR(info.st_mode):
                if entry.name not in SKIP_DIRS:
                    stack.append(rel)
            elif stat.S_ISREG(info.st_mode):
                out[rel] = [info.st_size, info.st_mtime_ns]
            if len(out) > 200000:
                return None
    return out


def make_record(path, summary, report, accepted, upstream=None, plugin=None, how="adopt"):
    """Build the record for one approved skill from a finished scan."""
    stats = quick_stats(path) or {}
    files = summary.get("files_sha256", {})
    return {
        "name": summary["name"],
        "path": os.path.realpath(path),
        "adopted_at": now(),
        "how": how,
        "verdict": summary["internal"],
        "accepted": sorted(accepted),
        "reasons": report["verdict"]["reasons"],
        "tool_version": TOOL_VERSION,
        "rules_version": report["tool"]["rules_version"],
        "hash_algo": "sha256",
        "file_map_sha256": report["hashes"].get("file_map_sha256", ""),
        "files": files,
        "stats": {rel: stats[rel] for rel in files if rel in stats},
        "upstream": upstream or {},
        "plugin": plugin or {},
    }


def looks_same(record, path):
    """True when no file was added, removed, resized or rewritten since the
    record was made, judged by size and change time alone."""
    stored = record.get("stats")
    if not stored or set(stored) != set(record.get("files", {})):
        return False
    return quick_stats(path) == stored


def full_check_due(state, key):
    last = state["full_check"].get(key)
    if not last:
        return True
    try:
        then = datetime.datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        return True
    age = datetime.datetime.now(datetime.timezone.utc) - then
    return age > datetime.timedelta(days=FULL_CHECK_DAYS)


def tree_hash(files):
    """One hash for a whole file list: every path with its file hash, in
    path order. Two folders with the same files give the same value."""
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(rel.encode("utf-8", "surrogatepass") + b"\0"
                      + str(files[rel]).encode("ascii", "replace") + b"\n")
    return digest.hexdigest()


# ------------------------------------------------- carrying the registry

def _body_hash(body):
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def export_data(home):
    """The registry as one small document that can be kept elsewhere. Each
    record keeps its facts and one hash for all its files; the long list of
    file hashes stays behind and is rebuilt on the first check."""
    data, state = load(home), load_state(home)
    skills = {}
    for key, record in data["skills"].items():
        slim = {name: value for name, value in record.items() if name not in ("files", "stats")}
        files = record.get("files")
        if isinstance(files, dict) and files:
            slim["tree"], slim["file_count"] = tree_hash(files), len(files)
        skills[key] = slim
    body = {"skills": skills, "settings": data["settings"],
            "agent_settings": data["agent_settings"], "noted": state["noted"][-500:]}
    return {"kind": CARRY_KIND, "schema_version": "1.0", "exported_at": now(),
            "tool_version": TOOL_VERSION, "body": body, "sha256": _body_hash(body)}


def _clean_record(record):
    """Keep only the fields a record has, each with the type it must have."""
    if not isinstance(record, dict) or record.get("verdict") not in VERDICTS:
        return None
    out = {}
    for name in ("name", "path", "adopted_at", "how", "verdict", "tool_version", "rules_version",
                 "hash_algo", "file_map_sha256", "tree"):
        value = record.get(name, "")
        if not isinstance(value, str) or len(value) > 4096:
            return None
        out[name] = value
    if not out["name"] or not out["path"] or out["hash_algo"] != "sha256":
        return None
    files = record.get("files")
    if files is not None:
        if not isinstance(files, dict) or not all(
                isinstance(rel, str) and isinstance(digest, str) and len(digest) == 64
                and set(digest) <= set(_KEY) for rel, digest in files.items()):
            return None
        out["files"], out["stats"] = files, {}
    elif len(out["tree"]) != 64 or not set(out["tree"]) <= set(_KEY):
        return None
    else:
        out["files"], out["stats"] = {}, {}
    count = record.get("file_count", 0)
    out["file_count"] = count if isinstance(count, int) and 0 <= count < 10 ** 7 else 0
    for name in ("accepted", "reasons"):
        value = record.get(name, [])
        out[name] = [item for item in value if isinstance(item, str)][:200] \
            if isinstance(value, list) else []
    for name, fields in (("upstream", ("url", "commit")), ("plugin", ("key", "version"))):
        value = record.get(name) if isinstance(record.get(name), dict) else {}
        out[name] = {field: value[field] for field in fields
                     if isinstance(value.get(field), str) and len(value[field]) < 500}
    return out


def read_carry(path):
    """Read and check a carried registry file. Raises ValueError with a
    plain reason when it is not one, or was damaged."""
    try:
        if os.path.getsize(path) > CARRY_CAP:
            raise ValueError("the file is too large to be a registry file")
        carry = load_json(path)
    except OSError as error:
        raise ValueError("could not read the file: %s" % clean_snippet(str(error), 100))
    except (ValueError, RecursionError):
        raise ValueError("the file is not a registry file")
    if not isinstance(carry, dict) or carry.get("kind") != CARRY_KIND \
            or not isinstance(carry.get("body"), dict):
        raise ValueError("the file is not a registry file")
    if carry.get("schema_version") != "1.0":
        raise ValueError("the file was written by a newer version of this tool")
    if _body_hash(carry["body"]) != carry.get("sha256"):
        raise ValueError("the file was changed or damaged after it was written")
    return carry


def import_data(home, carry, replace=False):
    """Take approvals from a carried registry into this one. A record that
    is already here and is newer stays. Returns counts."""
    body = carry["body"]
    data, state = load(home), load_state(home)
    if replace:
        data["skills"] = {}
    taken = kept = dropped = 0
    incoming = body.get("skills") if isinstance(body.get("skills"), dict) else {}
    for key, raw in sorted(incoming.items()):
        valid_key = isinstance(key, str) and len(key) == 12 and set(key) <= set(_KEY)
        record = _clean_record(raw) if valid_key else None
        if record is None:
            dropped += 1
            continue
        here = data["skills"].get(key)
        if here and str(here.get("adopted_at", "")) >= record["adopted_at"]:
            kept += 1
            continue
        data["skills"][key] = record
        taken += 1
    settings = body.get("settings") if isinstance(body.get("settings"), dict) else {}
    for name in ("lang", "email"):
        if isinstance(settings.get(name), str) and len(settings[name]) < 200:
            data["settings"].setdefault(name, settings[name])
    agent = body.get("agent_settings") if isinstance(body.get("agent_settings"), dict) else {}
    files = agent.get("files")
    if isinstance(files, dict) and isinstance(agent.get("recorded_at"), str) and all(
            isinstance(path, str) and isinstance(keys, dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in keys.items())
            for path, keys in files.items()):
        if agent["recorded_at"] > str(data["agent_settings"].get("recorded_at", "")):
            data["agent_settings"] = {"recorded_at": agent["recorded_at"], "files": files}
    noted = body.get("noted") if isinstance(body.get("noted"), list) else []
    state["noted"] = sorted(set(state["noted"]) | {p for p in noted if isinstance(p, str)})[-2000:]
    save(home, data)
    save_state(home, state)
    return {"taken": taken, "kept": kept, "dropped": dropped,
            "exported_at": str(carry.get("exported_at", ""))[:40]}


def diff(record, current):
    """Compare stored hashes to current ones. Returns sorted lists of paths."""
    old = record.get("files", {})
    added = sorted(set(current) - set(old))
    removed = sorted(set(old) - set(current))
    changed = sorted(rel for rel in set(old) & set(current) if old[rel] != current[rel])
    return {"added": added, "removed": removed, "changed": changed}


# --------------------------------------------------------- agent settings

def settings_files(cwd=None):
    home = os.path.expanduser("~")
    here = cwd or os.getcwd()
    return [os.path.join(home, ".claude", "settings.json"),
            os.path.join(home, ".claude", "settings.local.json"),
            os.path.join(home, ".claude.json"),
            os.path.join(here, ".claude", "settings.json"),
            os.path.join(here, ".claude", "settings.local.json"),
            os.path.join(here, ".mcp.json")]


def settings_fingerprint(paths):
    """A hash for each watched key of each agent settings file that exists.
    Only keys that make something run by itself are watched; the rest of a
    settings file changes all the time and says nothing."""
    out = {}
    for path in paths:
        try:
            if os.path.getsize(path) > 20 * 1024 * 1024:
                continue
            data = load_json(path)
        except (OSError, ValueError, RecursionError):
            continue
        if not isinstance(data, dict):
            continue
        keys = {}
        for key in SETTINGS_KEYS:
            if key in data:
                text = json.dumps(data[key], sort_keys=True, ensure_ascii=True)
                keys[key] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        out[os.path.realpath(path)] = keys
    return out


def settings_diff(stored, current):
    """Which watched keys differ from the baseline. Returns [{path, keys}]."""
    changes = []
    for path in sorted(set(stored) | set(current)):
        old, new = stored.get(path, {}), current.get(path, {})
        keys = sorted(key for key in set(old) | set(new) if old.get(key) != new.get(key))
        if keys:
            changes.append({"path": path, "keys": keys})
    return changes


# ---------------------------------------------------------------- reports

def strings(lang):
    """The registry sentences and the verdict names, from the i18n files."""
    data = load_json(os.path.join(SKILL_DIR, "i18n", lang + ".json"))
    return data["registry"], data["verdict"]


def hook_line(changes, lang="he", unknown=0, settings=()):
    """One short alert for the start of a session. Code-written, no quotes."""
    if not changes and not unknown and not settings:
        return ""
    text, _ = strings(lang)
    lines = []
    if changes:
        parts = []
        for item in changes[:5]:
            name = clean_snippet(item["name"], 40)
            if item["status"] in ("missing", "updated", "tampered", "upstream", "rules"):
                parts.append("%s (%s)" % (name, text["st_" + item["status"]]))
            else:
                count = len(item["added"]) + len(item["removed"]) + len(item["changed"])
                parts.append("%s (%d %s)" % (name, count, text["files_word"]))
        more = len(changes) - len(parts)
        lines.append(text["hook"].format(n=len(changes), items=", ".join(parts),
                                         more=text["hook_more"].format(n=more) if more > 0 else ""))
    if settings:
        lines.append(text["hook_settings"].format(n=sum(len(item["keys"]) for item in settings)))
    if unknown:
        lines.append(text["hook_unknown"].format(n=unknown))
    return " ".join(lines)


def change_report(changes, lang="he", unknown=(), settings=()):
    """A plain-text report of what changed. Paths are data from disk."""
    text, verdicts = strings(lang)
    lines = ["# " + text["title"], ""]
    if not changes and not unknown and not settings:
        lines.append(text["none"])
        return "\n".join(lines) + "\n"
    for item in changes:
        lines.append("## %s" % clean_snippet(item["name"], 60))
        lines.append("")
        lines.append("- **%s**" % text["what_" + item["status"]])
        lines.append("- %s: `%s`" % (text["location"], clean_snippet(item["path"], 200)))
        if item.get("version_then") or item.get("version_now"):
            lines.append("- %s: `%s`. %s: `%s`" % (
                text["version_then"], clean_snippet(item.get("version_then") or "?", 40),
                text["version_now"], clean_snippet(item.get("version_now") or "?", 40)))
        if item.get("carried") and item.get("changed") == ["?"]:
            lines.append("- " + text["carried_changed"])
        for key in ("added", "removed", "changed"):
            if item.get(key) and item[key] != ["?"]:
                shown = ", ".join("`%s`" % clean_snippet(p, 80).replace("`", "'") for p in item[key][:12])
                extra = len(item[key]) - 12
                lines.append("- %s (%d): %s%s" % (text[key], len(item[key]), shown,
                                                  (" +%d" % extra) if extra > 0 else ""))
        if item.get("verdict_now"):
            lines.append("- %s: %s. %s: %s" % (
                text["then"], verdicts.get(item["verdict_then"], item["verdict_then"]),
                text["now"], verdicts.get(item["verdict_now"], item["verdict_now"])))
        if item.get("upstream_commit"):
            lines.append("- " + text["upstream"].format(commit=item["upstream_commit"][:10]))
        if item.get("upstream_moved"):
            lines.append("- " + text["upstream_moved"])
        if item.get("rules_changed"):
            lines.append("- " + text["rules_changed"])
        lines.append("")
    if settings:
        lines += ["## %s" % text["settings_title"], "", text["settings_intro"], ""]
        for item in settings:
            lines.append("- `%s`: %s" % (clean_snippet(item["path"], 200),
                                         ", ".join("`%s`" % key for key in item["keys"])))
        lines += ["", text["settings_reapprove"], ""]
    if unknown:
        lines += ["## %s" % text["unknown_title"], "", text["unknown_intro"], ""]
        for item in list(unknown)[:40]:
            lines.append("- `%s` (`%s`)" % (clean_snippet(item["name"], 60),
                                           clean_snippet(item["path"], 200)))
        lines.append("")
    if changes:
        lines.append(text["reapprove"])
    return "\n".join(lines) + "\n"


def email_draft(changes, recipient, lang="he", unknown=(), settings=()):
    """Recipient, subject and body for an alert. The tool does not send mail."""
    text, _ = strings(lang)
    names = ", ".join(clean_snippet(item["name"], 40) for item in changes[:6])
    return "To: %s\nSubject: %s\n\n%s: %s\n%s\n" % (
        clean_snippet(recipient, 120), text["subject"].format(n=len(changes) + len(settings)),
        text["skills"], names or "-", change_report(changes, lang, unknown, settings))
