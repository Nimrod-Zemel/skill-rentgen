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
4. The hook line is written by code from hashes. It quotes nothing from
   the skills, so a skill cannot use it to speak to the agent.
5. The registry file is written atomically, under a lock, and never
   outside its folder.
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import os
import stat
import time

from common import SKILL_DIR, TOOL_VERSION, clean_snippet, dump_json, load_json

SCHEMA = "1.1"
FULL_CHECK_DAYS = 7
SETTINGS_KEYS = ("hooks", "mcpServers", "env", "apiKeyHelper", "statusLine", "enabledPlugins",
                 "extraKnownMarketplaces")
SKIP_DIRS = {".git"}


def home_dir(override=None):
    return os.path.abspath(override or os.path.join(os.path.expanduser("~"), ".skill-rentgen"))


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
        for key in ("added", "removed", "changed"):
            if item.get(key):
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
