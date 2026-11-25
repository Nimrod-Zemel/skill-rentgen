"""The trial run: start what a skill would start by itself, inside a sealed
container, and report what it tried to do.

WHY: a scan reads the files and reasons about what the code could do. A
trial run is the second half of the check: it starts the skill's own
commands in a throw-away home that holds decoy secrets, with no network,
and writes down what they reached for. It is evidence of what was seen in
one run. It is not evidence that a skill is safe.

Rules that tests check:
1. Nothing of the skill ever runs on this machine. If no container engine
   answers, the trial reports "not checked" and stops.
2. The container has no network, no writable path on this disk, a
   read-only system, no extra privileges, and limits on time, memory and
   processes.
3. The job goes in on standard input and the result comes back on standard
   output, marked with a value made for this run. A result without that
   mark is not a result.
4. The verdict of a trial comes from the rules files, like every other
   verdict here. A quiet trial never upgrades a scan.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import uuid

from common import (SEV_RANK, SKILL_DIR, clean_snippet, finding, is_test_path, load_json,
                    path_matches, read_text, rule_file)

DEFAULT_IMAGE = "python:3.12-slim"
ENGINES = ("docker", "podman")
BASE = "/sandbox"
HERE = os.path.dirname(os.path.abspath(__file__))
SANDBOX_FILES = ("runner.py", "audit_hook.py", "node_hook.js", "shim.sh")
COPY_BYTES = 300 * 1024 * 1024
COPY_FILES = 20000
MAX_COMMANDS = 24
MAX_SCRIPTS = 10
RESULT_CAP = 64 * 1024 * 1024
EXIT = {"quiet": 0, "notes": 0, "caution": 1, "blocked": 2}
READERS = {"cat", "head", "tail", "less", "more", "cp", "mv", "base64", "xxd", "od", "strings",
           "tar", "zip", "gzip", "grep", "egrep", "awk", "sed", "dd", "scp", "rsync", "openssl",
           "gpg", "source", ".", "jq", "cut", "sort", "tee", "diff", "nl", "tac", "hexdump"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "", "none", "ip6-localhost"}
GIT_REMOTE = {"clone", "fetch", "pull", "push", "ls-remote", "submodule", "remote"}
RUNNERS = {"python": "python3", "shell": "bash", "js": "node"}
URL = re.compile(r"[a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?(\[[0-9a-f:]+\]|[^/:\s?#\"']+)", re.I)
AT_HOST = re.compile(r"(?:^|[\s=])(?:[\w.-]+@)([\w-]+(?:\.[\w-]+)+)")
BARE_HOST = re.compile(r"(?:^|\s)((?:[\w-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?=[\s:/]|$)", re.I)
MISSING = re.compile(r"(?:^|[\s:])([\w.+-]+): (?:command )?not found", re.I)


class NotRun(Exception):
    """The trial could not be carried out. `reason` is a key in the i18n files."""

    def __init__(self, reason, detail=""):
        Exception.__init__(self, reason)
        self.reason, self.detail = reason, clean_snippet(detail, 200)


# ------------------------------------------------------------------ engine

def find_engine(prefer=None, which=shutil.which, call=subprocess.call):
    """The first container engine that answers. None when there is none."""
    names = [prefer] if prefer else list(ENGINES)
    for name in names:
        if name not in ENGINES:
            continue
        path = which(name)
        if not path:
            continue
        try:
            code = call([path, "info"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=25)
        except (OSError, subprocess.SubprocessError):
            continue
        if code == 0:
            return name, path
    return None


def container_argv(engine_path, name, image, skill_dir, tool_dir):
    """The full command line. Every isolation setting is spelled out here."""
    return [engine_path, "run", "--rm", "-i", "--name", name,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256", "--memory", "1g", "--memory-swap", "1g",
            "--user", "1000:1000", "--hostname", "sandbox", "--workdir", BASE,
            "--tmpfs", BASE + ":rw,exec,nosuid,nodev,size=768m,mode=1777",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=128m,mode=1777",
            "-v", skill_dir + ":/sr/skill:ro,z",
            "-v", tool_dir + ":/sr/tool:ro,z",
            "-v", os.path.join(tool_dir, "passwd") + ":/etc/passwd:ro,z",
            "-v", os.path.join(tool_dir, "group") + ":/etc/group:ro,z",
            "--entrypoint", "python3", image, "-I", "-B", "/sr/tool/runner.py"]


def _fsize_limit():
    if os.name != "posix":
        return None
    try:
        import resource
    except ImportError:
        return None

    def apply():
        try:
            hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
            value = RESULT_CAP if hard == resource.RLIM_INFINITY else min(RESULT_CAP, hard)
            resource.setrlimit(resource.RLIMIT_FSIZE, (value, hard))
        except (ValueError, OSError):
            pass
    return apply


def run_container(engine, image, skill_dir, tool_dir, job, wait, scratch):
    """Start the container, hand it the job, return the runner's report."""
    name = "skill-rentgen-trial-" + uuid.uuid4().hex[:12]
    argv = container_argv(engine[1], name, image, skill_dir, tool_dir)
    out_path, err_path = os.path.join(scratch, "stdout"), os.path.join(scratch, "stderr")
    timed_out = False
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                    preexec_fn=_fsize_limit())
        except OSError as error:
            raise NotRun("engine_failed", str(error))
        try:
            proc.communicate(json.dumps(job).encode("utf-8"), timeout=wait)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            for action in (["kill", name], ["rm", "-f", name]):
                try:
                    subprocess.call([engine[1]] + action, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                except (OSError, subprocess.SubprocessError):
                    pass
            if timed_out:
                proc.kill()
                proc.wait()
    with open(err_path, "rb") as handle:
        stderr = handle.read(20000).decode("utf-8", "replace")
    raw = parse_result(out_path, job["nonce"])
    if raw is None:
        if timed_out:
            raise NotRun("no_result", "the sandbox did not answer in time")
        if proc.returncode == 125 or "Unable to find image" in stderr or "pull access" in stderr:
            raise NotRun("image_missing", stderr.strip().split("\n")[-1])
        raise NotRun("no_result", stderr.strip().split("\n")[-1] if stderr.strip() else
                     "exit code %s" % proc.returncode)
    return raw


def parse_result(path, nonce):
    """The last line that carries this run's mark, as a dict. None otherwise."""
    prefix = ("SR-RESULT-%s " % nonce).encode("ascii")
    found = None
    try:
        with open(path, "rb") as handle:
            for line in handle:
                if line.startswith(prefix):
                    found = line[len(prefix):]
    except OSError:
        return None
    if found is None:
        return None
    try:
        raw = json.loads(found.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("commands"), list):
        return None
    return raw


# ------------------------------------------------------------- preparation

def copy_tree(root, dest):
    """A plain copy of the skill: regular files only, readable by anyone."""
    total = count = 0
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(folder, d)) and d != ".git"]
        target = os.path.join(dest, os.path.relpath(folder, root))
        os.makedirs(target, exist_ok=True)
        os.chmod(target, 0o755)
        for name in files:
            source = os.path.join(folder, name)
            if os.path.islink(source) or not os.path.isfile(source):
                continue
            total += os.path.getsize(source)
            count += 1
            if total > COPY_BYTES or count > COPY_FILES:
                raise NotRun("too_big")
            copy = os.path.join(target, name)
            shutil.copyfile(source, copy)
            os.chmod(copy, 0o755 if os.stat(source).st_mode & 0o111 else 0o644)


def hook_payload(event, home, work):
    """What an agent hands a hook on standard input, with sandbox paths."""
    data = {"session_id": "skill-rentgen-trial", "cwd": work, "permission_mode": "default",
            "transcript_path": home + "/.claude/projects/trial/transcript.jsonl",
            "hook_event_name": event or "SessionStart"}
    if event in ("PreToolUse", "PostToolUse", "PermissionRequest", "PostToolUseFailure"):
        data.update({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    if event == "PostToolUse":
        data["tool_response"] = {"stdout": "", "stderr": ""}
    if event == "UserPromptSubmit":
        data["prompt"] = "hello"
    if event in ("SessionStart", ""):
        data["source"] = "startup"
    if event in ("Stop", "SubagentStop"):
        data["stop_hook_active"] = False
    if event == "Notification":
        data["message"] = "trial"
    if event == "SessionEnd":
        data["reason"] = "other"
    if event == "PreCompact":
        data["trigger"] = "manual"
    return json.dumps(data)


def _plugin_root(rel, present):
    """The folder a component's ${CLAUDE_PLUGIN_ROOT} would name."""
    folder = os.path.dirname(rel)
    probe = folder
    while True:
        if (probe + "/" if probe else "") + ".claude-plugin/plugin.json" in present:
            return probe
        if not probe:
            break
        probe = os.path.dirname(probe)
    if os.path.basename(folder) in ("hooks", ".claude-plugin"):
        return os.path.dirname(folder)
    return folder


def collect_commands(root, stage_dir, extra=(), scripts=True, base=BASE):
    """What to start: everything that starts by itself, the scripts the
    instructions point to (with --help only), and what the user named."""
    intake = load_json(os.path.join(stage_dir, "intake.json"))
    try:
        surfaces = load_json(os.path.join(stage_dir, "surfaces.json"))
        structure = load_json(os.path.join(stage_dir, "structure.json"))
    except (OSError, ValueError):
        surfaces, structure = {"surfaces": [], "auto_started": []}, {}
    present = {entry["p"] for entry in intake.get("files", [])}
    home, work, skill = base + "/home", base + "/project", base + "/skill"
    commands, seen = [], set()

    def add(kind, shell, cwd, rel, event="", env=None, stdin="", note=""):
        key = (shell, cwd)
        if key in seen or len(commands) >= MAX_COMMANDS or not shell.strip():
            return
        seen.add(key)
        commands.append({"id": "%s-%d" % (kind, 1 + sum(1 for c in commands if c["kind"] == kind)),
                         "kind": kind, "event": event, "file": rel, "shell": shell, "cwd": cwd,
                         "env": env or {}, "stdin": stdin, "note": note})

    for surface in surfaces.get("surfaces", []):
        kind, shell = surface.get("kind"), surface.get("command") or ""
        if kind not in ("hook", "mcp", "lsp", "monitor", "package") or not shell:
            continue
        rel = surface.get("file", "")
        plugin = (skill + "/" + _plugin_root(rel, present)).rstrip("/")
        if kind == "package":
            add(kind, shell, (skill + "/" + os.path.dirname(rel)).rstrip("/"), rel,
                surface.get("event", ""))
        else:
            add(kind, shell, work, rel, surface.get("event", ""),
                {"CLAUDE_PLUGIN_ROOT": plugin, "CLAUDE_SKILL_DIR": plugin},
                hook_payload(surface.get("event", ""), home, work) if kind == "hook" else "")
    if scripts:
        started = set(surfaces.get("auto_started", []))
        code = {entry["p"]: entry.get("lang", "") for entry in intake.get("files", [])
                if entry["kind"] == "code" and entry.get("lang") in RUNNERS}
        chosen = []
        for item in structure.get("skills", [])[:200]:
            doc = item.get("file", "")
            if is_test_path(doc):
                continue
            try:
                text, _ = read_text(os.path.join(root, doc), 300000)
            except OSError:
                continue
            for rel in sorted(path_matches(text, os.path.dirname(doc), list(code))):
                if rel not in started and rel not in [c[0] for c in chosen]:
                    chosen.append((rel, os.path.dirname(doc)))
        for rel, folder in chosen[:MAX_SCRIPTS]:
            add("script", "%s %s --help" % (RUNNERS[code[rel]], shlex.quote(skill + "/" + rel)),
                (skill + "/" + folder).rstrip("/"), rel,
                env={"CLAUDE_SKILL_DIR": (skill + "/" + folder).rstrip("/")})
    for shell in extra:
        add("run", shell, skill, "")
    return commands


def build_job(commands, timeout, total, base=BASE, skill_src="/sr/skill"):
    decoys = rule_file("decoys.json")
    shims = sorted({name for group in decoys["shims"].values() for name in group})
    return {"nonce": secrets.token_hex(16), "home": base + "/home", "work": base + "/project",
            "skill": base + "/skill", "skill_src": skill_src, "scratch": base + "/tmp",
            "timeout": timeout, "total": total,
            "decoys": {"home": decoys["home"], "work": decoys["work"]}, "shims": shims,
            "commands": [{k: c[k] for k in ("id", "shell", "cwd", "env", "stdin")}
                         for c in commands]}


# ------------------------------------------------------------------- judge

def _short(path, raw):
    for key, shown in (("skill", "<skill>"), ("work", "<project>"), ("home", "~"),
                       ("scratch", "<tmp>")):
        base = raw.get(key) or ""
        if base and (path == base or path.startswith(base + "/")):
            return shown + path[len(base):]
    return path


def _hosts_of(event):
    kind = event.get("kind")
    if kind == "net":
        text = str(event.get("address", ""))
        match = re.match(r"^\('?([^',]+)'?,", text) or re.match(r"^\[?([^\]]+?)\]?:\d*$", text)
        return [match.group(1)] if match else []
    if kind == "dns":
        return [str(event.get("host", ""))]
    if kind == "url":
        match = URL.search(str(event.get("url", "")))
        return [match.group(1)] if match else []
    return []


def _shim_hosts(tool, args):
    hosts = [m.group(1) for m in URL.finditer(args)]
    hosts += [m.group(1) for m in AT_HOST.finditer(args)]
    if not hosts and tool in ("ssh", "scp", "sftp", "nc", "ncat", "netcat", "telnet", "ftp",
                              "rsync", "curl", "wget"):
        hosts += [m.group(1) for m in BARE_HOST.finditer(args)]
    return hosts


def judge(raw, commands, declared_hosts=()):
    """Turn the runner's description into findings. Returns (findings, notes)."""
    decoys = rule_file("decoys.json")
    classes, groups = decoys["kinds"], decoys["shims"]
    by_id = {c["id"]: c for c in commands}
    home, work = raw.get("home") or "", raw.get("work") or ""
    findings, notes = [], {"config_read": [], "own_writes": 0, "local": []}

    def where(command_id):
        return (by_id.get(command_id) or {}).get("file", "")

    def add(rule, command_id, snippet, **extra):
        findings.append(finding(rule, where(command_id), 0, snippet, during=command_id, **extra))

    known = raw.get("decoys") or {}
    state = {}
    rank = {"referenced": 1, "read": 2, "changed": 3, "deleted": 4}

    def touch(path, what, command_id):
        if path in known and rank[what] > rank.get(state.get(path, ("", ""))[0], 0):
            state[path] = (what, command_id)

    for item in raw.get("decoys_touched") or []:
        if item.get("what") in rank:
            touch(str(item.get("path", "")), item["what"], str(item.get("id", "")))
    hosts, shim_calls = [], []
    for event in raw.get("events") or []:
        if not isinstance(event, dict):
            continue
        command_id = str(event.get("id", ""))
        kind = event.get("kind")
        if kind == "open":
            touch(str(event.get("path", "")), "read", command_id)
        elif kind == "shim":
            tool, args = str(event.get("tool", "")), str(event.get("args", ""))
            shim_calls.append((tool, args, command_id))
        for host in _hosts_of(event):
            hosts.append((host, command_id, ""))
    relative = {}
    for path in known:
        if work and path.startswith(work + "/"):
            relative[path[len(work) + 1:]] = path
    for entry in raw.get("shell") or []:
        line = str(entry.get("line", ""))
        words = line.lstrip("+ ").split()
        if not line.startswith("+") or not words:
            continue
        verb = os.path.basename(words[0])
        for token in words[1:]:
            token = token.strip("'\"<>;")
            path = token if token in known else relative.get(
                token[2:] if token.startswith("./") else token)
            if path:
                touch(path, "read" if verb in READERS else "referenced", str(entry.get("id", "")))
    for path, (what, command_id) in sorted(state.items()):
        kind = known[path]
        group, shown = classes.get(kind, "secret"), _short(path, raw)
        if what in ("changed", "deleted"):
            add("SR-TR-004", command_id, shown, sub=what)
        elif group == "secret":
            add("SR-TR-001" if what == "read" else "SR-TR-006", command_id, shown, sub=kind)
        elif group == "sensitive" and what == "read":
            add("SR-TR-006", command_id, shown, sub=kind)
        elif group == "config" and what == "read":
            notes["config_read"].append(shown)
    leaks = {}
    for item in raw.get("leaked") or []:
        command_id, place = str(item.get("id", "")), item.get("where")
        if place == "output":
            leaks[(command_id, "output", "")] = 1
        elif place == "file":
            leaks[("", "file", _short(str(item.get("path", "")), raw))] = 1
        elif place == "command":
            tool = str(item.get("detail", ""))
            named = tool not in ("shell", "exec", "open", "")
            leaks[(command_id, "tool" if named else "shell", tool if named else "")] = 1
    for command_id, place, detail in sorted(leaks)[:8]:
        if place == "shell" and any(k[0] == command_id and k[1] == "tool" for k in leaks):
            continue
        add("SR-TR-002", command_id, detail, sub=place)
    for tool, args, command_id in shim_calls:
        shown = (tool + " " + args).strip()
        if tool in groups["network"]:
            first = args.split()[0] if args.split() else ""
            if tool == "git" and first not in GIT_REMOTE and not URL.search(args):
                continue
            found = _shim_hosts(tool, args)
            if found:
                hosts.extend((host, command_id, shown) for host in found)
            else:
                add("SR-TR-003", command_id, shown, sub="tool")
        elif tool in groups["install"]:
            add("SR-TR-005", command_id, shown)
        elif tool in groups["persist"]:
            add("SR-TR-004", command_id, shown, sub="persist")
        elif tool in groups["keychain"]:
            add("SR-TR-001", command_id, shown, sub="keychain")
        elif tool in ("open", "xdg-open"):
            found = _shim_hosts(tool, args)
            hosts.extend((host, command_id, shown) for host in found)
            if not found:
                add("SR-TR-010", command_id, shown)
        else:
            add("SR-TR-010", command_id, shown)
    declared = {h.lower() for h in declared_hosts}
    seen_host = set()
    for host, command_id, shown in hosts:
        host = host.strip("[]").lower()
        if host in LOCAL_HOSTS or host.startswith("127."):
            if host and host not in notes["local"]:
                notes["local"].append(host)
            continue
        if host in seen_host:
            continue
        seen_host.add(host)
        rule = "SR-TR-008" if host in declared else "SR-TR-003"
        add(rule, command_id, shown or host, host=clean_snippet(host, 80))
    persist, quiet = decoys["persist_paths"], decoys["quiet_paths"]
    outside = []
    for group in ("created", "changed", "removed"):
        for path in raw.get(group) or []:
            path = str(path)
            for base in (home, work):
                if not base or not path.startswith(base + "/"):
                    continue
                rel = path[len(base) + 1:]
                if any(rel.startswith(prefix) for prefix in quiet):
                    continue
                if any(rel.startswith(prefix) for prefix in persist) or (
                        base == work and rel.startswith(".claude/")):
                    add("SR-TR-004", "", _short(path, raw), sub=group)
                else:
                    outside.append(_short(path, raw))
            if raw.get("skill") and path.startswith(raw["skill"] + "/"):
                notes["own_writes"] += 1
    if outside:
        findings.append(finding("SR-TR-007", "", 0, ", ".join(outside[:4]), names=outside[:8],
                                count=len(outside)))
    for result in raw.get("commands") or []:
        command_id, status = str(result.get("id", "")), result.get("status")
        missing = MISSING.search(str(result.get("stderr", ""))) if result.get("exit") == 127 else None
        if status in ("timeout", "could-not-start", "no-time-left"):
            add("SR-TR-009", command_id, status, sub=status)
        elif missing:
            add("SR-TR-009", command_id, missing.group(1), sub="missing")
    return findings, notes


def decide(findings):
    worst = max([SEV_RANK[f["severity"]] for f in findings] or [0])
    if worst >= SEV_RANK["red"]:
        return "blocked"
    if worst >= SEV_RANK["high"]:
        return "caution"
    return "notes" if worst >= SEV_RANK["low"] else "quiet"


def tidy(findings, per_rule=6):
    seen, kept, counts = set(), [], {}
    for item in sorted(findings, key=lambda f: (-SEV_RANK[f["severity"]], f["rule_id"],
                                                f.get("snippet", ""))):
        key = (item["rule_id"], item.get("snippet"), item.get("host"), item.get("sub"))
        if key in seen:
            continue
        seen.add(key)
        counts[item["rule_id"]] = counts.get(item["rule_id"], 0) + 1
        if counts[item["rule_id"]] <= per_rule:
            kept.append(item)
    return kept


# ------------------------------------------------------------------ report

def strings(lang):
    data = load_json(os.path.join(SKILL_DIR, "i18n", lang + ".json"))
    return data["trial"], data["rules"], data["surface"]


def _code(text, limit=110):
    text = clean_snippet(text, limit).replace("`", "'").replace("|", "/")
    return "`%s`" % text if text else ""


def render(trial, lang):
    """The trial report as Markdown. Fixed sentences plus quoted data."""
    text, rules, surface = strings(lang)
    out = ["# %s" % text["title"].format(name=clean_snippet(trial["name"], 60)), ""]
    status = trial["status"]
    if status != "ran":
        out += ["**%s**" % text["not_run"], "", text["reason_" + trial["reason"]]]
        if trial.get("detail"):
            out += ["", "%s: %s" % (text["detail"], _code(trial["detail"], 160))]
        out += ["", text["host_safe"], ""]
        return "\n".join(out)
    verdict = trial["verdict"]
    out += ["**%s**" % text["v_" + verdict], "", text["s_" + verdict], "", "> " + text["evidence"], ""]
    seen = [f for f in trial["findings"] if f["severity"] != "info"]
    out += ["## %s" % text["seen"], ""]
    if not seen:
        out.append(text["seen_none"])
    by_id = {c["id"]: c for c in trial["commands"]}
    for index, item in enumerate(seen, 1):
        rule = rules[item["rule_id"]]
        line = "%d. **%s**" % (index, rule["title"])
        detail = item.get("host") or item.get("snippet")
        if item["rule_id"] == "SR-TR-002":
            line += ": " + text["leak_" + item.get("sub", "shell")].format(what=_code(detail, 60))
        elif detail:
            line += ": " + _code(detail)
        command = by_id.get(item.get("during") or "")
        if command:
            line += " (%s %s)" % (text["during"], _code(command["shell"], 70))
        line += ". " + rule["you"]
        if item["red_line"]:
            line += " %s %s." % (text["red"], item["rule_id"])
        out.append(line)
    out += ["", "## %s" % text["ran"], ""]
    results = {r.get("id"): r for r in trial["results"]}
    for command in trial["commands"]:
        kind = text["k_" + command["kind"]] if command["kind"] in ("script", "run") else surface.get(
            command["kind"], command["kind"])
        if command.get("event"):
            kind += " " + clean_snippet(command["event"], 30)
        result = results.get(command["id"], {})
        state = result.get("status", "no-time-left")
        if state == "finished":
            how = text["st_finished"].format(code=result.get("exit"), sec=result.get("seconds"))
        else:
            how = text["st_" + state.replace("-", "_")].format(sec=trial["timeout"])
        out.append("- %s: %s. %s" % (kind, _code(command["shell"], 120), how))
    notes = trial.get("notes") or {}
    if notes.get("config_read"):
        out.append("- %s: %s" % (text["config_read"],
                                 ", ".join(_code(p, 60) for p in notes["config_read"][:5])))
    info = [f for f in trial["findings"] if f["rule_id"] == "SR-TR-009"]
    if info:
        out += ["", "## %s" % text["unseen"], ""]
        for item in info:
            command = by_id.get(item.get("during") or "", {})
            out.append("- %s: %s" % (text["u_" + item.get("sub", "timeout").replace("-", "_")].format(
                tool=clean_snippet(item.get("snippet"), 30), sec=trial["timeout"]),
                _code(command.get("shell", ""), 100)))
    out += ["", "## %s" % text["where"], ""]
    out.append("- " + text["w_engine"].format(engine=trial["engine"], image=_code(trial["image"], 80)))
    for key in ("w_network", "w_files", "w_limits"):
        out.append("- " + text[key])
    out.append("- " + text["w_decoys"].format(n=trial["decoys"]))
    out.append("- " + text["w_atime_yes" if trial.get("atime") else "w_atime_no"])
    out += ["", "## %s" % text["not_checked"], ""]
    out += ["- " + text[key] for key in ("nc_agent", "nc_help", "nc_wait", "nc_aware", "nc_kernel")]
    out += ["", text["data_note"], ""]
    return "\n".join(out)


def terminal(trial):
    if trial["status"] != "ran":
        return "TRIAL  NOT RUN  %s" % trial["reason"].replace("_", " ")
    word = {"quiet": "NOTHING SEEN", "notes": "NOTES", "caution": "CAUTION",
            "blocked": "DO NOT INSTALL"}[trial["verdict"]]
    count = len([f for f in trial["findings"] if f["severity"] != "info"])
    return "TRIAL  %s  %d started, %d seen" % (word, len(trial["commands"]), count)


# --------------------------------------------------------------------- run

def not_run(name, reason, detail=""):
    """The record of a trial that did not happen."""
    return {"schema_version": "1.0", "name": name, "status": "not_run", "reason": reason,
            "detail": detail, "engine": "", "image": "", "timeout": 0, "commands": [],
            "results": [], "findings": [], "notes": {}, "verdict": "",
            "exit_code": {"rejected": 2, "nothing_to_run": 0}.get(reason, 10)}


def run(root, stage_dir, name, declared_hosts=(), extra=(), scripts=True, prefer=None,
        image=None, timeout=15, engine=None):
    """Carry out one trial. Always returns a trial record; never raises NotRun."""
    trial = not_run(name, "")
    trial.update({"image": image or DEFAULT_IMAGE, "timeout": timeout})
    scratch = tempfile.mkdtemp(prefix="skill-rentgen-trial-")
    try:
        commands = collect_commands(root, stage_dir, extra, scripts)
        trial["commands"] = [{k: c[k] for k in ("id", "kind", "event", "file", "shell")}
                             for c in commands]
        if not commands:
            raise NotRun("nothing_to_run")
        engine = engine or find_engine(prefer)
        if not engine:
            raise NotRun("no_engine")
        trial["engine"] = engine[0]
        skill_dir, tool_dir = os.path.join(scratch, "skill"), os.path.join(scratch, "tool")
        os.chmod(scratch, 0o755)
        copy_tree(root, skill_dir)
        os.makedirs(tool_dir)
        os.chmod(tool_dir, 0o755)
        for filename in SANDBOX_FILES:
            target = os.path.join(tool_dir, filename)
            shutil.copyfile(os.path.join(HERE, "sandbox", filename), target)
            os.chmod(target, 0o644)
        # The sandbox user gets a name and a home, so programs that look the
        # user up behave as they would for a real person.
        for filename, text in (("passwd", "root:x:0:0:root:/root:/bin/sh\n"
                                          "user:x:1000:1000:user:%s/home:/bin/sh\n"
                                          "nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n" % BASE),
                               ("group", "root:x:0:\nuser:x:1000:\nnogroup:x:65534:\n")):
            target = os.path.join(tool_dir, filename)
            with open(target, "w", encoding="ascii") as handle:
                handle.write(text)
            os.chmod(target, 0o644)
        total = min(600, timeout * len(commands) + 20)
        job = build_job(commands, timeout, total)
        raw = run_container(engine, trial["image"], skill_dir, tool_dir, job, total + 90, scratch)
        findings, notes = judge(raw, commands, declared_hosts)
        trial.update({"status": "ran", "findings": tidy(findings), "notes": notes,
                      "results": [{k: r.get(k) for k in ("id", "status", "exit", "seconds")}
                                  for r in raw["commands"] if isinstance(r, dict)],
                      "decoys": len(raw.get("decoys") or {}), "atime": bool(raw.get("atime")),
                      "tools": raw.get("tools") or {}})
        trial["verdict"] = decide(trial["findings"])
        trial["exit_code"] = EXIT[trial["verdict"]]
    except NotRun as stop:
        trial.update(not_run(name, stop.reason, stop.detail), commands=trial["commands"],
                     image=trial["image"], engine=trial["engine"], timeout=timeout)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return trial
