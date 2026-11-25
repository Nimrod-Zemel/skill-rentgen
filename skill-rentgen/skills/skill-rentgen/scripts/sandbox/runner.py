"""Runs INSIDE the sandbox. Plants decoy secrets, starts the skill's own
commands, and writes down what happened.

WHY: reading code tells you what a skill could do. This shows what its
commands actually try to do when nothing stops them, in a place that holds
nothing worth stealing and has no network to reach.

It trusts nothing it runs, and it decides nothing. The description of the
run goes back to trial.py, which is the only place that judges it.

Rules that tests check:
1. The job arrives on standard input and the result leaves on standard
   output, on one line that starts with a marker only the caller knows.
   No folder is shared for writing with the machine outside.
2. Every decoy holds a marker made for this run. The marker never leaves
   in the result; it is replaced before the result is written.
3. A command that does not finish in time is stopped, with its children.

Usage (inside the sandbox only): python3 -I -B runner.py < job.json
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CAP = 6000
EVENT_CAP = 3000
FILE_CAP = 300


def write_decoy(path, marker):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if path.endswith(".jsonl"):
        text = json.dumps({"type": "user", "message": {"role": "user", "content": marker}}) + "\n"
    elif path.endswith(".json"):
        text = json.dumps({"decoy": "written by skill-rentgen for a trial run", "value": marker}) + "\n"
    else:
        text = "# decoy file written by skill-rentgen for a trial run\n%s\n" % marker
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o666)
    past = time.time() - 7200
    os.utime(path, (past, past))


def plant(base, entries, marker):
    state = {}
    for entry in entries:
        path = os.path.join(base, entry["path"])
        write_decoy(path, marker)
        info = os.stat(path)
        state[path] = {"kind": entry["kind"], "atime": info.st_atime_ns,
                       "mtime": info.st_mtime_ns, "seen": ""}
    return state


def atime_works(folder):
    """Does reading a file here move its access time? Some mounts never do."""
    probe = os.path.join(folder, ".sr-atime-probe")
    try:
        with open(probe, "w") as handle:
            handle.write("probe\n")
        past = time.time() - 7200
        os.utime(probe, (past, past))
        before = os.stat(probe).st_atime_ns
        with open(probe) as handle:
            handle.read()
        after = os.stat(probe).st_atime_ns
        os.unlink(probe)
        return after != before
    except OSError:
        return False


def check_decoys(decoys, marker, command_id, touched):
    for path, state in decoys.items():
        if state["seen"] in ("changed", "deleted"):
            continue
        try:
            info = os.stat(path)
        except OSError:
            state["seen"] = "deleted"
            touched.append({"path": path, "kind": state["kind"], "what": "deleted", "id": command_id})
            continue
        if info.st_mtime_ns != state["mtime"]:
            state["seen"] = "changed"
            touched.append({"path": path, "kind": state["kind"], "what": "changed", "id": command_id})
        elif info.st_atime_ns != state["atime"] and not state["seen"]:
            state["seen"] = "read"
            touched.append({"path": path, "kind": state["kind"], "what": "read", "id": command_id})


def snapshot(roots, skip):
    seen = {}
    for root in roots:
        for folder, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if not os.path.join(folder, d).startswith(skip)]
            for name in files:
                path = os.path.join(folder, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                seen[path] = (info.st_size, info.st_mtime_ns)
                if len(seen) > 40000:
                    return seen
    return seen


def run_one(command, env, xtrace, timeout):
    shell = shutil.which("bash")
    if shell:
        wrapper = ("exec 9>>'%s'; BASH_XTRACEFD=9; export BASH_XTRACEFD SHELLOPTS; set -x; %s"
                   % (xtrace, command["shell"]))
        argv = [shell, "-c", wrapper]
    else:
        argv = ["sh", "-c", command["shell"]]
    full_env = dict(env)
    full_env.update(command.get("env") or {})
    started = time.time()
    try:
        proc = subprocess.Popen(argv, cwd=command["cwd"], env=full_env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
    except OSError as error:
        return {"status": "could-not-start", "detail": str(error)[:200], "stdout": "", "stderr": ""}
    try:
        out, err = proc.communicate((command.get("stdin") or "").encode("utf-8"), timeout=timeout)
        status = "finished"
    except subprocess.TimeoutExpired:
        status = "timeout"
        out, err = b"", b""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    if status == "timeout":
        try:
            out, err = proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
    return {"status": status, "exit": proc.returncode, "seconds": round(time.time() - started, 2),
            "stdout": out[-OUTPUT_CAP:].decode("utf-8", "replace"),
            "stderr": err[-OUTPUT_CAP:].decode("utf-8", "replace")}


def read_lines(path, cap):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return [line.rstrip("\n")[:1300] for _, line in zip(range(cap), handle)]
    except OSError:
        return []


def main():
    job = json.load(sys.stdin)
    nonce = str(job["nonce"])
    home, work, skill, scratch = job["home"], job["work"], job["skill"], job["scratch"]
    trace = os.path.join(scratch, "sr-trace")
    for folder in (home, work, scratch, os.path.join(trace, "py"), os.path.join(trace, "bin")):
        os.makedirs(folder, exist_ok=True)
    if job.get("skill_src") and job["skill_src"] != skill:
        shutil.copytree(job["skill_src"], skill, symlinks=False)
    events, xtrace = os.path.join(trace, "events.jsonl"), os.path.join(trace, "xtrace.log")
    for name in (events, xtrace):
        with open(name, "a"):
            pass
        os.chmod(name, 0o666)
    shutil.copyfile(os.path.join(HERE, "audit_hook.py"), os.path.join(trace, "py", "sitecustomize.py"))
    shutil.copyfile(os.path.join(HERE, "node_hook.js"), os.path.join(trace, "node_hook.js"))
    tools = {name: bool(shutil.which(name)) for name in ("bash", "sh", "python3", "node")}
    for name in job["shims"]:
        target = os.path.join(trace, "bin", name)
        shutil.copyfile(os.path.join(HERE, "shim.sh"), target)
        os.chmod(target, 0o755)
    token = secrets.token_hex(12)
    marker = "SR-DECOY-" + token
    needles = (marker, token[:12], token[12:])

    def hit(text):
        return any(needle in text for needle in needles)

    def scrub(text):
        for needle in needles:
            text = text.replace(needle, "<decoy>")
        return text

    decoys = plant(home, job["decoys"]["home"], marker)
    decoys.update(plant(work, job["decoys"]["work"], marker))
    env = {"HOME": home, "USER": "user", "LOGNAME": "user", "LANG": "C.UTF-8", "SHELL": "/bin/sh",
           "TERM": "dumb", "TMPDIR": scratch,
           "PATH": os.path.join(trace, "bin") + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONPATH": os.path.join(trace, "py"), "PYTHONDONTWRITEBYTECODE": "1",
           "SR_TRACE": events, "SR_WATCH": os.pathsep.join([home, work]),
           "CLAUDE_PROJECT_DIR": work, "CLAUDE_PLUGIN_ROOT": skill, "CLAUDE_SKILL_DIR": skill}
    if tools["node"]:
        env["NODE_OPTIONS"] = "--require=" + os.path.join(trace, "node_hook.js")
    roots = [home, work, scratch, skill]
    before = snapshot(roots, trace)
    results, touched = [], []
    began = time.time()
    for command in job["commands"]:
        if time.time() - began > job["total"]:
            results.append({"id": command["id"], "status": "no-time-left", "stdout": "", "stderr": ""})
            continue
        with open(events, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"kind": "start", "id": command["id"]}) + "\n")
        with open(xtrace, "a", encoding="utf-8") as handle:
            handle.write("#start %s\n" % command["id"])
        outcome = run_one(command, env, xtrace, job["timeout"])
        outcome["id"] = command["id"]
        results.append(outcome)
        check_decoys(decoys, marker, command["id"], touched)
    after = snapshot(roots, trace)
    decoy_paths = set(decoys)
    created = sorted(p for p in after if p not in before)
    changed = sorted(p for p in after if p in before and after[p] != before[p]
                     and p not in decoy_paths)
    removed = sorted(p for p in before if p not in after and p not in decoy_paths)
    leaked = []
    for outcome in results:
        for stream in ("stdout", "stderr"):
            if hit(outcome[stream]):
                leaked.append({"where": "output", "id": outcome["id"]})
                outcome[stream] = scrub(outcome[stream])
    for path in (created + changed)[:2000]:
        try:
            if os.path.getsize(path) < 4000000:
                with open(path, "rb") as handle:
                    if hit(handle.read().decode("utf-8", "replace")):
                        leaked.append({"where": "file", "path": path})
        except OSError:
            pass
    current, event_lines = "", []
    for line in read_lines(events, EVENT_CAP):
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if item.get("kind") == "start":
            current = str(item.get("id", ""))
            continue
        item["id"] = current
        if hit(line):
            leaked.append({"where": "command", "id": current,
                           "detail": str(item.get("tool") or item.get("kind") or "")[:40]})
            item = json.loads(scrub(json.dumps(item)))
        event_lines.append(item)
    current, shell_lines = "", []
    for line in read_lines(xtrace, EVENT_CAP):
        if line.startswith("#start "):
            current = line[7:]
            continue
        if hit(line):
            leaked.append({"where": "command", "id": current, "detail": "shell"})
            line = scrub(line)
        shell_lines.append({"id": current, "line": line[:400]})
    report = {"schema_version": "1.0", "commands": results, "events": event_lines,
              "shell": shell_lines, "decoys_touched": touched,
              "decoys": {path: state["kind"] for path, state in decoys.items()},
              "created": created[:FILE_CAP], "changed": changed[:FILE_CAP],
              "removed": removed[:FILE_CAP], "leaked": leaked[:50],
              "counts": {"created": len(created), "changed": len(changed), "removed": len(removed)},
              "home": home, "work": work, "skill": skill, "scratch": scratch,
              "tools": tools, "atime": atime_works(home)}
    sys.stdout.write("\nSR-RESULT-%s %s\n" % (nonce, json.dumps(report)))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
