"""Shared setup for the tests. Standard library only."""
from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PACKAGE = os.path.join(REPO, "skill-rentgen")
SKILL = os.path.join(PACKAGE, "skills", "skill-rentgen")
SCRIPTS = os.path.join(SKILL, "scripts")
CLI = os.path.join(SCRIPTS, "skill_rentgen.py")
EXAMPLES = os.path.join(REPO, "examples")

for path in (SCRIPTS, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

# The tests decide for themselves what kind of machine this is. The signs of
# a machine that does not keep its disk (a cloud session, a build runner)
# are taken out of the environment here, and a test that wants one sets it.
with open(os.path.join(SKILL, "rules", "places.json"), encoding="utf-8") as _handle:
    MARKERS = json.load(_handle)["short_lived_env"]
for _name in MARKERS + ["SKILL_RENTGEN_HOME"]:
    os.environ.pop(_name, None)

import skill_rentgen as engine  # noqa: E402


class Workspace:
    """A temporary folder that is removed when the test ends."""

    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="sr-test-")
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)

    def join(self, *parts):
        return os.path.join(self.path, *parts)


def scan_inline(target, out, lang="he"):
    """Scan in this process. Fast; used where isolation is not what is tested."""
    summary, report, out_dir = engine.scan(target, lang, out, runner=engine.run_stage_inline)
    return summary, report, out_dir


EMPTY_HOME = tempfile.mkdtemp(prefix="sr-test-home-")
atexit.register(shutil.rmtree, EMPTY_HOME, True)


def run_cli(*args, cwd=None, home=None, path_first=None, env=None):
    """Run the real command line. Returns (exit_code, stdout, stderr).
    The user's own home folder is never read: HOME points at an empty
    folder unless a test passes one. `env` adds variables for this run."""
    extra = env or {}
    env = dict(os.environ)
    env.update(extra)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HOME"] = env["USERPROFILE"] = home or EMPTY_HOME
    if path_first:
        env["PATH"] = path_first + os.pathsep + env.get("PATH", "")
    proc = subprocess.run([sys.executable, CLI] + list(args), cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def run_hook(*args, home=None, env=None):
    """Run the session hook script the way the agent does."""
    extra = env or {}
    env = dict(os.environ)
    env.update(extra)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HOME"] = env["USERPROFILE"] = home or EMPTY_HOME
    proc = subprocess.run([sys.executable, os.path.join(SCRIPTS, "session_check.py")] + list(args),
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def rule_ids(report):
    return sorted({item["rule_id"] for item in report["findings"]})
