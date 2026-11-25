#!/usr/bin/env python3
"""A stand-in for docker, for tests on a machine that has no container engine.

It accepts the same command line that trial.py builds. It refuses to start
unless every isolation flag is present, so a test that passes also proves
the flags were sent. It then runs the in-sandbox runner inside new user,
network, process and mount namespaces: no network, every file system
read-only except a throw-away folder that stands in for /sandbox, and the
home folders hidden. It is weaker than a container and is used only for
this repository's own test skills.

It is not shipped with the skill and the command line never uses it.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REQUIRED = [("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
            ("--user", "1000:1000")]
UNSHARE = ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork", "--mount-proc",
           "--mount"]
LOCK = r'''
base="$1"; shift
hide="$1"; shift
mount --bind "$base" "$base" || exit 97
awk '{print $5}' /proc/self/mountinfo | sort -u | while read -r point; do
  case "$point" in "$base"|/proc|/proc/*|/dev|/dev/*|/sys|/sys/*) continue;; esac
  mount -o remount,bind,ro "$point" 2>/dev/null
done
touch /sr-lock-probe 2>/dev/null && exit 98
if [ "$hide" = yes ]; then
  for folder in /root /home; do [ -d "$folder" ] && mount -t tmpfs tmpfs "$folder" 2>/dev/null; done
fi
exec "$@"
'''


def usable():
    """True when this machine can build the namespaces the stand-in needs."""
    if not shutil.which("unshare"):
        return False
    try:
        probe = tempfile.mkdtemp(prefix="sr-fake-probe-")
        try:
            return subprocess.call(UNSHARE + ["sh", "-c", LOCK, "lock", probe, "no", "true"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=30) == 0
        finally:
            shutil.rmtree(probe, ignore_errors=True)
    except (OSError, subprocess.SubprocessError):
        return False


def main(argv):
    if not argv or argv[0] in ("info", "kill", "rm"):
        return 0
    if argv[0] != "run":
        return 64
    args = argv[1:]
    for flag, value in REQUIRED:
        if flag not in args or args[args.index(flag) + 1] != value:
            sys.stderr.write("fake engine: missing %s %s\n" % (flag, value))
            return 125
    if "--read-only" not in args or "--privileged" in args:
        sys.stderr.write("fake engine: wrong privileges\n")
        return 125
    mounts = {}
    for index, item in enumerate(args):
        if item == "-v":
            source, target, options = args[index + 1].split(":", 2)
            if "ro" not in options.split(","):
                sys.stderr.write("fake engine: a writable mount was asked for\n")
                return 125
            mounts[target] = source
    image = args.index("python3") + 1
    if os.environ.get("FAKE_ENGINE_NO_IMAGE"):
        sys.stderr.write("Unable to find image '%s' locally\n" % args[image])
        return 125
    base = tempfile.mkdtemp(prefix="sr-fake-sandbox-")
    try:
        job = sys.stdin.read().replace("/sandbox", base).replace("/sr/skill", mounts["/sr/skill"])
        if os.environ.get("FAKE_ENGINE_FORGE"):
            sys.stdout.write('SR-RESULT-0000 {"commands": [], "decoys": {}}\n')
            return 0
        needed = [os.path.realpath(p) for p in (sys.executable, base, mounts["/sr/skill"],
                                                mounts["/sr/tool"])]
        hide = "no" if any(p.startswith(("/root/", "/home/")) for p in needed) else "yes"
        proc = subprocess.run(UNSHARE + ["sh", "-c", LOCK, "lock", base, hide, sys.executable,
                                         "-I", "-B", os.path.join(mounts["/sr/tool"], "runner.py")],
                              input=job.encode("utf-8"), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=700)
        sys.stdout.write(proc.stdout.decode("utf-8", "replace").replace(base, "/sandbox"))
        sys.stderr.write(proc.stderr.decode("utf-8", "replace")[-2000:])
        return proc.returncode
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
