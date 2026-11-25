#!/usr/bin/env python3
"""The session hook of SkillRentgen: one line if something you approved
has changed, and nothing otherwise.

WHY: this is the only part of the tool that starts by itself, so it is the
smallest part. It can read the registry, list folders and hash files. It
cannot scan, install, block, reach the network or start a program, because
it does not load the code that does those things.

It never fails a session: on any error it prints nothing and exits 0.

Usage: python3 session_check.py [--home DIR] [--lang he|en]
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv):
    try:
        if sys.version_info < (3, 9):
            return 0
        if not (sys.flags.isolated and sys.dont_write_bytecode):
            import subprocess
            return subprocess.call([sys.executable, "-I", "-B", "-X", "utf8",
                                    os.path.abspath(__file__)] + argv)
        sys.path.insert(0, HERE)
        import registry
        import watch
        home = lang = None
        for flag, value in zip(argv, argv[1:]):
            if flag == "--home":
                home = value
            elif flag == "--lang" and value in ("he", "en"):
                lang = value
        line = watch.session_line(registry.home_dir(home), lang)
        if line:
            try:
                sys.stdout.reconfigure(errors="replace")
            except (AttributeError, ValueError):
                pass
            print(line)
    except BaseException:  # a session must never fail to start because of this check
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
