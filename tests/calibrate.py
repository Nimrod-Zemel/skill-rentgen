"""Calibration run: scan a folder of known-good skill repositories and count.

WHY: a scanner that cries wolf on Anthropic's own skills is ignored within
a week. Before any rule ships, it is run against real, well-regarded skills.
The gate: no red line and no "do not install" on a known-good skill, and at
most one in ten ends in "caution".

Usage:
  python3 tests/calibrate.py <corpus_dir> [--json out.json] [--only name] [--cli]

corpus_dir holds one folder per repository. Every plugin folder, every skill
folder and every repository root is scanned as its own unit. The skills are
read, never run. --cli uses the real command line (isolated child processes)
and is slower; without it the stages run in this process.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import tempfile
import time

sys.dont_write_bytecode = True  # a .pyc next to the scripts would fail the tool's own check

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "skill-rentgen", "skills", "skill-rentgen", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import skill_rentgen as engine  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def units(repo):
    """Yield (kind, path) for the repo root, each plugin and each skill."""
    yield "repo", repo
    for folder, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        rel = os.path.relpath(folder, repo)
        if rel == ".":
            continue
        parts = rel.split(os.sep)
        if any(part in ("tests", "test", "fixtures", "evals", "examples", "templates",
                        "template") for part in parts):
            continue
        if os.path.isfile(os.path.join(folder, ".claude-plugin", "plugin.json")):
            yield "plugin", folder
        if "SKILL.md" in files:
            yield "skill", folder


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("corpus")
    parser.add_argument("--json")
    parser.add_argument("--only", default="")
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    rows = []
    out = tempfile.mkdtemp(prefix="sr-calibrate-")
    runner = None if args.cli else engine.run_stage_inline
    try:
        for repo in sorted(os.listdir(args.corpus)):
            path = os.path.join(args.corpus, repo)
            if not os.path.isdir(path) or (args.only and args.only not in repo):
                continue
            for kind, unit in units(path):
                started = time.time()
                try:
                    summary, report, _ = engine.scan(unit, "en", out, runner=runner)
                except engine.ToolError as error:
                    rows.append({"repo": repo, "kind": kind, "unit": os.path.relpath(unit, path),
                                 "verdict": "tool-error", "error": str(error), "findings": [],
                                 "seconds": time.time() - started})
                    continue
                rows.append({
                    "repo": repo, "kind": kind, "unit": os.path.relpath(unit, path),
                    "verdict": summary["internal"], "seconds": round(time.time() - started, 3),
                    "files": report["subject"]["files"],
                    "findings": [{k: f.get(k) for k in ("rule_id", "severity", "file", "line",
                                                        "snippet", "sub", "host", "stage")}
                                 for f in report["findings"]],
                })
    finally:
        shutil.rmtree(out, ignore_errors=True)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, ensure_ascii=False, indent=1)
    verdicts = {}
    for row in rows:
        key = (row["kind"], row["verdict"])
        verdicts[key] = verdicts.get(key, 0) + 1
    print("units scanned: %d" % len(rows))
    for kind in ("skill", "plugin", "repo"):
        total = sum(n for (k, _), n in verdicts.items() if k == kind)
        if not total:
            continue
        line = ", ".join("%s %d" % (v, n) for (k, v), n in sorted(verdicts.items()) if k == kind)
        caution = sum(n for (k, v), n in verdicts.items() if k == kind and v == "caution")
        print("%-7s %4d  %s  (caution %.1f%%)" % (kind, total, line, 100.0 * caution / total))
    times = sorted(row["seconds"] for row in rows)
    if times:
        print("seconds: median %.2f, p95 %.2f, max %.2f" % (
            statistics.median(times), times[int(len(times) * 0.95) - 1], times[-1]))
    red = [(row, f) for row in rows for f in row["findings"] if f["severity"] == "red"]
    print("red-line findings on known-good units: %d" % len(red))
    return 1 if red or any(r["verdict"] in ("blocked", "reject", "tool-error") for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
