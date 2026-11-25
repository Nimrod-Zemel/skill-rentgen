"""Calibration of the trial run: start the self-starting parts of known-good
skills in a real container and count what the trial says.

WHY: the trial has red lines of its own. Before they are relied on, they
are run against the same well-regarded repositories the scan rules were
calibrated on. The gate is the same: no red line on a known-good skill.

Usage:
  python3 tests/calibrate_trial.py <corpus_dir> [--json out.json] [--only name]

This starts code that other people wrote, so it runs only where Docker or
Podman answers. The test stand-in (fake_engine.py) is for this repository's
own test skills and is never used here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import helpers  # noqa: E402
import calibrate  # noqa: E402
import trial  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("corpus")
    parser.add_argument("--json")
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    engine = trial.find_engine()
    if not engine:
        sys.stderr.write("No container engine answers on this machine. Nothing was started.\n")
        return 10
    rows, started = [], time.time()
    for repo in sorted(os.listdir(args.corpus)):
        if args.only and args.only not in repo:
            continue
        for kind, path in calibrate.units(os.path.realpath(os.path.join(args.corpus, repo))):
            box = {}

            def after(root, work, summary, report, out_dir):
                declared = [n["host"] for n in (report.get("label") or {}).get("network", [])
                            if n.get("declared")]
                box["record"] = trial.run(root, work, summary["name"], declared, engine=engine,
                                          timeout=10)
            with helpers.Workspace() as ws:
                try:
                    helpers.engine.scan(path, "en", ws.join("out"),
                                        runner=helpers.engine.run_stage_inline, then=after)
                except Exception as error:  # a calibration run reports and moves on
                    rows.append({"repo": repo, "kind": kind, "path": path, "status": "error",
                                 "detail": str(error)[:200], "commands": 0})
                    continue
            record = box.get("record") or {"status": "not_run", "reason": "rejected"}
            row = {"repo": repo, "kind": kind, "path": os.path.relpath(path, args.corpus),
                   "status": record["status"], "reason": record.get("reason", ""),
                   "verdict": record.get("verdict", ""), "commands": len(record.get("commands", [])),
                   "rules": sorted({f["rule_id"] for f in record.get("findings", [])}),
                   "findings": [{k: f.get(k) for k in ("rule_id", "snippet", "host", "sub", "during")}
                                for f in record.get("findings", [])],
                   "shell": [c["shell"][:160] for c in record.get("commands", [])]}
            rows.append(row)
            if row["status"] == "ran":
                print("%-8s %-7s %-60s %s" % (row["verdict"], kind, row["path"][-60:],
                                              " ".join(row["rules"])), flush=True)
    ran = [r for r in rows if r["status"] == "ran"]
    tally = {}
    for row in ran:
        tally[row["verdict"]] = tally.get(row["verdict"], 0) + 1
    summary = {"engine": engine[0], "units": len(rows), "ran": len(ran), "verdicts": tally,
               "nothing_to_run": sum(1 for r in rows if r.get("reason") == "nothing_to_run"),
               "not_run_other": sum(1 for r in rows if r["status"] != "ran"
                                    and r.get("reason") != "nothing_to_run"),
               "commands": sum(r["commands"] for r in ran), "seconds": round(time.time() - started)}
    print(json.dumps(summary, indent=2))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump({"summary": summary, "rows": rows}, handle, indent=1)
    return 2 if tally.get("blocked") else 0


if __name__ == "__main__":
    sys.exit(main())
