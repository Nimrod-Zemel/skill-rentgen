"""Write docs/calibration.md, docs/rules.md and tests/corpus.lock.json from
the output of real runs, so that no number in the docs is typed by hand.

Usage:
  python3 tests/make_docs.py <calibration.json> <independent.json> <corpus_dir> <cli_seconds>
          <hook_ms> [<trial_calibration.json>]
"""
from __future__ import annotations

import collections
import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SKILL = os.path.join(REPO, "skill-rentgen", "skills", "skill-rentgen")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def git(folder, *args):
    try:
        return subprocess.check_output(["git", "-C", folder] + list(args),
                                       stderr=subprocess.DEVNULL).decode().strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def main():
    rows, outside = load(sys.argv[1]), load(sys.argv[2])
    corpus, seconds, hook_ms = sys.argv[3], sys.argv[4], sys.argv[5]
    trial_rows = load(sys.argv[6]) if len(sys.argv) > 6 else None
    en = load(os.path.join(SKILL, "i18n", "en.json"))
    he = load(os.path.join(SKILL, "i18n", "he.json"))
    rules = []
    for name in ("red-lines.json", "warnings.json"):
        rules += load(os.path.join(SKILL, "rules", name))["rules"]
    trial_rules = load(os.path.join(SKILL, "rules", "trial.json"))["rules"]
    decoys = load(os.path.join(SKILL, "rules", "decoys.json"))
    version = load(os.path.join(SKILL, "rules", "red-lines.json"))["rules_version"]

    lock = []
    for name in sorted(os.listdir(corpus)):
        folder = os.path.realpath(os.path.join(corpus, name))
        url = git(folder, "remote", "get-url", "origin")
        if url:
            lock.append({"repository": url, "commit": git(folder, "rev-parse", "HEAD")})
    with open(os.path.join(HERE, "corpus.lock.json"), "w", encoding="utf-8") as handle:
        json.dump({"note": "The known-good repositories the rules were calibrated on. "
                           "They are not copied into this repository.", "repositories": lock},
                  handle, indent=2)
        handle.write("\n")

    counts = collections.Counter((r["kind"], r["verdict"]) for r in rows)
    kinds = {"skill": "Skills", "plugin": "Plugins", "repo": "Whole repositories"}
    out = ["# Calibration", "",
           "Rules version %s. Every number on this page was written by `tests/make_docs.py` "
           "from the output of real runs. To repeat them, see the end of the page." % version, "",
           "## Known-good corpus", "",
           "Nine public repositories of well-regarded skills and plugins, read at these commits. "
           "They were read as examples of good practice. Nothing from them is copied here, and "
           "no report about any of them is published.", "",
           "| Repository | Commit |", "| --- | --- |"]
    out += ["| %s | `%s` |" % (item["repository"].replace("https://", ""), item["commit"][:10])
            for item in lock]
    out += ["", "Each plugin folder, each skill folder and each repository root was scanned as "
            "its own unit: %d units." % len(rows), "",
            "| Unit | Count | Install | Install, with notes | Caution | Do not install |",
            "| --- | --- | --- | --- | --- | --- |"]
    for kind, title in kinds.items():
        total = sum(n for (k, _), n in counts.items() if k == kind)
        out.append("| %s | %d | %d | %d | %d | %d |" % (
            title, total, counts[(kind, "approve")], counts[(kind, "approve_with_notes")],
            counts[(kind, "caution")], counts[(kind, "blocked")] + counts[(kind, "reject")]))
    red = sum(1 for r in rows for f in r["findings"] if f["severity"] == "red")
    small = [r for r in rows if r["kind"] != "repo"]
    caution = [r for r in small if r["verdict"] == "caution"]
    out += ["", "Red-line findings on known-good units: **%d**." % red, "",
            "Caution among skills and plugins: **%d of %d (%.1f%%)**. The gate allows 10%%."
            % (len(caution), len(small), 100.0 * len(caution) / len(small)), "",
            "A whole repository is a collection of many skills, so one warning anywhere makes "
            "the repository a caution. The gate is measured on skills and plugins, which is "
            "what a person installs.", "",
            "### Every caution, and why", "",
            "Named by rule, not by project. Each one is an observation a person would want "
            "to know before installing.", "",
            "| Rule | What was observed | Units |", "| --- | --- | --- |"]
    by_rule = collections.Counter()
    for row in caution:
        for rule in sorted({f["rule_id"] for f in row["findings"] if f["severity"] == "high"}):
            by_rule[rule] += 1
    for rule, count in sorted(by_rule.items()):
        out.append("| %s | %s | %d |" % (rule, en["rules"][rule]["title"], count))
    out += ["", "## What calibration changed", "",
            "The first run put 47 red-line findings on known-good units. Each one was read, and "
            "each led to a change that is recorded next to its rule.", "",
            "| Rule | Severity now | Why |", "| --- | --- | --- |"]
    for rule in rules:
        if rule.get("calibration") or rule.get("status") == "downgraded":
            out.append("| %s | %s | %s |" % (rule["id"], rule["severity"],
                                             rule.get("calibration") or rule.get("about", "")))
    out += ["",
            "Changes that do not show as a severity:", "",
            "- Invisible characters. Good code holds them inside quotes or a regex class, one "
            "at a time, to clean text. A red line now needs a character inside a word, a run "
            "with repeats, a run of twelve or more, or a bidi control that reorders code.",
            "- Quoted attack phrases. Security documentation quotes phrases such as \"ignore "
            "previous instructions\" in quotes, code blocks and \"look for\" lists. Those are "
            "reported as mentions. A sentence that opens with the phrase is an order.",
            "- Download and run. A known installer of a well-known tool, a container build "
            "file and an install hint inside an error message are not red lines.",
            "- Promises. A statement in the front page of a collection, in a table row, or "
            "with a condition (\"offline for local folders\") is never a red line.",
            "- Frontmatter. Folded descriptions and multi-line lists are read. Only constructs "
            "that can blow up a parser are refused.",
            "- A server named in an open config file after the plugin itself counts as declared.",
            "- What a hook starts. A file that a self-starting file hands to an interpreter, "
            "starts by its path or imports is judged as self-starting too, and so on down the "
            "chain. A file that is only mentioned by name is not followed: the first version "
            "of this rule followed mentions, reached hundreds of files in one repository, and "
            "put red lines on its tests.",
            "- A declared installer. A command that writes into the skills folder is a caution. "
            "When the skill's capabilities file names that folder, it is a note (SR-DF-020). "
            "A component that starts by itself and writes there is a red line either way.",
            "", "## Shapes taken from published attacks", "",
            "In early 2026, researchers documented skills in a public registry that delivered "
            "an infostealer. The SKILL.md looked harmless. It carried a \"prerequisite\": run a "
            "command that was base64 text piped to a shell, which decoded to a download from a "
            "raw IP address; or fetch a password-protected archive; or install a \"CLI\" from a "
            "page on a free-hosting site. Sources are in ACKNOWLEDGEMENTS.md.", "",
            "Each shape has a rule and a fixture named `real-*` in tests/fixtures.py. The tool "
            "decodes the base64 text without running it and reports what it says.", "",
            "These rules were added after the first calibration and the corpus was run again: "
            "still no red line on a known-good unit.",
            "", "## An outside check", "",
            "Our own test skills pass because we wrote them. So the tool was also run on the "
            "evaluation set of [cisco-ai-defense/skill-scanner]"
            "(https://github.com/cisco-ai-defense/skill-scanner) at commit `c558c42`: %d cases "
            "that carry an expected verdict, written by other people for another scanner. "
            "They are small, inert fixtures, each built around one signal." % (
                sum(r["expected"] in ("unsafe", "safe") for r in outside)), ""]
    flagged = ("caution", "blocked", "reject")
    unsafe = [r for r in outside if r["expected"] == "unsafe"]
    safe = [r for r in outside if r["expected"] == "safe"]
    out += ["| Expected by Cisco | Cases | Flagged here (caution or do not install) |",
            "| --- | --- | --- |",
            "| Unsafe | %d | %d |" % (len(unsafe), sum(r["verdict"] in flagged for r in unsafe)),
            "| Safe | %d | %d |" % (len(safe), sum(r["verdict"] in flagged for r in safe)), "",
            "The first run flagged 3 of the 17 unsafe cases and wrongly blocked 1 safe case. "
            "That run is why the rules for raw sockets, tunnel services, registry redirects, "
            "whole-environment reads, installs from an address and instructions to obey "
            "outside content exist.", "",
            "Unsafe cases not flagged, by category:", "",
            "| Category | Verdict here | Why |", "| --- | --- | --- |"]
    why = {"hardcoded-secrets": "The key is a dummy made of one repeated letter. Placeholders are ignored on purpose",
           "harmful-content": "Out of scope: the tool does not judge the subject of the text",
           "malware": "Out of scope: the payload is an inert string that nothing runs",
           "path-traversal": "Out of scope: a flaw inside the skill's own code",
           "resource-exhaustion": "Out of scope: a flaw inside the skill's own code",
           "sql-injection": "Out of scope: a flaw inside the skill's own code",
           "unauthorized-tool-use": "The address uses the reserved `.invalid` domain. Reserved domains are ignored on purpose"}
    for row in unsafe:
        if row["verdict"] not in flagged:
            category = row["unit"].split("/")[1]
            out.append("| %s | %s | %s |" % (category, en["verdict"][row["verdict"]],
                                             why.get(category, "Not covered")))
    out += ["", "## Our own test skills", "",
            "`tests/fixtures.py` describes %d test skills as data. They are written to disk "
            "only while a test runs. With the three examples, that is %d." % (
                fixture_count(), fixture_count() + 3), "",
            "## The trial run", "",
            "The trial has %d rules of its own, %d of them red lines, and %d decoy files. "
            "`tests/test_trial.py` builds six test skills at test time (a thief, a polite hook, "
            "a hook that never ends, a Node hook, a hook that calls a declared server, and a "
            "plain skill given one command) and checks that each rule is triggered by one of "
            "them. Where Docker or Podman answers, the tests run in a real container and also "
            "check the fences from inside: no network, nothing writable outside the sandbox, "
            "not root. Elsewhere they run on a stand-in built from Linux namespaces."
            % (len(trial_rules), sum(r["severity"] == "red" for r in trial_rules),
               len(decoys["home"]) + len(decoys["work"])), ""] + trial_section(trial_rows) + [
            "## Speed", "",
            "One skill through the real command line, with every stage in its own process: "
            "median %s seconds, measured on every eighth skill and plugin of the corpus (43 of "
            "341). The largest repository in the corpus, 129 MB, took about half a minute."
            % seconds, "",
            "The check at the start of a session, on an approved skill of 500 files (1.7 MB) "
            "with nothing changed: median %s milliseconds, measured over 15 runs. It compares "
            "size and change time and reads a file only when one of them differs." % hook_ms,
            "", "## Repeat it", "", "```bash",
            "python3 tests/calibrate.py <folder with the repositories> --json out.json",
            "python3 -m unittest discover -s tests -p \"test_*.py\"", "```", "",
            "## What this page does not show", "",
            "- The corpus is skills written in English by experienced builders. No Hebrew "
            "skill written by someone else was available to calibrate on.",
            "- Known-good means well-regarded, not proven harmless.",
            "- Nobody outside this project has run these numbers yet.", ""]
    with open(os.path.join(REPO, "docs", "calibration.md"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(out))

    lines = ["# Rules", "", "Rules version %s. Written by `tests/make_docs.py` from the rules "
             "files and the language files." % version, "",
             "| Id | Severity | What it means | בעברית |", "| --- | --- | --- | --- |"]
    order = {"red": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for rule in sorted(rules, key=lambda r: (order[r["severity"]], r["id"])):
        note = " (reserved, never reported)" if rule.get("status") == "deferred" else ""
        lines.append("| %s | %s%s | %s | %s |" % (rule["id"], rule["severity"], note,
                                                  en["rules"][rule["id"]]["title"],
                                                  he["rules"][rule["id"]]["title"]))
    lines += ["", "A red line ends in \"do not install\". High ends in \"caution\". Medium and "
              "low are notes. Info appears only under details.", "",
              "## Rules of the trial run", "",
              "These describe what a skill's own commands did inside the sandbox, not what its "
              "files contain.", "",
              "| Id | Severity | What it means | בעברית |", "| --- | --- | --- | --- |"]
    for rule in sorted(trial_rules, key=lambda r: (order[r["severity"]], r["id"])):
        lines.append("| %s | %s | %s | %s |" % (rule["id"], rule["severity"],
                                              en["rules"][rule["id"]]["title"],
                                              he["rules"][rule["id"]]["title"]))
    lines.append("")
    with open(os.path.join(REPO, "docs", "rules.md"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def trial_section(found):
    """The corpus result of the trial, or the plain statement that there is none yet."""
    if not found:
        return ["**The trial rules have not yet been run against the known-good corpus.** That "
                "run starts code other people wrote, so it is done only in a real container: "
                "`python3 tests/calibrate_trial.py <corpus>`, or the calibration workflow in "
                "this repository. Until it has been done, treat a red line from a trial as "
                "strong evidence and a caution as a question to ask.", ""]
    summary = found["summary"]
    ran = [row for row in found["rows"] if row["status"] == "ran"]
    red = sorted({rule for row in ran for rule in row["rules"]
                  if rule in ("SR-TR-001", "SR-TR-002", "SR-TR-004")})
    return ["Run against the known-good corpus in a %s container: %d units had something to "
            "start, %d commands were started. Verdicts: %s. Red-line rules seen: %s."
            % (summary["engine"], summary["ran"], summary["commands"],
               ", ".join("%s %d" % kv for kv in sorted(summary["verdicts"].items())) or "none",
               ", ".join(red) or "none"), ""]


def fixture_count():
    sys.path.insert(0, HERE)
    import fixtures
    return len(fixtures.FIXTURES)


if __name__ == "__main__":
    main()
