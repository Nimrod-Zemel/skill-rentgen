# Calibration

Rules version 2026.11.2. Every number on this page was written by `tests/make_docs.py` from the output of real runs. To repeat them, see the end of the page.

## Known-good corpus

Nine public repositories of well-regarded skills and plugins, read at these commits. They were read as examples of good practice. Nothing from them is copied here, and no report about any of them is published.

| Repository | Commit |
| --- | --- |
| github.com/anthropics/claude-code | `4cc5e8b63a` |
| github.com/anthropics/claude-plugins-official | `6985b2d88d` |
| github.com/anthropics/skills | `e4bb5d960d` |
| github.com/garrytan/gstack | `64fe9e5231` |
| github.com/coreyhaines31/marketingskills | `8fd2fcade2` |
| github.com/mattpocock/skills | `d65391149d` |
| github.com/DietrichGebert/ponytail | `ebd8654c2c` |
| github.com/obra/superpowers | `22f0b463e7` |
| github.com/vercel-labs/agent-skills | `5a37a6329f` |

Each plugin folder, each skill folder and each repository root was scanned as its own unit: 350 units.

| Unit | Count | Install | Install, with notes | Caution | Do not install |
| --- | --- | --- | --- | --- | --- |
| Skills | 277 | 204 | 70 | 3 | 0 |
| Plugins | 64 | 39 | 22 | 3 | 0 |
| Whole repositories | 9 | 0 | 5 | 4 | 0 |

Red-line findings on known-good units: **0**.

Caution among skills and plugins: **6 of 341 (1.8%)**. The gate allows 10%.

A whole repository is a collection of many skills, so one warning anywhere makes the repository a caution. The gate is measured on skills and plugins, which is what a person installs.

### Every caution, and why

Named by rule, not by project. Each one is an observation a person would want to know before installing.

| Rule | What was observed | Units |
| --- | --- | --- |
| SR-CD-001 | Contains code in a language the scan does not analyse | 1 |
| SR-DF-004 | Contacts a server that the docs never mention | 1 |
| SR-SF-002 | A hook runs a file outside the plugin folder | 1 |
| SR-SF-006 | An auto-run component pulls the latest version of a package every time | 3 |

## What calibration changed

The first run put 47 red-line findings on known-good units. Each one was read, and each led to a change that is recorded next to its rule.

| Rule | Severity now | Why |
| --- | --- | --- |
| SR-RL-03 | high | downgraded from red at design time: a long encoded string passed to exec is also how some build tools embed assets. High keeps it a caution |
| SR-RL-11 | medium | downgraded from red at design time: a paid service is a cost to know about, not a safety problem |
| SR-RL-15 | high | downgraded from red: in-process modules are an official Claude Code feature, used by four plugins in Anthropic's own directory |
| SR-ST-002 | info | structure note, not a safety signal |
| SR-ST-003 | info | structure note, not a safety signal |
| SR-ST-004 | info | structure note; the context cost badge carries it |
| SR-ST-005 | info | structure note, not a safety signal |
| SR-SF-004 | low | calibration: 78 of 341 known-good units pre-approve a tool; reported for Bash and * only |
| SR-CD-003 | high | raised to high: zero known-good skills or plugins run code built at run time; an independent set shows it is a common attack shape |
| SR-DF-011 | low | calibration: dynamic targets with network use named in the docs are routine |
| SR-DF-013 | info | calibration: 36 known-good units name a connected service; shown in the label |
| SR-DF-020 | medium | added with the add command: an installer that states what it installs is a note, the same way a declared server is. Undeclared stays SR-SF-007; a component that starts by itself stays the red line SR-RL-05 whatever is declared |

Changes that do not show as a severity:

- Invisible characters. Good code holds them inside quotes or a regex class, one at a time, to clean text. A red line now needs a character inside a word, a run with repeats, a run of twelve or more, or a bidi control that reorders code.
- Quoted attack phrases. Security documentation quotes phrases such as "ignore previous instructions" in quotes, code blocks and "look for" lists. Those are reported as mentions. A sentence that opens with the phrase is an order.
- Download and run. A known installer of a well-known tool, a container build file and an install hint inside an error message are not red lines.
- Promises. A statement in the front page of a collection, in a table row, or with a condition ("offline for local folders") is never a red line.
- Frontmatter. Folded descriptions and multi-line lists are read. Only constructs that can blow up a parser are refused.
- A server named in an open config file after the plugin itself counts as declared.
- What a hook starts. A file that a self-starting file hands to an interpreter, starts by its path or imports is judged as self-starting too, and so on down the chain. A file that is only mentioned by name is not followed: the first version of this rule followed mentions, reached hundreds of files in one repository, and put red lines on its tests.
- A declared installer. A command that writes into the skills folder is a caution. When the skill's capabilities file names that folder, it is a note (SR-DF-020). A component that starts by itself and writes there is a red line either way.
- Servers named in the code. In JavaScript, TypeScript and shell a call is tied to its address when both sit in one file. A server that is only held in a string, or used from another file, is listed in the label as named in the code, with no call found. XML namespaces, schema ids and licence links are names and are left out. On the corpus 21 of 341 skills and plugins get that line, 7 of them with a server their documents do not mention. Against the run before the change: 0 of 350 units changed verdict, and 2 gained a finding, each a call with an address decided at run time that was not seen before.
- The capabilities file. It is written by other people, and the first real one in another form (objects and booleans where lists are expected) stopped the contract stage. It is now read as far as it can be, and the report says which fields are not lists (SR-DF-012).
- A child process and its environment. Copying the environment for a child process is routine. The output of that child was also treated as the environment, so a version stamp read from `git rev-parse` looked like a dump of every variable (SR-DF-018). What is handed over as `env=` now stays with the child.
- A container command with a setting. `docker run -e KEY=value image:1.2` was read as starting an image called `value`. Only a flag is split at its equals sign now.

## Shapes taken from published attacks

In early 2026, researchers documented skills in a public registry that delivered an infostealer. The SKILL.md looked harmless. It carried a "prerequisite": run a command that was base64 text piped to a shell, which decoded to a download from a raw IP address; or fetch a password-protected archive; or install a "CLI" from a page on a free-hosting site. Sources are in ACKNOWLEDGEMENTS.md.

Each shape has a rule and a fixture named `real-*` in tests/fixtures.py. The tool decodes the base64 text without running it and reports what it says.

These rules were added after the first calibration and the corpus was run again: still no red line on a known-good unit.

## An outside check

Our own test skills pass because we wrote them. So the tool was also run on the evaluation set of [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) at commit `c558c42`: 29 cases that carry an expected verdict, written by other people for another scanner. They are small, inert fixtures, each built around one signal.

| Expected by Cisco | Cases | Flagged here (caution or do not install) |
| --- | --- | --- |
| Unsafe | 17 | 10 |
| Safe | 12 | 0 |

The first run flagged 3 of the 17 unsafe cases and wrongly blocked 1 safe case. That run is why the rules for raw sockets, tunnel services, registry redirects, whole-environment reads, installs from an address and instructions to obey outside content exist.

Unsafe cases not flagged, by category:

| Category | Verdict here | Why |
| --- | --- | --- |
| hardcoded-secrets | Install | The key is a dummy made of one repeated letter. Placeholders are ignored on purpose |
| harmful-content | Install | Out of scope: the tool does not judge the subject of the text |
| malware | Install | Out of scope: the payload is an inert string that nothing runs |
| path-traversal | Install | Out of scope: a flaw inside the skill's own code |
| resource-exhaustion | Install | Out of scope: a flaw inside the skill's own code |
| sql-injection | Install | Out of scope: a flaw inside the skill's own code |
| unauthorized-tool-use | Install, with notes | The address uses the reserved `.invalid` domain. Reserved domains are ignored on purpose |

## Our own test skills

`tests/fixtures.py` describes 103 test skills as data. They are written to disk only while a test runs. With the three examples, that is 106.

## The trial run

The trial has 13 rules of its own, 3 of them red lines, and 27 decoy files. `tests/test_trial.py` builds its test skills at test time and checks that each rule is triggered by one of them. Where Docker or Podman answers, the tests run in a real container and also check the fences from inside: no network, nothing writable outside the sandbox, not root. Elsewhere they run on a stand-in built from Linux namespaces.

Run against the known-good corpus in a docker container: 78 of 350 units had something to start, 206 commands were started. Verdicts: caution 3, notes 14, quiet 61. Red-line rules seen: none.

The first run on the corpus gave: caution 17, notes 4, quiet 57. No red line, and too many cautions. It showed four ordinary things judged as cautions: a tool used to run local code (`bun run`) counted as an installer; a package or image pinned to a version, and an installer inside a script the user runs, were judged like an unpinned download at start; reading session transcripts was a caution even for a plugin whose documents say that is its job; and opening a web page counted as contacting a server. Rules SR-TR-011, SR-TR-012 and SR-TR-013 and the list of runtimes came from that run.

The units at caution: `firebase`, `playwright`, `serena`. Each fetches and starts a package with no version when it starts, and each is also a caution in the scan.

## Speed

One skill through the real command line, with every stage in its own process: median 2.14 seconds, measured on every eighth skill and plugin of the corpus (43 of 341). The slowest unit, a whole repository, took 20 seconds with the stages in one process.

The check at the start of a session, on an approved skill of 500 files (1.7 MB) with nothing changed: median 52 milliseconds, measured over 15 runs. It compares size and change time and reads a file only when one of them differs.

## Repeat it

```bash
python3 tests/calibrate.py <folder with the repositories> --json out.json
python3 -m unittest discover -s tests -p "test_*.py"
```

## What this page does not show

- The corpus is skills written in English by experienced builders. No Hebrew skill written by someone else was available to calibrate on.
- Known-good means well-regarded, not proven harmless.
- Nobody outside this project has run these numbers yet.
