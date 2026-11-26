# SkillRentgen

Check an agent skill before you install it, try it in a sealed container, and know when it changes.

A skill is instructions and code that run with your permissions. SkillRentgen tells you, in Hebrew or English, three things: what a skill does, whether that matches what it promises, and what would run on your machine without you asking. A script decides the verdict. No model is asked.

Hebrew: [README.he.md](README.he.md)

## What you get

One word, one sentence, up to three things that matter, and a label.

```text
DO NOT INSTALL  pdf-tools  (exit 2)
6 findings, 3 red lines. Network: get.pdf-tools.example (undeclared), upload.pdf-tools.example (undeclared)
Report: ./skill-rentgen-report/pdf-tools.he.md
```

The report for that example ([Hebrew](examples/reports/pdf-tools.he.md), [English](examples/reports/pdf-tools.en.md)) says that the README promises "works fully offline, no data leaves your machine" while the code uploads to a server, that a script reads your SSH key, and that a hook downloads and runs a script every time a session starts. `pdf-tools` is a test skill written for this repository. Every example here is.

## Install

As a Claude Code plugin:

```text
/plugin marketplace add Nimrod-Zemel/skill-rentgen
/plugin install skill-rentgen@skill-rentgen
```

Or run the script directly. It needs Python 3.9 or newer and nothing else:

```bash
git clone https://github.com/Nimrod-Zemel/skill-rentgen
python3 skill-rentgen/skill-rentgen/skills/skill-rentgen/scripts/skill_rentgen.py scan <folder>
```

The folder `skill-rentgen/skills/skill-rentgen/` is also a plain skill. Copy it into any agent that reads the Agent Skills format.

## Use

```bash
python3 skill_rentgen.py scan <folder | file.zip | https://github.com/owner/repo>
python3 skill_rentgen.py trial <the same>      # start it in a sealed container and see what it tries
python3 skill_rentgen.py add <the same>        # install exactly what was scanned, if it passes
python3 skill_rentgen.py baseline              # check and record everything already on this machine
python3 skill_rentgen.py check                 # did anything I approved change?
```

Inside Claude, ask: "check this skill before I install it" and give the folder or the address.

Every scan also writes the report as a single HTML page that opens in any browser. Builders get `declare`, a GitHub Action, a pre-commit hook and SARIF output. See [docs/recipes.md](docs/recipes.md).

## Where it runs

On your own computer, and in a cloud session where the machine starts empty every time.

| | Your own computer | A cloud session |
| --- | --- | --- |
| A GitHub address | Downloaded from GitHub | Where the download host is closed, the agent brings the repository in with the session's own tool for repositories, and the scan reads that copy (`--copy`) |
| The trial run | Docker Desktop, OrbStack or Podman, running | Docker is usually installed and not running: `--start-engine` starts it for one run and stops it. No image is downloaded: the container gets the machine's own program folders, read-only |
| `add` | Installs into `~/.claude/skills` | Writes exactly the scanned files as one `.skill` or `.plugin` file, for you to install |
| The registry | `~/.skill-rentgen` | Also written as one small file to keep between sessions. `registry import` loads it |
| What is installed | Skill folders and Claude Code plugins | Also the skills and plugins your account brings into the session |

The cloud column was run on 26 November 2026 in a Claude cloud session, with this repository's own test skills and with public repositories that were already on its disk. Keeping the registry file between sessions is a step the agent does by following the skill's instructions; that step has not been watched from end to end.

## The four things it does

| What | How |
| --- | --- |
| Promise against code | Finds statements such as "works offline", "read-only" and "no data leaves your machine" in the docs and checks them against what the code does. A plain contradiction is a red line |
| What runs on its own, and where data goes | Lists every hook, MCP server, in-process module and `bin/` command, when each one runs, which servers the code contacts, which secrets it reads and where it writes. Python is read as a syntax tree. What a hook starts is followed through the scripts it runs and the modules it imports |
| See it before you install it, twice | **In a clean chat:** a page that quotes the skill's instructions, with invisible characters removed, to paste into a chat with no tools. **In a sealed container:** `trial` starts what the skill starts by itself, with no network and decoy secrets in place of yours, and reports what it reached for. For the instructions themselves there is a pack that runs them with a real agent inside [cowork-harness](https://github.com/yaniv-golan/cowork-harness) |
| Approve, then be told when it changes | Records a hash of every file you approved. `add` installs exactly the bytes that were scanned. A check tells an update from tampering, lists what was added, removed or changed, and watches the settings keys that decide what runs by itself. As a plugin it checks at the start of every session and prints one line only when something changed |

## How the verdict is decided

| You see | When | Exit code |
| --- | --- | --- |
| Install | Nothing above a note | 0 |
| Caution | At least one serious warning, or a part of the scan failed on the skill's own files | 1 |
| Do not install | A red line, or the skill's structure is itself unsafe | 2 |
| Tool error | The tool failed, or a trial was asked for and could not run. This is never shown as a verdict | 10 |

Only findings decide. A score exists for tools and never changes the verdict. Any number of warnings stays "caution". A scan that cannot finish never says "install". A quiet trial never upgrades a scan.

## The trial run

```text
TRIAL  DO NOT INSTALL  3 started, 11 seen
```

`trial` copies the skill into a container that has no network, a read-only system, no extra privileges, no path on your disk it can write to, and a home folder made for the run. In that home it plants 27 decoy files where real keys, tokens, browser logins and agent settings live. Then it starts each hook, server command and install script the skill declares, and each script its instructions point to (with `--help` only), and writes down what they did: which decoys they read, where a decoy's content went, which servers they tried, what they changed, what they tried to install.

- It needs Docker or Podman. With neither installed it says "not checked" and starts nothing. With Docker installed and not running it says so; `--start-engine` lets the tool start Docker's service for one run and stop it afterwards (Linux, as root). It never falls back to running on your computer.
- The sandbox image is `python:3.12-slim`. On Linux, when that image is not on the machine and cannot be fetched, the container gets the machine's own program folders instead (`/usr` and the like), each one read-only, and no folder that holds anything personal. The report says which was used.
- The verdict of a trial comes from ten rules of its own, three of them red lines.
- A trial is evidence of what was seen in one run. It is not evidence that a skill is safe, and every report says what the run does not show.

## Measured

Numbers from 25 November 2026. The method, the corpus and every caution are in [docs/calibration.md](docs/calibration.md).

| Test | Result |
| --- | --- |
| 341 well-regarded skills and plugins from nine public repositories, scanned | 0 red lines, 0 "do not install". 6 "caution" (1.8%), each one listed with its reason |
| 99 test skills of our own: known-bad, evasions, hostile inputs, near misses, and shapes taken from published attacks | All end in the verdict they were written for |
| 29 labelled cases from Cisco's skill-scanner evaluation set, written by others | 10 of 17 unsafe cases flagged. 0 of 12 safe cases flagged |
| Time for one skill, real command line | Median 2.7 seconds |
| The session check on a skill of 500 files, nothing changed | Median 72 milliseconds |
| The trial run, on six test skills of our own | Every one of the ten trial rules is triggered by one of them, and a hook that only reads its own settings stays quiet |

Of the 7 unsafe cases it does not flag, five belong to classes this tool does not check (flaws inside a skill's own code, and harmful content), and two use placeholder values that the tool ignores on purpose (a reserved domain, a dummy key).

The trial's rules have not yet been run against the known-good corpus. That run starts other people's code, so it is done only in a real container, by the calibration workflow in this repository.

## What it does not do

- A scan does not run the skill. A trial runs only what starts by itself, once, for a few seconds. A skill can wait, or behave well when it recognises a sandbox.
- It does not judge whether a skill's output is any good.
- It is not a code review. SQL injection, path traversal or an endless loop inside a skill's own code are not reported.
- Python is read in full. Shell and JavaScript are read by patterns. Other languages are reported as "not analysed", which is a caution.
- A script cannot decide free-language instructions. Clear cases are red lines. The rest is what the clean-chat page and the agent trial are for.
- "Install" is the result of a defined check, not a guarantee. Every report lists what was not checked.

## The tool itself

- Standard library only. No dependencies, no telemetry, no account, no token.
- A scan never runs or imports the skill it reads. Every stage runs in its own isolated Python process with a time limit. On macOS and Linux it also has a CPU limit and a memory limit.
- Only `trial` starts anything of a skill, and only inside a container.
- `add` installs a skill only after it passed, and only the bytes that were scanned.
- The part that starts by itself, the session hook, is a small script that can only read. It cannot scan, install, block or use the network, and a test checks that.
- Archives are unpacked entry by entry into a temporary folder. No link from an archive is ever created on disk.
- Network use: `codeload.github.com` when you give a GitHub address, `api.github.com` when you ask about upstream updates. Nothing else. With `--copy` a GitHub address is scanned from a copy on disk and nothing is downloaded. The container engine downloads the sandbox image the first time, if it can. See [skill-capabilities.json](skill-rentgen/skills/skill-rentgen/skill-capabilities.json).
- It passes its own check with two notes, both for commands that write into a `.claude` folder when you ask them to: `add` and `block`. CI fails if anything else appears.

Threat model and limits: [SECURITY.md](SECURITY.md).

## License and credits

Apache-2.0. Copyright 2026 Nimrod Zemel. The agent trial runs in [cowork-harness](https://github.com/yaniv-golan/cowork-harness) and the plugin copies are found by [claude-plugin-doctor](https://github.com/yaniv-golan/claude-plugin-doctor), both by Yaniv Golan. All prior work that shaped this tool is credited in [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md).
