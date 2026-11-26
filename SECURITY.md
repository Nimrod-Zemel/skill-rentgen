# Security

## Status

Pre-release. The scan rules were calibrated on 25 November 2026 against the corpus in [docs/calibration.md](docs/calibration.md). The trial rules have been run on this repository's own test skills only; they have not yet been calibrated on that corpus. No outside party has audited this tool. CI runs the tests on Linux and macOS, with Python 3.9 and 3.13; on Linux the trial tests run in Docker. Windows has not been tried. Treat its verdict as one careful opinion, not as proof.

## What this tool is for

A founder is about to install a skill or a plugin that someone else wrote. The tool reads it and reports what it does, whether that matches its documentation, and what would run without being asked.

It is built for these cases:

| Case | What the tool does |
| --- | --- |
| The code reads your keys, tokens or passwords | Red line |
| The code downloads something and runs it | Red line. A known installer of a well-known tool is a warning |
| A hook or a server entry changes the agent's settings or other skills | Red line |
| The instructions tell the agent to hide actions, skip approvals or follow orders from a URL | Red line |
| Text you cannot see: Unicode Tags, bidi overrides, look-alike letters in commands, hidden comments | Red line |
| The documentation says one thing and the code does another | Red line when the statement is plain and the evidence is in code |
| An executable with no source, or a file that takes the place of a standard Python module | Red line |
| A server that the documentation never mentions, a tunnel or paste service, a package registry redirect | Warning |
| An approved skill changes later | Reported by `check` and by the session hook. An update is told apart from files that changed with no new version |
| A hook starts a launcher, and the launcher starts the payload | Followed: what a self-starting file runs or imports is judged as self-starting too |
| A component that starts by itself reads your keys, sends them, or rewrites your settings when it runs | Seen by `trial`, in a container, with decoys in place of your files. Red line |

## What it does not protect against

Say these out loud to anyone who relies on the tool.

1. **A scan reads; it does not run.** Behaviour that depends on the date, on a server's answer or on your data is not seen by a scan. A trial run sees one short run of what starts by itself, and nothing more: see "The trial run" below.
2. **Free-language instructions.** A script matches phrases. An instruction written in new words, in another language, or split across files can pass. The page for a clean chat exists for this reason, and it relies on a person reading the answer.
3. **Mentions against orders.** A phrase inside quotes, a code block, or a list that begins "look for" is treated as a description. An attacker who knows this can dress an order as a description. An agent is less likely to obey text framed that way, and nothing more is claimed.
4. **Languages.** Python is read as a syntax tree. Shell and JavaScript are matched by patterns and can be evaded by anyone who tries. Other languages are not analysed at all, and the report says so with a caution.
5. **Data flow across functions.** The tool follows a value inside one file in simple cases. It does not follow values across files or through helper functions.
6. **Packages.** It reports that a skill installs packages. It does not inspect the packages.
7. **Vulnerabilities in the skill's own code.** SQL injection, path traversal, unsafe parsing and similar flaws are not its subject.
8. **A machine that is already compromised.** If something can change the tool's own files, the tool cannot be trusted.

## How the tool protects itself

The tool reads files written by strangers. These rules are tested in `tests/`.

| Rule | Why |
| --- | --- |
| A scan never executes and never imports the scanned skill | Reading must not be an attack surface |
| Only `trial` starts anything of a skill, and only inside a container. With no container engine it reports "not checked" | A trial that falls back to your own machine would be the attack |
| The tool starts a container engine's service only with `--start-engine`, only on Linux as root, and stops the one it started | Starting a service that runs as root is a change to the machine. It happens when asked and is undone |
| A GitHub address given with `--copy` is read from a folder on disk. Git is never started, and the `.git` folder is read as a few plain text files and never scanned or run | A copy made by another tool must not become a way to run that copy's hooks or settings |
| A carried registry file is checked for damage and every record is rebuilt field by field; a record that is not an approval is left out | The file comes from outside the tool's own folder |
| The session hook is a separate script that loads only the code that reads | The one part that starts by itself must not be able to install, block, scan or reach the network |
| The tool restarts itself in Python's isolated mode with bytecode reading disabled | A `json.py` or a `.pyc` planted in the current folder or next to the scripts is not loaded |
| Every stage runs in its own process with a time limit, and on macOS and Linux a CPU limit and a memory limit | A file built to hang or exhaust a parser stops one stage, not the scan |
| A stage that fails adds a finding and the verdict becomes "caution" at best | A crash must never read as "clean" |
| Severity is read from the rules files again when the verdict is computed | A stage cannot report a red line as a note |
| Frontmatter is parsed by a small reader that refuses anchors, aliases, tags, merge keys and deep nesting | General YAML parsers can be made to expand a few lines into gigabytes |
| Archives are unpacked entry by entry, with size limits; an entry that points outside ends the scan | Path traversal and archive bombs |
| Links are never followed, and a link inside an archive is recorded, never created | A link can point at your own files |
| Every quoted snippet is cut to 120 characters and stripped of control and invisible characters | The report is read by people and by agents |
| The session line is built from file names and counts only | A skill must not be able to speak to the agent through the alert |
| Downloads go to GitHub hosts only, and a redirect elsewhere is refused | The tool must not be turned into a fetcher |

## The trial run

What the container is given: no network, a read-only system, no extra privileges, a limit on memory, processes and time, an unprivileged user, and two read-only folders (a copy of the skill, and the four small files that record what happens). Nothing on your disk is writable from inside. The job goes in on standard input and the result comes back on standard output, marked with a value made for that run; a result without the mark is treated as no result.

What it sees: reads of 27 decoy files (by access time, by recording calls in Python and Node, and by the shell's own trace), the content of a decoy turning up in a command, a new file or the output, attempts to reach a server, changes to settings and start-up files, attempts to install or to gain rights.

What it does not see, and what you should not conclude from a quiet run:

1. **No agent runs.** The trial starts hooks, server commands, install scripts and the scripts the instructions point to. What an agent would do when it follows the instructions is a different question, and the agent trial pack is for that.
2. **One short run.** A skill that waits, or acts only on a certain date, machine or file, shows nothing.
3. **A skill can recognise a sandbox** and behave well inside it. The recording files are writable by the code being watched, so code written against this tool can also erase its own traces from them. Reads by access time and the comparison of files before and after do not depend on those files.
4. **A container shares the kernel of the machine.** It is the right fence for looking at a skill. It is not a guarantee against code written to break out of containers. On a Mac, Docker and Podman run containers inside a virtual machine, which adds a wall; on Linux they do not.
5. **The sandbox image** is `python:3.12-slim` from Docker's official library unless you choose another. It is not pinned to a digest. A bad image could lie about what a skill did; it could not reach your files or the network any more than the skill can.
   **When that image cannot be had, on Linux,** the container is given the machine's own program folders: `/usr`, the top-level folders that hold programs and libraries, the dynamic linker's files under `/etc`, and the install folder of Python or Node when it is under `/opt`. Each is mounted read-only. No home folder, no `/var`, no `/tmp`, and nothing else from `/etc` is given. The same fences apply: no network, no privileges, a read-only system. What changes is what the code can read: every program installed on the machine, and any file that somebody put under `/usr` or that `/opt` folder. If you keep something private there, use the default image.
6. **Programs other than Python, Node and the shell** are not recorded call by call. Their effects on the decoys and on the files are still seen.

The agent trial is not run by this tool. It writes a scenario for cowork-harness and reads the harness's result. For a skill that is not your own the scenario asks for the harness's virtual-machine tier, following the harness's own security notes, which say its container tier is for trusted code.

## A machine that starts empty: the carried registry

On a machine whose disk does not last, the registry is also written as one small file, and the instructions tell the agent to keep it where the session keeps things between chats. That file is not signed: the tool has no secret to sign it with, because it has no account and keeps no key. It is as trusted as the place it was kept. Three things follow:

1. Anyone who can write to that place can add an approval. A project that several people can write to is such a place.
2. An approval is a path and one hash. It does not make a skill pass a scan. It makes `check` stay quiet about files that match the hash.
3. The instructions tell the agent to load a registry file only from the project's own documents or from the user, and never from inside a skill or a repository being checked.

## Residual risks

Three residual risks remain and are accepted:

- A report quotes short snippets from the skill. An agent that reads the report sees them. They are marked as data, kept short and cleaned, and the instructions tell the agent to treat them as data.
- The session hook runs code at the start of every session. It reads the registry and the approved folders, uses no network, and exits silently on any error.
- `add` and `block` write into a `.claude` folder: `add` installs a skill that passed, `block` adds two deny rules with `--yes`. A tool that can write there is a tool worth attacking. Both are declared in the capabilities file, neither is reachable from the hook, and the tool's own scan reports them as notes.

## Network, files, telemetry

- Network: `codeload.github.com` when you scan a GitHub address without `--copy`. `api.github.com` when you use `adopt --source`, `add` with a GitHub address whose version the scan does not already know, or `check --upstream`. Nothing else. The container engine, not this tool, downloads the sandbox image the first time a trial runs, if it can.
- Files written: the report folder you choose; `~/.skill-rentgen/registry.json` and `state.json`; a temporary folder that is removed; with `add`, the skill folder you asked for; with `block --yes`, two lines in `./.claude/settings.local.json`.
- Programs started: Python for the tool's own stages; `docker` or `podman` for a trial; `dockerd` with `trial --start-engine`, stopped when the run ends; `cpd` with `inventory --doctor`, if you installed it.
- Telemetry: none.

## Reporting a problem

- A security flaw in the tool itself: open a private report through the repository's "Security" tab on GitHub. Please do not open a public issue first.
- A skill the tool wrongly blocks, or wrongly passes: open an issue with the report JSON. A wrong verdict is a bug.
