# Roadmap

One product, built in parts. What is written here as built has a test. What is not built says why.

## Part A: scan and label. Built

The scan, the report in Hebrew and English, the label of what a skill does, the timeline of what runs and when, the promise check, the page for a clean chat, and the inventory of what is installed.

Gate, measured on 25 November 2026:

| Condition | Result |
| --- | --- |
| No red line and no "do not install" on known-good skills | Met: 0 of 341 |
| At most 10% "caution" on known-good skills, each a correct observation | Met: 1.8%, listed in docs/calibration.md |
| Every active red line has a known-bad test skill | Met |
| Hostile inputs end in a refusal or a caution, never a crash | Met |
| The tool passes its own check | Met, with two notes for `add` and `block`, which write into a `.claude` folder when asked |
| Three founders read three reports and say what they would do, without help | **Open. Needs people** |
| A second person runs the tool on a machine that is not the author's | **Open. Needs a person** |

The two open conditions are the ones a build cannot close alone. Until they are met, the tool should not be announced.

## Part B: install, approve and monitor. Built, not yet used in the field

| What | State |
| --- | --- |
| `add`: scan, then install exactly the scanned bytes, record them, and verify the copy | Built |
| `baseline`: check everything installed that has no record, record what passes | Built |
| `adopt`, `list`, and a record that keeps what was accepted for a "caution" skill | Built |
| `check`: tells an update from tampering from a plain change; quick look by size and time, full hash once a week | Built |
| A record made under older rules is scanned again and marked | Built |
| A fingerprint of the settings keys that decide what runs by itself | Built |
| Skills that are installed and were never checked: said once | Built |
| The session hook, as a small script that can only read | Built |
| `check --upstream`, including a source address that now leads elsewhere | Built. The moved-address case is tested with a stand-in for GitHub, not against GitHub |
| `block` and `unblock`: a deny rule for one skill in the project's local settings, written only with `--yes` | Built. It does not stop a plugin's hooks or servers, and it does not undo what already ran in the session |
| The email alert | Built as a draft file. The tool sends nothing; a person or an agent with a mail connector sends it |

Not built:

- A second scanner as a second opinion (Cisco's skill-scanner behind its command line). Its condition stands: the false-alarm rate of this tool must first be stable across two versions of the rules. There is one version so far.
- A strict profile and a seven-day trial period for new skills. Both need field data first.
- Watching for changes between sessions. The check runs when a session starts or when asked.

Gate before calling part B finished: ten skills approved on three machines for two weeks, with every alert reviewed. Target: no false alert left open for more than seven days.

## Part C: the trial run, the network layer and tools for builders. Mostly built

| What | State |
| --- | --- |
| The trial run in a container | Built. Tested with this repository's own test skills, on a real container engine in CI and on a stand-in elsewhere. **Not yet calibrated on the known-good corpus**: that run starts other people's code and is done only in a real container, by `.github/workflows/calibration.yml` |
| The agent trial pack for cowork-harness, and the reader of its result | Built. The scenario and session are checked against the harness's published schemas. **Not yet run end to end**: that needs the harness, Docker, a Claude login, and for the virtual-machine tier a Mac with Apple silicon |
| `inventory --doctor`, through claude-plugin-doctor | Built against its documented output. **Not yet run against the real program**, which works on macOS only |
| `declare`, SARIF, the HTML report | Built |
| A GitHub Action (`uses: Nimrod-Zemel/skill-rentgen@<commit>`) and a pre-commit hook | Built. The action is tested by this repository's own CI |
| A name one letter away from a well-known skill; the same name in two places | The second is shown by `inventory`. The first is not built: it needs a list of well-known names that someone maintains |

Not built, and why:

- Reading public audits of a skill (for example on skills.sh) and showing them next to our verdict. There is no documented interface to read them from.
- Looking up known vulnerabilities of the packages a skill installs (OSV), and build attestations. Both need a network service on every scan, which the scan does not have today by design.
- A no-install sandbox for the Mac (the system's own sandbox instead of a container). It would let a founder run a trial without Docker. It is not offered until it has been built and tested on Macs, because a sandbox that was never tested is worse than none.
- Windows. The scan is plain Python and may work; nobody has run it there. The trial needs a container engine.

## Only if earned

- A catalog of checked skills. Needs an accelerator that commits in writing to maintain a list, and a second person who approves what the first one wrote.
- JavaScript and shell read as syntax trees. Would need a parser dependency, which breaks "standard library only".
- An inventory for other agents. Needs a test skill for each and one user who asked.
