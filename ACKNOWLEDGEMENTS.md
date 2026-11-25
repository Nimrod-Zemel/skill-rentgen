# Acknowledgements

Prior work that shaped this tool. Each line says what was taken from it and how it is used.

## Tools this one works with

- [yaniv-golan/cowork-harness](https://github.com/yaniv-golan/cowork-harness) (MIT, by Yaniv Golan): the environment for the agent trial. `trial --agent-pack` writes a scenario and a session in its formats, and `trial --agent-result` reads the result file it writes. Three of its schema files, at commit `ec3317f`, are kept under `tests/vendor/` so the tests can check that what this tool writes and reads fits them. Its SECURITY.md is the reason the pack asks for the virtual-machine tier for a skill that is not your own, and the reason the trial run here starts nothing without a container. SkillRentgen does not include or run the harness; you install it yourself.
- [yaniv-golan/claude-plugin-doctor](https://github.com/yaniv-golan/claude-plugin-doctor) (MIT, by Yaniv Golan): the map of where a plugin is kept on a machine. `inventory --doctor` reads its documented JSON output, when it is installed, to find the copies that Claude Cowork keeps and the copies that are out of step, so that a scan covers the copy that runs. SkillRentgen does not include it.

## Work this one learned from

- [Agent Skills](https://agentskills.io): the open format this tool reads.
- [vercel-labs/skills](https://github.com/vercel-labs/skills) (MIT): the `computedHash` content hash of its lock file. Reimplemented here in Python for compatibility, against commit `57217cf`, and checked with three test vectors.
- [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) (Apache-2.0): its public evaluation set, at commit `c558c42`, served as a check written by someone else. The cases this tool first missed led to five new rules, to changes in five existing ones, and to our own fixtures for them. None of its fixtures or rules are copied.
- Published analyses of malicious skills found in a public skill registry in early 2026: [Snyk, "Inside the 'clawdhub' Malicious Campaign"](https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/) (Liran Tal, February 2026) and [Trend Micro, on skills used to distribute Atomic macOS Stealer](https://www.trendmicro.com/en/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html) (February 2026). The shapes they describe are the reason for the rules on encoded commands, raw IP addresses, password-protected archives and prerequisites hosted on free sites, and for the list of decoy files in the trial run. Our fixtures for them are our own, with addresses from a range reserved for documentation.
- [lool-ventures/founder-skills](https://github.com/lool-ventures/founder-skills) (Apache-2.0): two things learned from reading the repository. The pattern in which a deterministic script validates every step before the work continues, and the layout of one repository that holds one package.
- The maintainers of the nine public repositories used for calibration, listed in [docs/calibration.md](docs/calibration.md). Their skills were read as examples of good practice. No report about any of them is published here.

A contributor is someone who made a commit. Nobody is listed as one without that.
