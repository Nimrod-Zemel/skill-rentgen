# Changelog

## 0.1.0, not yet released

First build.

Scan:

- `scan` for folders, `.zip` and `.skill` archives, `.tar.gz`, and GitHub addresses.
- Reports in Hebrew and English as Markdown and as a single HTML page, a JSON report, SARIF output, and a page for a clean chat.
- 81 scan rules, 16 of them red lines, and 10 trial rules, 3 of them red lines.
- What a hook starts is followed through the scripts it runs and the modules it imports, so a payload one file away from the hook is judged as something that starts by itself.
- Rules for the shapes seen in published attacks on skill registries: an encoded command in a prerequisite, a raw IP address, a password-protected archive, a required tool on a free-hosting site, download-then-run in two steps, browser and wallet files, a fake password dialog.
- Calibrated on known-good skills and plugins and checked against an outside evaluation set. See docs/calibration.md.

Trial:

- `trial`: starts what a skill starts by itself inside a container with no network, with decoy secrets, and reports what it reached for. Starts nothing when no container engine answers.
- `trial --agent-pack` and `trial --agent-result`: a pack for an agent trial in cowork-harness, and a reader for its result.

Install, approve, monitor:

- `add`, `baseline`, `adopt`, `check`, `list`, `notify`, `block`, `unblock`.
- A check tells an update from tampering, and watches the settings keys that decide what runs by itself.
- The session hook is a separate small script that can only read.
- `inventory`, with `--doctor` to include the plugin copies that claude-plugin-doctor finds.

For builders:

- `declare`, a GitHub Action, a pre-commit hook.
