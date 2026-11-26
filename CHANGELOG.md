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

A machine that starts empty every time (a cloud session):

- `scan`, `add` and `trial` take `--copy FOLDER` with a GitHub address: the repository is read from a copy already on disk and nothing is downloaded. The copy's origin and version are checked from its `.git` text files; git is never started.
- `trial --start-engine`: when Docker is installed and its service is not running, start it for one run and stop it afterwards. Linux, as root.
- A trial needs no image download on Linux: when the default image cannot be had, the container gets the machine's own program folders, each one read-only.
- `add` writes exactly the scanned files as one `.skill` or `.plugin` file instead of installing, and `add --as-file` does that anywhere.
- `registry export`, `registry import` and `registry where`: the registry as one small file to keep between sessions. `SKILL_RENTGEN_HOME` moves the registry folder.
- `inventory`, `baseline` and `check` also see the skills and plugins that an account brings into a cloud session.
- `check <name>` with a name that matches nothing is an error, not a quiet "nothing changed".

For builders:

- `declare`, a GitHub Action, a pre-commit hook.
