# Recipes

## Check your own skill in CI

For a repository that holds a skill or a plugin. The step fails on "caution" and on "do not install". Set `fail-on: block` to fail only on "do not install".

```yaml
name: skill-rentgen
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Nimrod-Zemel/skill-rentgen@<commit>
        with:
          path: .
          fail-on: block
          sarif: skill-rentgen.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: skill-rentgen.sarif
```

Replace `<commit>` with a full commit id of this repository. The report is added to the job summary. The action's outputs are `verdict` and `report`.

This repository tests the action in its own CI. It has not yet been used from another repository.

## Try a skill in a container, in CI

Linux runners on GitHub have Docker. This starts what the skill starts by itself and fails the job on "caution" or worse:

```yaml
      - uses: actions/checkout@v4
        with:
          repository: Nimrod-Zemel/skill-rentgen
          ref: <commit>
          path: .skill-rentgen
      - run: python3 .skill-rentgen/skill-rentgen/skills/skill-rentgen/scripts/skill_rentgen.py trial . --lang en
```

Useful options: `--run "python3 scripts/tool.py sample.csv"` starts one more command of yours in the container, `--timeout 30` gives each command more time, `--image` chooses another image when your hooks need a program that `python:3.12-slim` does not have.

## In a cloud session

A cloud session starts empty, often cannot reach GitHub's download host or Docker's image library, and has Docker installed but not running. Three options cover that:

```bash
# A GitHub address, read from a copy the session already fetched with its own repository tool
python3 skill_rentgen.py scan https://github.com/owner/repo/tree/main/skills/x --copy /path/to/clone

# A trial run: start Docker for this run, stop it afterwards, download nothing
python3 skill_rentgen.py trial ./my-skill --start-engine

# Keep what you approved for the next session
python3 skill_rentgen.py registry export --to skill-rentgen-registry.json
python3 skill_rentgen.py registry import skill-rentgen-registry.json
```

`add` in such a session writes `<name>.zip` (a skill) or `<name>.plugin` into the report folder instead of installing. `registry import --find` loads a registry file kept among the project's documents.

## Check before every commit

With [pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/Nimrod-Zemel/skill-rentgen
    rev: <commit>
    hooks:
      - id: skill-rentgen
```

It scans the repository and stops the commit on "do not install". This hook has not yet been run through pre-commit itself.

## Declare what your skill does

```bash
python3 skill_rentgen.py declare . > skill-capabilities.json
```

Then open the file, write the purpose of every server, and remove anything that is wrong. A server you declare is shown as "declared" in every report. A declaration is checked against the code and never excuses a red line. If one of your commands installs skills or edits agent settings, say so under `writes_outside_skill_dir` with the path; a declared write is a note, an undeclared one is a caution, and one done by a hook is a red line either way.

## See what an agent does with your instructions

```bash
python3 skill_rentgen.py trial . --agent-pack --own-skill
```

Writes a folder with a copy of your skill (hooks and servers removed), a scenario and a session for [cowork-harness](https://github.com/yaniv-golan/cowork-harness), and a README with three commands. After the harness has run:

```bash
python3 skill_rentgen.py trial --agent-result result.json
```

Without `--own-skill` the scenario asks for the harness's virtual-machine tier, which is the one its own security notes name for code you do not trust.

## Read a report in a browser

Every scan writes `<name>.he.html` and `<name>.en.html` next to the Markdown report. Each is one page with no scripts and no outside files, so it can be opened offline or sent as a file.
