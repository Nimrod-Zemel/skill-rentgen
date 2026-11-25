# Contributing

Thank you for looking. This tool tells people whether to trust code, so the bar for changing it is high and the rules are few.

## The rules

1. **Every rule has a test skill.** A new rule comes with a known-bad fixture that it catches and a near-miss fixture that it leaves alone. Fixtures live in `tests/fixtures.py` as data and are written to disk only while a test runs.
2. **Every rule is calibrated.** Run `python3 tests/calibrate.py <corpus>` before and after. A rule that puts a red line on a known-good skill does not ship as a red line. Record the reason in the rule's `calibration` field.
3. **The code decides.** No model in the path from files to verdict.
4. **Standard library only**, Python 3.9 and newer. The tests check both.
5. **Every sentence a user reads is in `i18n/he.json` and `i18n/en.json`.** Same keys in both. No long dashes.
6. **No claim without a measurement.** A number in the README comes from a run you can repeat. A feature in the README has a fixture.
7. **Examples are our own.** Never publish a report about someone else's skill in this repository.
8. **Nothing of a scanned skill runs on the machine.** A scan reads. A trial starts commands only inside a container. Code written by someone else is never started on the test stand-in; it is started only where a real container engine answers.
9. **The session hook stays small.** `session_check.py` may load only the modules that read. A test follows its imports.

## Running the tests

```bash
python3 -m unittest discover -s tests -p "test_*.py"
python3 skill-rentgen/skills/skill-rentgen/scripts/skill_rentgen.py scan skill-rentgen
```

The second command is the self-check. It must exit 0 and list only the two notes for `add` and `block`.

Where Docker or Podman is running, the trial tests use a real container. Elsewhere they use a stand-in built from Linux namespaces (`tests/fake_engine.py`), and on a machine that has neither they are skipped. CI on Linux runs them in Docker.

## Reporting a wrong verdict

A skill that is wrongly blocked and a bad skill that passes are both bugs. Open an issue with the `report.json`. If the skill is not yours, describe the pattern in a few lines of your own and leave the author's name out.
