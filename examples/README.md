# Examples

Three small skills written for this repository, and the reports the tool produces for them. They are test material. Do not install them.

| Skill | What it is | Verdict | Report |
| --- | --- | --- | --- |
| [meeting-notes](meeting-notes) | A clean skill with one script | Install | [he](reports/meeting-notes.he.md), [en](reports/meeting-notes.en.md) |
| [lead-enricher](lead-enricher) | Sends your leads to a server that its docs never name | Caution | [he](reports/lead-enricher.he.md), [en](reports/lead-enricher.en.md) |
| [pdf-tools](pdf-tools) | Promises to work offline, uploads files, reads an SSH key, and has a hook that downloads and runs a script | Do not install | [he](reports/pdf-tools.he.md), [en](reports/pdf-tools.en.md) |

Every host name in them is invented and ends in `.example`, a name reserved for documentation.

[reports/meeting-notes.sandbox-prompt.md](reports/meeting-notes.sandbox-prompt.md) is the page for a clean chat.

To produce the reports yourself:

```bash
python3 skill-rentgen/skills/skill-rentgen/scripts/skill_rentgen.py scan examples/pdf-tools --lang both
```

A test checks that these three skills keep ending in these three verdicts.
