# Third-party notices

The installed tool (`skill-rentgen/`) contains no third-party code. It uses the Python standard library only.

The tests contain three data files from another project:

| Files | From | Licence |
| --- | --- | --- |
| `tests/vendor/cowork-harness/scenario.schema.json`, `session.schema.json`, `run-result.json` | [yaniv-golan/cowork-harness](https://github.com/yaniv-golan/cowork-harness), commit `ec3317fd1c83d86fab227dcb66af2133886ad24e`. The `description` text of each field was removed; the structure is unchanged | MIT, Copyright (c) 2026 Yaniv Golan. Full text in `tests/vendor/cowork-harness/LICENSE` |

They are used to check that the scenario and session this tool writes, and the result it reads, fit the formats the harness publishes. They are not part of the plugin and are not installed with it.

If code or data from another project is ever added, it will be listed here with its licence.
