# Vendored from cowork-harness

Three schema files from [yaniv-golan/cowork-harness](https://github.com/yaniv-golan/cowork-harness),
commit `ec3317fd1c83d86fab227dcb66af2133886ad24e`, MIT licence (see `LICENSE` in this folder,
Copyright (c) 2026 Yaniv Golan).

- `scenario.schema.json` and `session.schema.json`: the tests check that the scenario and the
  session that `trial --agent-pack` writes fit them.
- `run-result.json`: the tests check that the sample result they read has the shape the harness writes.

One change was made: the `description` text of every field was removed, to keep the files small.
The structure is untouched. They are used by tests only and are not part of the installed skill.
