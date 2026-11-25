#!/bin/sh
# pre-commit entry: check the skill or plugin in this repository before a commit.
here=$(cd "$(dirname "$0")/.." && pwd)
exec python3 "$here/skill-rentgen/skills/skill-rentgen/scripts/skill_rentgen.py" scan . --lang en --fail-on block --out "${TMPDIR:-/tmp}/skill-rentgen-pre-commit"
