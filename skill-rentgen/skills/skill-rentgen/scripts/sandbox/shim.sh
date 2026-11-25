#!/bin/sh
# Stands in for a network, installer or system program inside the sandbox.
# Records that it was called and with what, then fails. Nothing is fetched,
# installed or changed.
name=${0##*/}
if [ -n "$SR_TRACE" ]; then
  line=$(printf '%s' "$*" | tr '\n\r\t"\\' '     ' | cut -c1-900)
  printf '{"kind": "shim", "tool": "%s", "args": "%s"}\n' "$name" "$line" >> "$SR_TRACE"
fi
echo "skill-rentgen trial: $name is switched off inside the sandbox" >&2
exit 1
