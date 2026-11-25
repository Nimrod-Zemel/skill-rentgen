"""What is installed on this machine. Reads only.

WHY: you cannot watch what you cannot list. This module finds the skill
folders and the installed plugins of the agents this tool knows, and
nothing else. It opens index files and lists folders. It never opens a
file of a skill and never writes.
"""
from __future__ import annotations

import os

from common import load_json


def plugin_installs(root=None):
    """Installed Claude Code plugins: {"name@marketplace": {"path", "version"}}."""
    root = root or os.path.join(os.path.expanduser("~"), ".claude", "plugins")
    try:
        listed = load_json(os.path.join(root, "installed_plugins.json")).get("plugins", {})
    except (OSError, ValueError, AttributeError, RecursionError):
        return {}
    found = {}
    for key, entries in sorted(listed.items() if isinstance(listed, dict) else []):
        for entry in entries if isinstance(entries, list) else []:
            path = entry.get("installPath") if isinstance(entry, dict) else None
            if isinstance(path, str) and isinstance(key, str):
                found[key] = {"path": os.path.realpath(path),
                              "version": str(entry.get("version") or "")}
    return found


def installed():
    """List skills and plugins already on this machine."""
    home, here = os.path.expanduser("~"), os.getcwd()
    places = [("user", os.path.join(home, ".claude", "skills")),
              ("project", os.path.join(here, ".claude", "skills")),
              ("user", os.path.join(home, ".agents", "skills")),
              ("project", os.path.join(here, ".agents", "skills"))]
    found, seen = [], set()

    def add_item(kind, where, path, name=None, **extra):
        real = os.path.realpath(path)
        if real in seen or not os.path.isdir(real):
            return
        seen.add(real)
        item = {"kind": kind, "where": where, "path": real,
                "name": name or os.path.basename(path.rstrip(os.sep))}
        item.update(extra)
        found.append(item)

    for where, folder in places:
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        for name in names:
            if not name.startswith("."):
                add_item("skill", where, os.path.join(folder, name))
    for key, info in plugin_installs().items():
        add_item("plugin", "user", info["path"], key.split("@")[0], plugin_key=key,
                 version=info["version"])
    names = {}
    for item in found:
        names.setdefault((item["kind"], item["name"]), []).append(item)
    for group in names.values():
        if len(group) > 1:
            for item in group:
                item["shadowed"] = True
    return found
