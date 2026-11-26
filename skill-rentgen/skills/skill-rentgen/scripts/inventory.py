"""What is installed on this machine. Reads only.

WHY: you cannot watch what you cannot list. This module finds the skill
folders and the installed plugins of the agents this tool knows, and
nothing else. It opens index files and lists folders. It never opens a
file of a skill and never writes.

The places come from rules/places.json. Two kinds of machine are covered:
a personal computer, where the agent keeps skills in the home folder, and
a cloud session, where the skills and plugins of the account are copied
in when the session starts.
"""
from __future__ import annotations

import os

from common import load_json, rule_file


def _expand(pattern, cwd=None):
    """A path from the places file as real folders. `~` is the home folder,
    `./` is the folder the tool runs in, and one trailing `/*` means every
    folder directly inside."""
    home, here = os.path.expanduser("~"), cwd or os.getcwd()
    each = pattern.endswith("/*")
    if each:
        pattern = pattern[:-2]
    if pattern.startswith("~/"):
        path = os.path.join(home, pattern[2:])
    elif pattern.startswith("./"):
        path = os.path.join(here, pattern[2:])
    else:
        path = pattern
    if not each:
        return [path]
    try:
        names = sorted(os.listdir(path))
    except OSError:
        return []
    return [os.path.join(path, name) for name in names
            if not name.startswith(".") and os.path.isdir(os.path.join(path, name))]


def account_plugins():
    """Plugins that a cloud session copied in for this account:
    {"name@marketplace": {"path", "version", "name"}}. The folder of a plugin
    is named <name>~g<generation>; its index says the version."""
    found = {}
    for place in rule_file("places.json").get("plugin_folders", []):
        for folder in _expand(place["path"]):
            listed = {}
            try:
                index = load_json(os.path.join(folder, place.get("index", "manifest.json")))
                for entry in index.get("plugins", []) if isinstance(index, dict) else []:
                    if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                        listed[entry["name"]] = entry
            except (OSError, ValueError, RecursionError):
                pass
            try:
                names = sorted(os.listdir(folder))
            except OSError:
                continue
            for name in names:
                path = os.path.join(folder, name)
                if name.startswith(".") or not os.path.isdir(path):
                    continue
                plain = name.split("~", 1)[0]
                entry = listed.get(plain, {})
                market = entry.get("marketplaceName")
                key = "%s@%s" % (plain, market if isinstance(market, str) and market else "account")
                version = "%s/%s" % (entry.get("version") or "", entry.get("generation") or "")
                found[key] = {"path": os.path.realpath(path), "name": plain, "where": place["where"],
                              "version": version.strip("/") or name.partition("~")[2]}
    return found


def plugin_installs(root=None):
    """Installed plugins: {"name@marketplace": {"path", "version"}}. Those
    Claude Code lists in its own index and, when `root` is not given, those
    a cloud session copied in."""
    listed_root = root or os.path.join(os.path.expanduser("~"), ".claude", "plugins")
    try:
        listed = load_json(os.path.join(listed_root, "installed_plugins.json")).get("plugins", {})
    except (OSError, ValueError, AttributeError, RecursionError):
        listed = {}
    found = {} if root else {key: {"path": info["path"], "version": info["version"]}
                             for key, info in account_plugins().items()}
    for key, entries in sorted(listed.items() if isinstance(listed, dict) else []):
        for entry in entries if isinstance(entries, list) else []:
            path = entry.get("installPath") if isinstance(entry, dict) else None
            if isinstance(path, str) and isinstance(key, str):
                found[key] = {"path": os.path.realpath(path),
                              "version": str(entry.get("version") or "")}
    return found


def installed():
    """List skills and plugins already on this machine."""
    places = rule_file("places.json")
    containers = set(places.get("containers", []))
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

    for place in places.get("skill_folders", []):
        for folder in _expand(place["path"]):
            try:
                names = sorted(os.listdir(folder))
            except OSError:
                continue
            for name in names:
                path = os.path.join(folder, name)
                if name.startswith("."):
                    continue
                if name in containers and not os.path.isfile(os.path.join(path, "SKILL.md")):
                    continue        # a folder that holds skill folders, not a skill
                add_item("skill", place["where"], path)
    account = account_plugins()
    for key, info in plugin_installs().items():
        add_item("plugin", account.get(key, {}).get("where", "user"), info["path"],
                 account.get(key, {}).get("name") or key.split("@")[0], plugin_key=key,
                 version=info["version"])
    names = {}
    for item in found:
        names.setdefault((item["kind"], item["name"]), []).append(item)
    for group in names.values():
        if len(group) > 1:
            for item in group:
                item["shadowed"] = True
    return found
