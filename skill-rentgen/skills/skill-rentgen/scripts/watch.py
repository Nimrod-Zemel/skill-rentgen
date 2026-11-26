"""Compare what is on disk with what was approved. Reads only.

WHY: this is the part that runs at the start of every session, so it is
kept apart from everything that can install, block or scan. It opens the
registry, lists folders, and hashes files as plain bytes. It parses no
file of a skill and starts no program. The only thing it writes is its own
bookkeeping file, next to the registry.

Rules that tests check:
1. A file whose size and change time match the record is not read again,
   except in the weekly full pass.
2. A file that was touched but holds the same bytes is not a change.
3. Nothing here changes what was approved.
"""
from __future__ import annotations

import hashlib
import os

import inventory
import registry
from common import LIMITS, SKILL_DIR, load_json


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def diff_folder(record, path, full=False):
    """What was added, removed or changed since the record was made.
    Returns None when the folder cannot be listed."""
    stats = registry.quick_stats(path)
    if stats is None:
        return None
    files, stored = record.get("files", {}), record.get("stats") or {}
    if not files and record.get("tree"):
        # A record that was carried in holds one hash for all its files.
        now_files = {}
        try:
            for rel in stats:
                now_files[rel] = sha256_file(os.path.join(path, rel))
        except OSError:
            return {"added": [], "removed": [], "changed": ["?"]}
        if registry.tree_hash(now_files) != record["tree"]:
            return {"added": [], "removed": [], "changed": ["?"]}
        return {"added": [], "removed": [], "changed": [], "files": now_files, "stats": stats}
    added = sorted(set(stats) - set(files)) if len(files) < LIMITS["soft_files"] else []
    removed = sorted(set(files) - set(stats))
    changed = []
    for rel in sorted(set(files) & set(stats)):
        if not full and stored.get(rel) == stats[rel]:
            continue
        try:
            if sha256_file(os.path.join(path, rel)) != files[rel]:
                changed.append(rel)
        except OSError:
            changed.append(rel)
    return {"added": added, "removed": removed, "changed": changed}


def rules_version():
    return load_json(os.path.join(SKILL_DIR, "rules", "red-lines.json"))["rules_version"]


def compare(home, name="", hook=False, upstream=None):
    """Every approved skill against its record.
    Returns (changes, extras, data). `upstream`, when given, is a function
    that takes a GitHub address and returns (commit, moved)."""
    data = registry.load(home)
    state = registry.load_state(home)
    installs = inventory.plugin_installs()
    rules_now = rules_version()
    changes = []
    refilled = False
    for key, record in sorted(data["skills"].items()):
        if name and name not in (record.get("name"), key):
            continue
        item = {"id": key, "name": record.get("name", key), "path": record.get("path", ""),
                "status": "same", "added": [], "removed": [], "changed": [],
                "verdict_then": record.get("verdict", "")}
        plugin = record.get("plugin") or {}
        if plugin.get("key"):
            now_at = installs.get(plugin["key"])
            if now_at is None:
                item["status"] = "missing"
            else:
                item["path"] = now_at["path"]
                if now_at["version"] != plugin.get("version", ""):
                    item.update(status="updated", version_then=plugin.get("version", ""),
                                version_now=now_at["version"])
        if item["status"] != "missing" and not os.path.isdir(item["path"]):
            item["status"] = "missing"
        elif item["status"] != "missing":
            full = not hook and registry.full_check_due(state, key)
            found = diff_folder(record, item["path"], full or item["status"] == "updated")
            if not record.get("files") and record.get("tree"):
                item["carried"] = True
            if found is None:
                item["changed"] = ["?"]
            else:
                fresh = found.pop("files", None), found.pop("stats", None)
                item.update(found)
                if full:
                    state["full_check"][key] = registry.now()
                if fresh[0] is not None and not hook:
                    # The files matched the carried hash: keep their list from now on.
                    record["files"], record["stats"] = fresh
                    record["path"] = item["path"]
                    refilled = True
            if (item["added"] or item["removed"] or item["changed"]) and item["status"] == "same":
                item["status"] = "tampered" if plugin.get("key") else "changed"
        if not hook and record.get("rules_version") and record["rules_version"] != rules_now:
            item["rules_changed"] = True
            if item["status"] == "same":
                item["status"] = "rules"
        if upstream and not hook and record.get("upstream", {}).get("url"):
            head, moved = upstream(record["upstream"]["url"])
            known = record["upstream"].get("commit")
            if moved:
                item["upstream_moved"] = True
            if (head and known and head != known) or moved:
                item["upstream_commit"] = head or ""
                if item["status"] == "same":
                    item["status"] = "upstream"
        if item["status"] != "same":
            changes.append(item)
    known_paths = {record.get("path") for record in data["skills"].values()} | {
        item["path"] for item in changes}
    known_plugins = {(r.get("plugin") or {}).get("key") for r in data["skills"].values()} - {None}
    unknown = [] if name else [entry for entry in inventory.installed()
                               if entry["path"] not in known_paths
                               and entry.get("plugin_key") not in known_plugins]
    stored = (data.get("agent_settings") or {}).get("files")
    settings = [] if (name or stored is None) else registry.settings_diff(
        stored, registry.settings_fingerprint(registry.settings_files()))
    if refilled:
        registry.save(home, data)
    if hook:
        fresh = [entry for entry in unknown if entry["path"] not in state["noted"]]
        if fresh:
            state["noted"] = sorted(set(state["noted"]) | {e["path"] for e in fresh})[-2000:]
            registry.save_state(home, state)
        unknown = fresh
    else:
        registry.save_state(home, state)
    return changes, {"unknown": unknown, "settings": settings}, data


def session_line(home, lang=None):
    """The one line for the start of a session. Empty when all is quiet."""
    known = registry.load(home)
    if not known["skills"] and not known["agent_settings"] and registry.short_lived():
        # A machine that starts empty every time has nothing to compare with.
        # Saying "never checked" at the start of every session would be noise.
        return ""
    lang = lang or known["settings"].get("lang") or "he"
    changes, extras, _ = compare(home, hook=True)
    return registry.hook_line(changes, lang, len(extras["unknown"]), extras["settings"])
