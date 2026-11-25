"""Stage 1: structure. Find the skills, plugins and docs, and read frontmatter.

WHY: frontmatter is YAML, and a general YAML parser accepts anchors and
aliases that expand a few lines into gigabytes. A skill only needs a small
subset, so this stage parses that subset itself and fails closed on the
rest: a frontmatter block it cannot read safely is a finding, not a crash.

Rules that tests check:
1. Anchors, aliases, tags and merge keys in frontmatter are refused.
2. Nesting deeper than 8 levels, or more than 2,000 lines, is refused.
3. The verdict unit is the plugin when a plugin manifest sits at the root.
"""
from __future__ import annotations

import os
import re

from common import finding, load_json, read_text

MAX_DEPTH = 8
MAX_ITEMS = 2000
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
LINK_RE = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)\)")


class FrontmatterError(Exception):
    """The block has a shape this reader does not parse."""


class FrontmatterRefused(FrontmatterError):
    """The block uses a construct that can blow up a YAML parser."""


def _scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    cut = text.find(" #")
    if cut != -1:
        text = text[:cut].rstrip()
    if text in ("null", "~", ""):
        return None
    if text in ("true", "True"):
        return True
    if text in ("false", "False"):
        return False
    return text


def _check_value(text):
    if text[:1] in ("&", "*") or text.startswith("!!") or text.startswith("!<"):
        raise FrontmatterRefused("anchors, aliases and tags are not allowed")


def _flow_list(text):
    inner = text.strip()[1:-1]
    out, buf, quote = [], "", ""
    for char in inner:
        if quote:
            buf += char
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
            buf += char
        elif char == ",":
            out.append(_scalar(buf))
            buf = ""
        else:
            buf += char
    if buf.strip():
        out.append(_scalar(buf))
    return out


def _split_key(text):
    if text.startswith(("\"", "'")):
        quote = text[0]
        end = text.find(quote, 1)
        if end != -1 and text[end + 1:end + 2] == ":":
            return text[1:end], text[end + 2:].strip()
        return None
    pos = text.find(":")
    while pos != -1:
        if pos == len(text) - 1 or text[pos + 1] == " ":
            return text[:pos].strip(), text[pos + 1:].strip()
        pos = text.find(":", pos + 1)
    return None


def _node(items, pos, indent, depth):
    if depth > MAX_DEPTH:
        raise FrontmatterRefused("nesting is too deep")
    if items[pos][1].startswith("- ") or items[pos][1] == "-":
        out = []
        while pos < len(items) and items[pos][0] == indent and (
                items[pos][1].startswith("- ") or items[pos][1] == "-"):
            body = items[pos][1][1:].strip()
            _check_value(body)
            if not body:
                pos += 1
                if pos < len(items) and items[pos][0] > indent:
                    value, pos = _node(items, pos, items[pos][0], depth + 1)
                    out.append(value)
                else:
                    out.append(None)
            elif _split_key(body) and not body.startswith(("\"", "'", "[", "{")):
                inner = indent + 2
                items[pos] = (inner, body)
                value, pos = _node(items, pos, inner, depth + 1)
                out.append(value)
            else:
                out.append(_flow_list(body) if body.startswith("[") and body.endswith("]")
                           else _scalar(body))
                pos += 1
        return out, pos
    out = {}
    while pos < len(items) and items[pos][0] == indent:
        pair = _split_key(items[pos][1])
        if pair is None:
            raise FrontmatterError("line is not a key and a value")
        key, value = pair
        if key == "<<":
            raise FrontmatterRefused("merge keys are not allowed")
        _check_value(value)
        pos += 1
        deeper = pos < len(items) and items[pos][0] > indent
        if value.startswith("[") and not value.endswith("]") and deeper:
            parts = [value]
            while pos < len(items) and items[pos][0] > indent:
                parts.append(items[pos][1])
                pos += 1
            joined = " ".join(parts)
            out[key] = _flow_list(joined) if joined.endswith("]") else joined
        elif value in ("", "|", ">", "|-", ">-", "|+", ">+"):
            if deeper and value == "":
                first = items[pos][1]
                block_end = pos
                while block_end < len(items) and items[block_end][0] > indent:
                    block_end += 1
                looks_nested = first == "-" or first.startswith("- ") or (
                    _split_key(first) is not None and not first.startswith(("\"", "'", "[")))
                parsed = False
                if looks_nested:
                    saved = list(items[pos:block_end])
                    try:
                        out[key], after = _node(items, pos, items[pos][0], depth + 1)
                        parsed = after == block_end
                    except FrontmatterRefused:
                        raise
                    except FrontmatterError:
                        parsed = False
                    if not parsed:
                        items[pos:block_end] = saved
                if not parsed:
                    joined = " ".join(item[1] for item in items[pos:block_end])
                    if joined.startswith("[") and joined.endswith("]"):
                        out[key] = _flow_list(joined)
                    else:
                        out[key] = _scalar(joined)
                pos = block_end
            elif deeper:
                lines = []
                while pos < len(items) and items[pos][0] > indent:
                    lines.append(items[pos][1])
                    pos += 1
                out[key] = ("\n" if value.startswith("|") else " ").join(lines)
            else:
                out[key] = None
        elif value.startswith("[") and value.endswith("]"):
            out[key] = _flow_list(value)
        else:
            text = value
            while pos < len(items) and items[pos][0] > indent:
                text += " " + items[pos][1]
                pos += 1
            out[key] = _scalar(text)
    return out, pos


def parse_frontmatter(text):
    """Return (data, body_start_line, error). data is None when absent or refused."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return None, 0, None
    end = None
    for index in range(1, min(len(lines), MAX_ITEMS + 2)):
        if lines[index].strip() in ("---", "..."):
            end = index
            break
    if end is None:
        return None, 0, "frontmatter is not closed"
    items = []
    for raw in lines[1:end]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        lead = raw[:len(raw) - len(raw.lstrip())]
        if "\t" in lead:
            return None, end + 1, "tab indentation"
        items.append((len(lead), raw.strip()))
    if len(items) > MAX_ITEMS:
        return None, end + 1, "refused: frontmatter is too long"
    if not items:
        return {}, end + 1, None
    try:
        data, _ = _node(items, 0, items[0][0], 0)
    except FrontmatterRefused as error:
        return None, end + 1, "refused: " + str(error)
    except FrontmatterError as error:
        return None, end + 1, str(error)
    except RecursionError:
        return None, end + 1, "refused: nesting is too deep"
    return (data if isinstance(data, dict) else {}), end + 1, None


def _loose(text):
    """Read name, description and allowed-tools line by line, for a block
    the reader could not parse. Returns (fields, raw_block)."""
    lines = text.split("\n")
    block = []
    for line in lines[1:MAX_ITEMS]:
        if line.strip() in ("---", "..."):
            break
        block.append(line)
    raw = "\n".join(block)
    fields = {}
    for key in ("name", "description", "allowed-tools"):
        match = re.search(r"^%s:[ \t]*(\S.*)$" % key, raw, re.M)
        if match:
            fields[key] = _scalar(match.group(1))
    return fields, raw


def _tools(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [part.strip() for part in re.split(r",(?![^(]*\))", str(value)) if part.strip()]


def _skill(root, rel, findings):
    text, _ = read_text(os.path.join(root, rel))
    data, body_line, error = parse_frontmatter(text)
    folder = os.path.dirname(rel)
    info = {"file": rel, "dir": folder, "lines": text.count("\n") + 1,
            "tokens": len(text) // 4, "name": None, "description": None,
            "allowed_tools": [], "fm_hooks": False}
    if error and error.startswith("refused:"):
        findings.append(finding("SR-ST-006", rel, 1, error, kind="input"))
        return info
    if error:
        findings.append(finding("SR-ST-008", rel, 1, error))
        data, raw = _loose(text)
        if re.search(r"^hooks:", raw, re.M):
            info["fm_raw"] = raw[:20000]
    if data is None:
        findings.append(finding("SR-ST-001", rel, 1, "no frontmatter"))
        return info
    name, description = data.get("name"), data.get("description")
    info["name"] = name if isinstance(name, str) else None
    info["description"] = description if isinstance(description, str) else None
    info["allowed_tools"] = _tools(data.get("allowed-tools") or data.get("allowed_tools"))
    info["fm_hooks"] = isinstance(data.get("hooks"), (dict, list)) and bool(data.get("hooks"))
    info["fm"] = {key: data[key] for key in ("hooks", "license", "compatibility", "model")
                  if key in data}
    if not info["name"] or not info["description"]:
        findings.append(finding("SR-ST-001", rel, 1, "name or description is missing"))
    else:
        base = os.path.basename(folder) if folder else ""
        if not NAME_RE.match(info["name"]) or len(info["name"]) > 64 or (
                base and NAME_RE.match(base) and base != info["name"]):
            findings.append(finding("SR-ST-002", rel, 1, info["name"]))
        if len(info["description"]) > 1024 or "<" in info["description"]:
            findings.append(finding("SR-ST-003", rel, 1, info["description"][:60]))
    if info["lines"] > 500:
        findings.append(finding("SR-ST-004", rel, 1, "%d lines" % info["lines"]))
    missing = 0
    for match in LINK_RE.finditer(text):
        target = match.group(1).split("#")[0].split("?")[0]
        if not target or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith(("/", "<", "{", "$")):
            continue
        path = os.path.normpath(os.path.join(root, folder, target))
        if not path.startswith(os.path.normpath(root)) or os.path.exists(path):
            continue
        missing += 1
        if missing <= 3:
            findings.append(finding("SR-ST-005", rel, text.count("\n", 0, match.start()) + 1, target))
    return info


def _component(root, rel):
    text, _ = read_text(os.path.join(root, rel), 200000)
    data, _, error = parse_frontmatter(text)
    raw = ""
    if error and not error.startswith("refused:"):
        data, raw = _loose(text)
    data = data or {}
    return {"file": rel, "name": data.get("name"),
            "fm_raw": raw[:20000] if re.search(r"^hooks:", raw, re.M) else "",
            "allowed_tools": _tools(data.get("allowed-tools")),
            "fm_hooks": bool(data.get("hooks")), "fm": {"hooks": data.get("hooks")} if data.get("hooks") else {},
            "error": error}


def run(root, work, opts):
    intake = load_json(os.path.join(work, "intake.json"))
    paths = [entry["p"] for entry in intake.get("files", [])]
    findings, skills, agents, commands, plugins = [], [], [], [], []
    marketplace = None
    for rel in paths:
        base = os.path.basename(rel)
        parts = rel.split("/")
        if base == "SKILL.md" and len(skills) < 400:
            skills.append(_skill(root, rel, findings))
        elif rel.endswith(".claude-plugin/plugin.json"):
            try:
                data = load_json(os.path.join(root, rel))
            except (OSError, ValueError, RecursionError):
                findings.append(finding("SR-ST-006", rel, 1, "plugin.json is not valid JSON", kind="input"))
                data = {}
            plugins.append({"file": rel, "dir": os.path.dirname(os.path.dirname(rel)),
                            "name": data.get("name") if isinstance(data, dict) else None,
                            "version": data.get("version") if isinstance(data, dict) else None})
        elif rel.endswith(".claude-plugin/marketplace.json"):
            marketplace = {"file": rel}
        elif base.endswith(".md") and len(parts) >= 2 and parts[-2] in ("agents", "commands"):
            target = agents if parts[-2] == "agents" else commands
            if len(target) < 400:
                item = _component(root, rel)
                if item["error"]:
                    refused = item["error"].startswith("refused:")
                    findings.append(finding("SR-ST-006" if refused else "SR-ST-008", rel, 1,
                                            item["error"], kind="input" if refused else None))
                target.append(item)
    readmes = [rel for rel in paths if os.path.basename(rel).lower().startswith("readme")
               and rel.lower().endswith((".md", ".txt", ".rst", ""))]
    root_plugin = next((p for p in plugins if p["dir"] == ""), None)
    root_skill = next((s for s in skills if s["dir"] == ""), None)
    if root_plugin:
        unit, name = "plugin", root_plugin.get("name")
    elif root_skill:
        unit, name = "skill", root_skill.get("name")
    elif len(skills) == 1 and not plugins:
        unit, name = "skill", skills[0].get("name")
    elif skills or plugins:
        unit, name = "collection", None
    else:
        unit, name = "unknown", None
        findings.append(finding("SR-ST-007", "", 0, "no SKILL.md"))
    if not name or not isinstance(name, str):
        name = os.path.basename(os.path.normpath(opts.get("display_root") or root)) or "skill"
    return {"unit": unit, "name": re.sub(r"[^A-Za-z0-9._-]", "-", name)[:80] or "skill",
            "skills": skills, "agents": agents, "commands": commands, "plugins": plugins,
            "marketplace": marketplace, "readmes": readmes, "findings": findings}
