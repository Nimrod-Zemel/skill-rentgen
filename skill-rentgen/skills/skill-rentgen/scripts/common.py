"""Shared helpers for the SkillRentgen stages.

WHY: every stage reads untrusted files and must behave the same way when a
file is huge, binary, or built to break a parser. Keeping the limits, the
snippet cleaner and the finding shape in one place means a stage cannot
quietly use a looser rule than its neighbours.

Rules that tests check:
1. Standard library only.
2. A snippet taken from a scanned skill is never longer than 120 characters
   and never carries control, bidi or zero-width characters.
3. A finding always names a rule id that exists in the rules files.
"""
from __future__ import annotations

import json
import os
import re
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
TOOL_NAME = "skill-rentgen"
TOOL_VERSION = "0.1.0"

LIMITS = {
    "soft_files": 20000,
    "hard_files": 200000,
    "soft_bytes": 200 * 1024 * 1024,
    "hard_bytes": 2 * 1024 ** 3,
    "hard_file_bytes": 500 * 1024 * 1024,
    "max_depth": 40,
    "analyze_bytes": 1024 * 1024,
    "max_line": 20000,
    "stage_timeout": 120,
    "stage_cpu": 90,
    "stage_mem": 2 * 1024 ** 3,
}

SEVERITIES = ("info", "low", "medium", "high", "red")
SEV_RANK = {name: i for i, name in enumerate(SEVERITIES)}

# The Unicode Tags block and the variation selectors supplement, written as
# decimal code points (U+E0000 to U+E01EF) so this file holds no escape that
# its own scanner reports.
TAGS_FIRST, TAGS_ASCII_LAST, SELECTORS_FIRST, TAGS_LAST = 917504, 917631, 917760, 917999
TAGS_CLASS = "[%s-%s]" % (chr(TAGS_FIRST), chr(TAGS_LAST))

_UNSAFE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u00ad\u200b-\u200f\u202a-\u202e"
    "\u2060-\u2069\ufeff\ufe00-\ufe0f]|" + TAGS_CLASS
)


def clean_snippet(text, limit=120):
    """Return a short, inert copy of text taken from the scanned skill."""
    if not text:
        return ""
    text = _UNSAFE.sub("", str(text).replace("\t", " ").replace("\r", " ").replace("\n", " "))
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:limit]


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def dump_json(obj, path):
    """Write JSON atomically: temp file in the same folder, then replace."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


_RULE_CACHE = {}


def rule_file(name):
    if name not in _RULE_CACHE:
        _RULE_CACHE[name] = load_json(os.path.join(SKILL_DIR, "rules", name))
    return _RULE_CACHE[name]


def rule_table():
    """Map rule id -> metadata from the three rules files."""
    if "_table" not in _RULE_CACHE:
        table = {}
        for name in ("red-lines.json", "warnings.json", "trial.json"):
            for rule in rule_file(name)["rules"]:
                table[rule["id"]] = rule
        _RULE_CACHE["_table"] = table
    return _RULE_CACHE["_table"]


def finding(rule_id, file="", line=0, snippet="", confidence="high", **extra):
    """Build one finding. Severity always comes from the rules files."""
    rule = rule_table().get(rule_id)
    if rule is None:
        raise KeyError("unknown rule id: %s" % rule_id)
    item = {
        "rule_id": rule_id,
        "severity": rule["severity"],
        "red_line": rule["severity"] == "red",
        "file": file,
        "line": int(line or 0),
        "snippet": clean_snippet(snippet),
        "confidence": confidence,
    }
    for key, value in extra.items():
        if value is not None:
            item[key] = value
    return item


def read_bytes(path, limit=None):
    limit = LIMITS["analyze_bytes"] if limit is None else limit
    with open(path, "rb") as handle:
        return handle.read(limit + 1)


def read_text(path, limit=None):
    """Read a text file for analysis. Returns (text, truncated)."""
    limit = LIMITS["analyze_bytes"] if limit is None else limit
    data = read_bytes(path, limit)
    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    return data.decode("utf-8", "replace"), truncated


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def line_text(text, pos):
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end]


_ADDRESS = re.compile(r"https?://[^\s)>\"'`]+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|\b[\w-]+(?:\.[\w-]+)+\b")


def no_addresses(text):
    """Blank out URLs, emails and host names, so a word inside an address
    (the "example" of a .example domain) is not read as prose."""
    return _ADDRESS.sub(" ", text)


def is_test_path(rel):
    """True for files that ship with a skill but are not part of what runs."""
    parts = rel.replace("\\", "/").lower().split("/")
    names = {"tests", "test", "__tests__", "evals", "eval", "fixtures", "testdata",
             "examples", "example", "spec", "specs", "benchmarks", ".github",
             ".devcontainer", ".circleci", ".gitlab", ".husky", ".vscode", ".idea"}
    if any(part in names for part in parts[:-1]):
        return True
    base = parts[-1]
    return base.startswith("test_") or base.endswith(("_test.py", ".test.js", ".test.ts",
                                                      ".spec.js", ".spec.ts", ".test.mjs"))


_TOKEN = re.compile(r"[\w./${}~@-]+")
_PREFIX = re.compile(r"^(?:\$\{?\w+\}?/|\./|~/|@)+")


def path_matches(text, folder, paths):
    """Paths from `paths` that `text` names. A name counts when it is the
    whole path, its tail, or a path relative to `folder`."""
    hits = set()
    if not text:
        return hits
    by_base = {}
    for rel in paths:
        by_base.setdefault(rel.rsplit("/", 1)[-1], []).append(rel)
    for token in set(_TOKEN.findall(text)):
        token = _PREFIX.sub("", token).strip("/.")
        base = token.rsplit("/", 1)[-1]
        if base not in by_base or ("." not in base and token.count("/") < 1):
            continue
        for rel in by_base[base]:
            if rel == token or (folder and rel == folder + "/" + token):
                hits.add(rel)
            elif "/" in token and (rel.endswith("/" + token) or (
                    "/" in rel and token.endswith("/" + rel))):
                # A bare file name such as SKILL.md names the file beside the
                # document, not every file of that name in the tree.
                hits.add(rel)
    return hits


def referenced_files(root, intake, structure):
    """Files that the instruction documents tell the agent to use.

    WHY: files under tests/ or examples/ are normally not part of what
    runs, so findings there are softened. A skill could hide its payload
    there and have SKILL.md run it. Anything the instructions point at is
    treated as live, wherever it sits.
    """
    paths = [entry["p"] for entry in intake.get("files", [])
             if entry["kind"] in ("code", "doc", "data")]
    docs = [item["file"] for group in ("skills", "agents", "commands")
            for item in structure.get(group, [])]
    pointed = set()
    for rel in docs[:600]:
        if is_test_path(rel) and rel not in pointed:
            continue
        try:
            text, _ = read_text(os.path.join(root, rel), 300000)
        except OSError:
            continue
        pointed |= path_matches(text, os.path.dirname(rel), paths)
    return {rel for rel in pointed if is_test_path(rel)}


def is_doc_path(rel):
    return rel.lower().endswith((".md", ".mdx", ".markdown", ".txt", ".rst", ".adoc", ".mdc"))


def progress(work, stage, rel):
    """Record the file a stage is on, so a crash can name it."""
    try:
        with open(os.path.join(work, stage + ".progress"), "w", encoding="utf-8") as handle:
            handle.write(rel)
    except OSError:
        pass


def files_of(intake, kinds=None, langs=None):
    for entry in intake.get("files", []):
        if kinds and entry["kind"] not in kinds:
            continue
        if langs and entry.get("lang") not in langs:
            continue
        yield entry
