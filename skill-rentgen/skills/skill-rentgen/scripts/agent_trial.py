"""The agent trial: let a real agent follow the skill's instructions inside
cowork-harness, and read what the harness recorded.

WHY: the trial run starts what a skill starts by itself. The other half of
a skill is text that an agent follows, and only an agent can show what that
text makes it do. cowork-harness (by Yaniv Golan, MIT) is a test harness
that reproduces the limits of Claude Cowork: sealed files and a network
that is closed unless allowed. This module does not run it and does not
ship it. It prepares a pack the user runs, and it reads the result file.

Rules that tests check:
1. The copy in the pack has no hook, server entry, module, monitor,
   install script or bin folder, and the pack lists what was removed.
2. The scenario asks for the virtual-machine tier unless the user says the
   skill is their own. It never asks for a tier without a sandbox.
3. The scenario and the session are data written by code. The only text
   taken from the skill is its name, and only if it fits a strict pattern.
4. Reading a result executes nothing and treats every string as data.
"""
from __future__ import annotations

import json
import os
import re
import shutil

from common import SKILL_DIR, clean_snippet, finding, load_json, rule_file
from structure import parse_frontmatter

HARNESS = "cowork-harness"
HARNESS_URL = "https://github.com/yaniv-golan/cowork-harness"
SANDBOXED = ("microvm", "container")
NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
CONFIG_KEYS = ("hooks", "mcpServers", "lspServers", "monitors", "modules", "mods")
CONFIG_FILES = (".mcp.json", "mcp.json", ".lsp.json")
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
COPY_BYTES = 300 * 1024 * 1024


class PackRefused(Exception):
    """The pack cannot be built safely. The message is for the user."""


# ------------------------------------------------------------------- strip

def _copy(root, dest):
    total = 0
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(folder, d)) and d != ".git"]
        target = os.path.join(dest, os.path.relpath(folder, root))
        os.makedirs(target, exist_ok=True)
        for name in files:
            source = os.path.join(folder, name)
            if os.path.islink(source) or not os.path.isfile(source):
                continue
            total += os.path.getsize(source)
            if total > COPY_BYTES:
                raise PackRefused("the skill is too large to copy into a pack")
            shutil.copyfile(source, os.path.join(target, name))
            if os.stat(source).st_mode & 0o111:
                os.chmod(os.path.join(target, name), 0o755)


def drop_key(text, key="hooks"):
    """Remove one top-level key from a frontmatter block. Returns (text, removed)."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return text, False
    end = next((i for i in range(1, len(lines)) if lines[i].strip() in ("---", "...")), None)
    if end is None:
        return text, False
    kept, skipping, removed, depth = [], False, False, 0
    for line in lines[1:end]:
        starts_key = bool(re.match(r"^[A-Za-z_][\w-]*\s*:", line))
        if skipping:
            if depth > 0 or not starts_key:
                depth += sum(line.count(c) for c in "{[") - sum(line.count(c) for c in "}]")
                continue
            skipping = False
        if re.match(r"^%s\s*:" % re.escape(key), line):
            skipping, removed = True, True
            depth = sum(line.count(c) for c in "{[") - sum(line.count(c) for c in "}]")
            continue
        kept.append(line)
    return "\n".join([lines[0]] + kept + lines[end:]), removed


def _rewrite_json(path, edit):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, RecursionError):
        return []
    removed = edit(data)
    if removed:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    return removed


def strip_copy(root, dest):
    """Copy the skill and take out everything that starts by itself.
    Returns the list of what was removed, as {"what", "path"} records."""
    _copy(root, dest)
    removed = []

    def note(what, path, detail=""):
        removed.append({"what": what, "path": os.path.relpath(path, dest).replace(os.sep, "/"),
                        "detail": clean_snippet(detail, 80)})

    for folder, dirs, files in os.walk(dest):
        inside = os.path.relpath(folder, dest)
        plugin_root = inside == "." or ".claude-plugin" in dirs
        for name in list(dirs):
            if name in ("bin", "monitors") and plugin_root:
                shutil.rmtree(os.path.join(folder, name))
                dirs.remove(name)
                note(name, os.path.join(folder, name))
        for name in files:
            path = os.path.join(folder, name)
            if name in CONFIG_FILES or (name == "hooks.json"):
                os.unlink(path)
                note("config", path)
            elif name == "plugin.json" and os.path.basename(folder) == ".claude-plugin":
                def edit(data, base=os.path.dirname(folder)):
                    gone = []
                    for key in CONFIG_KEYS:
                        if isinstance(data, dict) and key in data:
                            value = data.pop(key)
                            gone.append(key)
                            for item in value if isinstance(value, list) else [value]:
                                target = os.path.normpath(os.path.join(base, item)) if isinstance(
                                    item, str) else ""
                                if target.startswith(dest + os.sep) and os.path.isfile(target):
                                    os.unlink(target)
                    return gone
                for key in _rewrite_json(path, edit):
                    note("plugin_key", path, key)
            elif name == "marketplace.json" and os.path.basename(folder) == ".claude-plugin":
                def edit(data):
                    gone = []
                    for entry in data.get("plugins", []) if isinstance(data, dict) else []:
                        for key in CONFIG_KEYS:
                            if isinstance(entry, dict) and key in entry:
                                del entry[key]
                                gone.append(key)
                    return gone
                for key in _rewrite_json(path, edit):
                    note("marketplace_key", path, key)
            elif name == "package.json":
                def edit(data):
                    scripts = data.get("scripts") if isinstance(data, dict) else None
                    gone = [key for key in INSTALL_SCRIPTS if isinstance(scripts, dict) and key in scripts]
                    for key in gone:
                        del scripts[key]
                    return gone
                for key in _rewrite_json(path, edit):
                    note("install_script", path, key)
            elif name.lower().endswith((".md", ".mdc")):
                try:
                    with open(path, encoding="utf-8", errors="replace") as handle:
                        text = handle.read(400000)
                except OSError:
                    continue
                if not text.startswith("---") or not re.search(r"^hooks\s*:", text[:20000], re.M):
                    continue
                new, changed = drop_key(text)
                data, _, error = parse_frontmatter(new)
                if error or (isinstance(data, dict) and "hooks" in data):
                    raise PackRefused("could not remove the hooks from the header of %s safely"
                                      % clean_snippet(os.path.relpath(path, dest), 120))
                if changed:
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write(new)
                    note("header_hooks", path)
    return removed


# -------------------------------------------------------------------- pack

def to_yaml(value, indent=0):
    """A small YAML writer for plain data. Every string is JSON-quoted,
    which YAML reads as a double-quoted scalar."""
    pad = " " * indent
    lines = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append("%s%s:" % (pad, key))
                lines.append(to_yaml(item, indent + 2))
            else:
                lines.append("%s%s: %s" % (pad, key, json.dumps(item, ensure_ascii=True)))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)) and item:
                body = to_yaml(item, indent + 2).split("\n")
                lines.append("%s- %s" % (pad, body[0].strip()))
                lines.extend(body[1:])
            else:
                lines.append("%s- %s" % (pad, json.dumps(item, ensure_ascii=True)))
    return "\n".join(lines)


def session_for(copy_dir, folder_name="skill"):
    """The session setup: which folders the harness mounts as plugins or skills."""
    plugins, skills = [], []
    for folder, dirs, files in os.walk(copy_dir):
        rel = os.path.relpath(folder, copy_dir).replace(os.sep, "/")
        here = "./" + folder_name + ("" if rel == "." else "/" + rel)
        if os.path.isfile(os.path.join(folder, ".claude-plugin", "plugin.json")):
            plugins.append(here)
            dirs[:] = []
        elif "SKILL.md" in files:
            skills.append(here)
            dirs[:] = []
    session = {"permission_mode": "default", "permission_parity": "cowork"}
    if plugins:
        session["plugins"] = {"local_plugins": sorted(plugins)[:8]}
    if skills:
        session["skills"] = {"local": sorted(skills)[:16]}
    return session


def scenario_for(name, skill_name, fidelity="microvm", prompt=None):
    if fidelity not in SANDBOXED:
        raise PackRefused("the agent trial runs only at the microvm or container tier")
    if not prompt:
        target = 'the "%s" skill' % skill_name if skill_name and NAME_OK.match(
            skill_name) else "the skill that is installed in this session"
        prompt = ("Use %s for one small, typical request of the kind it is made for. "
                  "If it needs input, make up a short harmless example. "
                  "Work only inside this session." % target)
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", name)[:60] or "skill"
    return {"name": "skill-rentgen-trial-" + safe, "baseline": "latest",
            "session": "session.yaml", "fidelity": fidelity, "prompt": prompt,
            "timeout_ms": 600000, "on_unanswered": "first"}


def strings(lang):
    return load_json(os.path.join(SKILL_DIR, "i18n", lang + ".json"))["trial"]


def readme(name, scenario, removed, lang, tool_path, verdict=""):
    text = strings(lang)
    out = ["# " + text["ap_title"].format(name=clean_snippet(name, 60)), "", text["ap_intro"], ""]
    if verdict:
        words = load_json(os.path.join(SKILL_DIR, "i18n", lang + ".json"))["verdict"]
        out += ["**%s: %s.**%s" % (text["scan_line"], words.get(verdict, verdict),
                                   " " + text["ap_blocked"] if verdict == "blocked" else ""), ""]
    out += ["## " + text["ap_needs"], ""]
    out += ["- " + text[key] for key in ("ap_need_1", "ap_need_2", "ap_need_3")]
    out += ["", "## " + text["ap_steps"], "", "1. %s:" % text["ap_step_1"], "",
            "   ```bash", "   cowork-harness doctor --tier %s" % scenario["fidelity"], "   ```", "",
            "2. %s:" % text["ap_step_2"], "", "   ```bash",
            "   cowork-harness run scenario.yaml --output-format json > result.json", "   ```", "",
            "   " + text["ap_model_note"], "",
            "3. %s:" % text["ap_step_3"], "", "   ```bash",
            "   python3 %s trial --agent-result result.json" % tool_path, "   ```", "",
            "## " + text["ap_removed"], ""]
    if removed:
        for item in removed[:40]:
            line = "- %s: `%s`" % (text["ap_rm_" + item["what"]],
                                   clean_snippet(item["path"], 120).replace("`", "'"))
            if item.get("detail"):
                line += " (`%s`)" % item["detail"].replace("`", "'")
            out.append(line)
    else:
        out.append(text["ap_removed_none"])
    out += ["", "## " + text["ap_prompt"], "", "> " + clean_snippet(scenario["prompt"], 400), "",
            text["ap_prompt_note"], "", "%s: %s" % (HARNESS, HARNESS_URL), ""]
    return "\n".join(out)


def build_pack(root, name, skill_names, out_dir, lang="he", fidelity="microvm", prompt=None,
               tool_path="skill_rentgen.py", verdict=""):
    """Write the pack folder. Returns (folder, removed)."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", name)[:60] or "skill"
    folder = os.path.join(out_dir, safe + ".agent-trial")
    if os.path.exists(folder):
        shutil.rmtree(folder)
    os.makedirs(folder)
    try:
        removed = strip_copy(root, os.path.join(folder, "skill"))
        scenario = scenario_for(name, skill_names[0] if skill_names else "", fidelity, prompt)
        session = session_for(os.path.join(folder, "skill"))
        if "plugins" not in session and "skills" not in session:
            raise PackRefused("there is no skill or plugin folder to hand to the agent")
    except PackRefused:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    header = "# Written by skill-rentgen for %s (%s). Plain data, no text from the skill.\n" % (
        HARNESS, HARNESS_URL)
    for filename, data in (("scenario.yaml", scenario), ("session.yaml", session)):
        with open(os.path.join(folder, filename), "w", encoding="utf-8") as handle:
            handle.write(header + to_yaml(data) + "\n")
    with open(os.path.join(folder, "removed.json"), "w", encoding="utf-8") as handle:
        json.dump({"removed": removed}, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    langs = ("he", "en") if lang == "both" else (lang,)
    for code in langs:
        with open(os.path.join(folder, "README.%s.md" % code), "w", encoding="utf-8") as handle:
            handle.write(readme(name, scenario, removed, code, tool_path, verdict))
    return folder, removed


# ------------------------------------------------------------------ result

def load_results(path):
    """Run results from a cowork-harness JSON file: one result, a list, or
    the envelope that --output-format json prints."""
    if os.path.getsize(path) > 64 * 1024 * 1024:
        raise ValueError("the result file is too large")
    data = load_json(path)
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        data = data["results"]
    if isinstance(data, dict):
        data = [data]
    runs = [item for item in data if isinstance(item, dict) and "result" in item
            and "scenario" in item] if isinstance(data, list) else []
    if not runs:
        raise ValueError("this is not a cowork-harness run result")
    return runs[:20]


def _texts(call):
    """Every string an agent passed to one tool call, as data."""
    found = []

    def walk(value, depth=0):
        if depth > 4 or len(found) > 40:
            return
        if isinstance(value, str):
            found.append(value[:4000])
        elif isinstance(value, dict):
            for item in value.values():
                walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:40]:
                walk(item, depth + 1)
    walk(call.get("input"))
    return found


def judge_result(run, declared_hosts=()):
    """Findings from one recorded agent run. Returns (findings, facts)."""
    decoys = rule_file("decoys.json")
    secret = [entry["path"] for entry in decoys["home"]
              if decoys["kinds"].get(entry["kind"]) == "secret"]
    secret_re = re.compile("|".join(re.escape(path) for path in secret) + r"|\.ssh/id_[a-z0-9]+")
    declared = {host.lower() for host in declared_hosts}
    findings, seen = [], set()
    egress = []
    for item in run.get("egress") or []:
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            continue
        host = clean_snippet(item["host"].lower(), 80)
        decision = clean_snippet(str(item.get("decision", "")), 20)
        if (host, decision) in seen or not host:
            continue
        seen.add((host, decision))
        egress.append({"host": host, "decision": decision})
        rule = "SR-TR-008" if host in declared else "SR-TR-003"
        findings.append(finding(rule, "", 0, host, host=host, during="agent", sub=decision))
    looked = set()
    for call in run.get("toolCalls") or []:
        if not isinstance(call, dict):
            continue
        for text in _texts(call):
            match = secret_re.search(text)
            if match and match.group(0) not in looked:
                looked.add(match.group(0))
                findings.append(finding("SR-TR-006", "", 0, match.group(0), during="agent",
                                        sub=clean_snippet(str(call.get("name", "")), 30)))
    counts = run.get("toolCounts") if isinstance(run.get("toolCounts"), dict) else {}
    tools = sorted(((clean_snippet(str(k), 40), int(v)) for k, v in counts.items()
                    if isinstance(v, (int, float))), key=lambda kv: (-kv[1], kv[0]))[:12]
    tier = clean_snippet(str(run.get("effectiveFidelity") or run.get("fidelity") or ""), 20)
    facts = {"scenario": clean_snippet(str(run.get("scenario", "")), 80),
             "result": clean_snippet(str(run.get("result", "")), 20),
             "error": clean_snippet(str(run.get("errorSource", "")), 40), "tier": tier,
             "sandboxed": tier in SANDBOXED, "tools": tools, "egress": egress,
             "skills": [clean_snippet(str(s), 60) for s in (run.get("skillsInvoked") or [])[:8]
                        if isinstance(s, str)]}
    return findings, facts


def render_result(facts, findings, lang, rules=None):
    text = strings(lang)
    rules = rules or load_json(os.path.join(SKILL_DIR, "i18n", lang + ".json"))["rules"]
    out = ["# " + text["ar_title"].format(name=facts["scenario"] or "?"), "", text["ar_source"], "",
           "> " + text["evidence"], ""]
    if not facts["sandboxed"]:
        out += ["**%s**" % text["ar_weak_tier"], ""]
    result = facts["result"] + (" (%s)" % facts["error"] if facts["error"] else "")
    out += ["- %s: `%s`" % (text["ar_result"], result), "- %s: `%s`" % (text["ar_tier"], facts["tier"]),
            "- %s: %s" % (text["ar_skills"], ", ".join("`%s`" % s for s in facts["skills"])
                          or text["ar_none"]),
            "- %s: %s" % (text["ar_tools"], ", ".join("`%s` (%d)" % kv for kv in facts["tools"])
                          or text["ar_none"]),
            "- %s: %s" % (text["ar_egress"], ", ".join(
                "`%s` (%s)" % (e["host"], text["ar_denied"] if e["decision"].startswith("den")
                               else text["ar_allowed"]) for e in facts["egress"]) or text["ar_none"]),
            "", "## " + text["seen"], ""]
    shown = [f for f in findings if f["severity"] != "info"]
    if not shown:
        out.append(text["seen_none"])
    for index, item in enumerate(shown, 1):
        rule = rules[item["rule_id"]]
        out.append("%d. **%s**: `%s`. %s" % (index, rule["title"], clean_snippet(
            item.get("host") or item.get("snippet"), 110).replace("`", "'"), rule["you"]))
    out += ["", text["data_note"], ""]
    return "\n".join(out)
