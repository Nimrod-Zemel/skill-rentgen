"""Stage 4: the contract. What the skill says against what it does.

WHY: other scanners judge code. A founder judges a promise: "works
offline", "read-only", "nothing leaves your machine". This stage builds the
label of what was actually observed, checks each observation against what
the skill declares anywhere (capabilities file, README, SKILL.md), and
checks a closed list of promises against the code.

Rules that tests check:
1. A missing capabilities file is a label, never a finding.
2. A host counts as declared when the capabilities file lists it, the docs
   mention it, or it is a common host.
3. A promise is a red line only when the sentence is not hedged and the
   contradicting evidence comes from code or an auto-run surface.
"""
from __future__ import annotations

import os
import re

from common import finding, is_test_path, line_of, line_text, load_json, read_text, rule_file

NET_WORDS = re.compile(r"\b(?:api|https?|fetch(?:es|ing)?|download(?:s|ing)?|upload(?:s|ing)?"
                       r"|requests?|internet|online|network|web|urls?|endpoint|server|remote"
                       r"|cloud|webhook|scrap(?:e|es|ing)|crawl(?:s|ing)?|search(?:es)?)\b", re.I)
ASK_WORDS = re.compile(r"ask\s+the\s+user|AskUserQuestion|confirm\s+with\s+the\s+user"
                       r"|wait\s+for\s+(?:the\s+)?(?:user|approval|confirmation)"
                       r"|before\s+proceeding,?\s+ask|\u05e9\u05d0\u05dc\s+\u05d0\u05ea\s+\u05d4\u05de\u05e9\u05ea\u05de\u05e9", re.I)
HEBREW = re.compile("[\u0590-\u05ff]{3,}")
RAW_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LOCAL_IP = re.compile(r"^(?:127\.|0\.0\.0\.0$|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)")
STOP = {"api", "www", "mcp", "app", "com", "org", "net", "io", "dev", "co", "ai", "cdn",
        "docs", "static", "files", "data", "cloud", "service", "services", "server"}


LISTED = ("hooks", "mcp_servers", "monitors", "bin", "modules", "runtime_installs",
          "writes_outside_skill_dir", "env_reads", "subprocess", "paid_services")


def _as_list(value):
    """(items, in the expected form). A capability is declared as a list.

    WHY: this file is written by other people, and a shape nobody expected
    must never stop the scan. Any other shape is read as far as it can be:
    a string is one item, an object gives the lists it holds, and a bare
    `true` means "yes, without saying what"."""
    if value is None:
        return [], True
    if isinstance(value, list):
        return [item for item in value if isinstance(item, (str, dict))][:200], all(
            isinstance(item, (str, dict)) for item in value)
    if isinstance(value, str):
        return ([value] if value.strip() else []), False
    if isinstance(value, dict):
        items = []
        for inner in value.values():
            if isinstance(inner, list):
                items += [item for item in inner if isinstance(item, (str, dict))]
        if not items and value.get("value") not in (None, False, "", 0, [], {}):
            items = [str(value.get("note") or "yes")]
        return items[:200], False
    if value is True:
        return ["yes"], False
    return [], False


def _manifest(root, intake, findings):
    declared = {"present": False, "network": set(), "raw": {}}
    for entry in intake["files"]:
        if os.path.basename(entry["p"]) != "skill-capabilities.json" or is_test_path(entry["p"]):
            continue
        try:
            data = load_json(os.path.join(root, entry["p"]))
            if not isinstance(data, dict):
                raise ValueError("not an object")
        except (ValueError, OSError, RecursionError):
            findings.append(finding("SR-DF-012", entry["p"], 1, "not valid"))
            declared["invalid"] = True
            continue
        declared["present"] = True
        odd = []
        network = data.get("network")
        if isinstance(network, dict):       # an object: take the lists whose name speaks of hosts
            odd.append("network")
            network = [host for key, inner in network.items() if isinstance(inner, list)
                       and "host" in str(key).lower() for host in inner]
        hosts, plain = _as_list(network)
        if not plain and "network" not in odd:
            odd.append("network")
        for item in hosts:
            host = item.get("host") if isinstance(item, dict) else item
            if isinstance(host, str) and host.strip():
                declared["network"].add(host.strip().lower())
        for key in LISTED:
            items, plain = _as_list(data.get(key))
            if not plain and data.get(key) is not False:
                odd.append(key)
            if items:
                declared["raw"][key] = items
        if odd:
            # Read as far as it could be, and said: the next tool may not be as forgiving.
            findings.append(finding("SR-DF-012", entry["p"], 1, ", ".join(odd[:6]), sub="shape"))
    return declared


def _docs(root, intake, structure):
    texts, total = {}, 0
    for entry in intake["files"]:
        rel = entry["p"]
        if entry["kind"] != "doc" or is_test_path(rel) or total > 3000000:
            continue
        try:
            text, _ = read_text(os.path.join(root, rel), 400000)
        except OSError:
            continue
        texts[rel] = text
        total += len(text)
    return texts


def _host_declared(host, declared, docs_low, name_words, known, via=""):
    if any(host == h or host.endswith("." + h) for h in declared["network"]):
        return "capabilities"
    if via == "mcp":
        brand = host.split(".")[-2] if host.count(".") else host
        for word in name_words:
            if len(word) >= 4 and (brand.startswith(word) or word.startswith(brand)):
                return "name"
    if via != "placeholder" and any(host == h or host.endswith("." + h)
                                    for h in known["common_hosts"]):
        return "common"
    labels = host.split(".")
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    if host in docs_low or domain in docs_low:
        return "docs"
    for label in labels[:-1]:
        if label in STOP or len(label) < 4 or label in name_words:
            continue
        if re.search(r"\b%s\b" % re.escape(label), docs_low):
            return "docs"
    return None


def _claims(root, structure, docs, observations, findings):
    spec = rule_file("claims.json")
    known = rule_file("known.json")
    hedges = re.compile(spec["hedges"], re.I)
    telemetry = set(known["telemetry_hosts"])
    promises = []
    scopes = []
    for skill in structure.get("skills", []):
        if skill["file"] in docs and not is_test_path(skill["file"]):
            scopes.append((skill["dir"], [skill["file"]]))
    root_docs = [rel for rel in structure.get("readmes", []) if "/" not in rel and rel in docs]
    many = len(structure.get("skills", [])) > 1
    if root_docs:
        scopes.append(("", root_docs))
    live = [o for o in observations if not o.get("in_tests") and o["source"] in ("code", "auto")]
    seen = set()
    for folder, files in scopes:
        prefix = folder + "/" if folder else ""
        local = [o for o in live if o["file"].startswith(prefix)]
        for rel in files:
            text = docs[rel]
            for claim in spec["claims"]:
                match = None
                for pattern in claim["re"]:
                    match = re.search(pattern, text, re.I | re.M)
                    if match:
                        break
                if not match or (claim["id"], rel) in seen:
                    continue
                before = text[text.rfind("\n", 0, match.start()) + 1:match.start()]
                if before.count("\"") % 2 == 1 or before.count("`") % 2 == 1 or (
                        before.count("\u201c") > before.count("\u201d")):
                    continue  # a quotation of someone else's promise, not this skill's own
                seen.add((claim["id"], rel))
                sentence = line_text(text, match.start())
                hedged = bool(hedges.search(sentence))
                strong, weak = None, None
                for obs in local:
                    kind, hard = obs["kind"], obs["confidence"] == "high"
                    host = obs.get("value", "")
                    if host in ("localhost", "127.0.0.1"):
                        continue
                    target = claim["contradicts"]
                    hit = soft = False
                    if target == "network":
                        hit = kind in ("network", "remote_exec") and (hard or bool(host))
                        hit = hit or (kind == "network_dyn" and hard)
                        soft = kind in ("network_dyn", "install")
                    elif target == "send":
                        hit = kind in ("network", "network_dyn") and bool(obs.get("send")) and hard
                        soft = kind in ("network", "network_dyn")
                    elif target == "collect":
                        hit = kind == "network" and any(
                            host == t or host.endswith("." + t) for t in telemetry)
                    elif target == "write":
                        hit = kind in ("write_out", "settings_write", "otherskill_write") or (
                            kind == "write" and obs.get("op") == "d")
                        soft = kind == "write"
                    elif target == "install":
                        soft = kind in ("install", "remote_exec")
                    if hit and (strong is None or (not strong.get("value") and host)):
                        strong = obs
                    if soft and weak is None:
                        weak = obs
                line = line_of(text, match.start())
                entry = {"claim": claim["id"], "text": sentence.strip()[:160], "file": rel,
                         "line": line, "status": "kept"}
                evidence = strong or weak
                if evidence:
                    entry["evidence"] = "%s:%d" % (evidence["file"], evidence["line"])
                    entry["evidence_value"] = evidence.get("value", "")
                table_row = sentence.lstrip().startswith("|")
                partial = (many and not folder) or table_row
                if strong and claim["red_line"] and not hedged and not partial:
                    entry["status"] = "contradicted"
                    findings.append(finding("SR-RL-08", rel, line, sentence, strong["confidence"],
                                            claim=claim["id"], evidence=entry["evidence"],
                                            evidence_value=strong.get("value", "")))
                elif evidence:
                    entry["status"] = "softened"
                    findings.append(finding("SR-CL-001", rel, line, sentence, "low",
                                            claim=claim["id"], evidence=entry["evidence"]))
                promises.append(entry)
    return promises


def run(root, work, opts):
    intake = load_json(os.path.join(work, "intake.json"))
    structure = load_json(os.path.join(work, "structure.json"))
    surfaces = load_json(os.path.join(work, "surfaces.json"))
    known = rule_file("known.json")
    findings = []
    observations = surfaces.get("observations", [])
    auto = [s for s in surfaces.get("surfaces", [])]
    declared = _manifest(root, intake, findings)
    docs = _docs(root, intake, structure)
    docs_low = "\n".join(docs.values()).lower()
    name_words = {(structure.get("name") or "").lower()}
    live = [o for o in observations if not o.get("in_tests")]
    code = [o for o in live if o["source"] in ("code", "auto")]

    network, seen_hosts = [], {}
    for obs in code:
        if obs["kind"] != "network" or not obs["value"]:
            continue
        host = obs["value"]
        if host in seen_hosts:
            seen_hosts[host]["send"] = seen_hosts[host]["send"] or bool(obs.get("send"))
            continue
        words = set(name_words)
        if obs.get("via") == "mcp":
            words.add(os.path.basename(os.path.dirname(obs["file"])).lower())
        via = "placeholder" if obs.get("placeholder") else obs.get("via", "")
        how = _host_declared(host, declared, docs_low, words, known, via)
        item = {"host": host, "declared": bool(how), "declared_by": how,
                "evidence": "%s:%d" % (obs["file"], obs["line"]),
                "confidence": obs["confidence"], "send": bool(obs.get("send"))}
        seen_hosts[host] = item
        network.append(item)
        if not how and len([n for n in network if not n["declared"]]) <= 5:
            findings.append(finding("SR-DF-004", obs["file"], obs["line"], host,
                                    obs["confidence"], host=host))
    # Servers the code names in a string and that no call was tied to.
    in_code = []
    for obs in code:
        host = obs["value"]
        if obs["kind"] != "code_host" or host in seen_hosts or any(n["host"] == host for n in in_code):
            continue
        how = _host_declared(host, declared, docs_low, set(name_words), known)
        in_code.append({"host": host, "declared": bool(how), "declared_by": how,
                      "evidence": "%s:%d" % (obs["file"], obs["line"])})
    in_code.sort(key=lambda item: item["declared"])
    dynamic = [o for o in code if o["kind"] == "network_dyn"]
    seen_dyn = [o for o in dynamic if not o.get("guess")]
    if seen_dyn:
        first = seen_dyn[0]
        talks = bool(NET_WORDS.search(docs_low)) or declared["present"]
        findings.append(finding("SR-DF-011" if talks else "SR-DF-001", first["file"],
                                first["line"], "", first["confidence"],
                                named=[n["host"] for n in in_code if not n["declared"]][:5]))

    kinds = {}
    for surface in auto:
        kinds.setdefault(surface["kind"], []).append(surface)
    words = {"hook": r"\bhooks?\b", "mcp": r"\bmcp\b", "monitor": r"\bmonitors?\b",
             "module": r"\bmods?\b|\bmodules?\b|\bpanes?\b|inside\s+claude\s+code|in-process",
             "bin": r"\bbin/|\bcli\b|\bcommand[- ]line\b|\bbinar(?:y|ies)\b", "lsp": r"\blsp\b|language server",
             "package": r"\bnpm\b|\binstall\b"}
    for kind, items in kinds.items():
        if kind == "module":
            if not declared["raw"].get("modules") and not re.search(words["module"], docs_low):
                findings.append(finding("SR-RL-15", items[0]["file"], 1, items[0].get("command", "")))
            continue
        said = declared["raw"].get({"hook": "hooks", "mcp": "mcp_servers", "monitor": "monitors",
                                    "bin": "bin"}.get(kind, "")) or (
            kind in words and re.search(words[kind], docs_low))
        if not said and kind in ("hook", "mcp", "monitor", "bin"):
            findings.append(finding("SR-DF-002", items[0]["file"], 1, kind, sub=kind,
                                    count=len(items)))

    # Tunnels, paste sites and throwaway collectors, wherever the skill points at them.
    exfil = known.get("exfil_hosts", [])
    instruction_docs = {s["file"] for s in structure.get("skills", [])}
    instruction_docs |= {a["file"] for g in ("agents", "commands") for a in structure.get(g, [])}
    flagged = set()
    for obs in live:
        if obs["kind"] not in ("network", "config_url", "mention", "remote_exec", "registry",
                               "code_host"):
            continue
        if obs["kind"] == "mention" and obs["file"] not in instruction_docs:
            continue
        host = obs.get("value") or ""
        if RAW_IP.match(host) and not LOCAL_IP.match(host) and ("ip", host) not in flagged:
            flagged.add(("ip", host))
            if sum(1 for item in flagged if isinstance(item, tuple)) <= 3:
                findings.append(finding("SR-DF-019", obs["file"], obs["line"], host,
                                        obs["confidence"], host=host))
        if host in flagged or not any(host == h or host.endswith("." + h) for h in exfil):
            continue
        flagged.add(host)
        if sum(1 for item in flagged if isinstance(item, str)) <= 3:
            findings.append(finding("SR-DF-014", obs["file"], obs["line"], host,
                                    obs["confidence"], host=host))
    registries = []
    for obs in live:
        if obs["kind"] == "registry" and obs["value"] not in registries:
            registries.append(obs["value"])
            if len(registries) <= 3:
                findings.append(finding("SR-DF-016", obs["file"], obs["line"], obs["value"],
                                        obs["confidence"], host=obs["value"]))
    env_all = [o for o in code if o["kind"] == "env_all"]
    if env_all:
        leaving = [o for o in env_all if o.get("sink") in ("net", "print")]
        first = (leaving or env_all)[0]
        findings.append(finding("SR-DF-018" if leaving else "SR-DF-015", first["file"],
                                first["line"], "", first["confidence"], sink=first.get("sink")))

    outside = []
    for obs in code:
        if obs["kind"] == "write_out" and obs["value"] not in outside:
            outside.append(obs["value"])
            base = obs["value"].rstrip("/").rsplit("/", 1)[-1].lower()
            said = declared["raw"].get("writes_outside_skill_dir") or (base and base in docs_low)
            if not said and len(outside) <= 3:
                findings.append(finding("SR-DF-003", obs["file"], obs["line"], obs["value"]))
    installs = [o for o in code if o["kind"] == "install"]
    by_hand = [o for o in installs if o["source"] != "auto"]
    tools = {o["value"].split(" ")[0].rsplit("/", 1)[-1].lower() for o in by_hand if o["value"]}
    named = bool(tools) and all(re.search(r"\b%s\b" % re.escape(t), docs_low) for t in tools)
    if by_hand and not named and not declared["raw"].get("runtime_installs") and not re.search(
            r"\b(?:pip3?|npm|npx|uvx?|bunx?|pnpm|yarn|brew|apt(?:-get)?|cargo|gem)\s+(?:install|add|i)\b"
            r"|\binstall(?:s|ed|ing)?\s+(?:the\s+)?(?:dependenc|packages?|requirements)", docs_low):
        findings.append(finding("SR-DF-005", by_hand[0]["file"], by_hand[0]["line"],
                                by_hand[0]["value"], by_hand[0]["confidence"]))
    env_names = sorted({o["value"] for o in code if o["kind"] == "env" and o["value"]})
    secret_re = re.compile(known["secret_env_re"])
    secret_names = [n for n in env_names if secret_re.search(n)]
    if secret_names:
        first = next(o for o in code if o["kind"] == "env" and o["value"] == secret_names[0])
        findings.append(finding("SR-DF-008", first["file"], first["line"],
                                ", ".join(secret_names[:6]), names=secret_names[:12]))
    paid = [n for n in env_names if n in known["paid_env"] and n.lower() not in docs_low]
    if paid and not declared["raw"].get("paid_services"):
        first = next(o for o in code if o["kind"] == "env" and o["value"] == paid[0])
        findings.append(finding("SR-RL-11", first["file"], first["line"], ", ".join(paid[:4])))
    dotenv = [o for o in code if o["kind"] == "dotenv"]
    if dotenv:
        findings.append(finding("SR-DF-009", dotenv[0]["file"], dotenv[0]["line"], ".env"))
    cred_refs = [o for o in live if o["kind"] == "cred_ref"]
    if cred_refs and not any(o["kind"] == "cred_read" for o in live):
        findings.append(finding("SR-DF-010", cred_refs[0]["file"], cred_refs[0]["line"], "",
                                cred_refs[0]["confidence"]))
    acting = [o for o in live if o["kind"] == "connector" and o.get("mode") == "write"]
    connectors = sorted({o["value"] for o in acting})
    if connectors:
        first = acting[0]
        findings.append(finding("SR-DF-013", first["file"], first["line"],
                                ", ".join(connectors[:6]), "low", names=connectors[:10]))
    if declared["network"] and not network and not dynamic and not any(
            n["declared_by"] == "capabilities" for n in in_code):
        findings.append(finding("SR-DF-006", "", 0, ", ".join(sorted(declared["network"]))[:100]))

    promises = _claims(root, structure, docs, observations, findings)

    timeline = {}
    for surface in auto:
        slot = surface.get("timing") or "on_use"
        detail = surface.get("command") or surface.get("url") or surface["file"]
        timeline.setdefault(slot, [])
        if len(timeline[slot]) < 8:
            timeline[slot].append({"what": surface["kind"], "event": surface.get("event", ""),
                                   "detail": detail[:160], "file": surface["file"]})
    langs = {}
    for entry in intake["files"]:
        if entry["kind"] == "code" and not is_test_path(entry["p"]):
            langs[entry["lang"]] = langs.get(entry["lang"], 0) + 1
    prose = []
    mentions = [o for o in live if o["kind"] == "mention"
                and os.path.basename(o["file"]) == "SKILL.md"]
    for obs in mentions[:8]:
        prose.append({"kind": "network", "value": obs["value"],
                      "evidence": "%s:%d" % (obs["file"], obs["line"])})
    for obs in [o for o in live if o["source"] == "prose" and o["kind"] in (
            "install", "connector", "remote_exec")][:8]:
        prose.append({"kind": obs["kind"], "value": obs["value"],
                      "evidence": "%s:%d" % (obs["file"], obs["line"])})
    config_hosts = []
    for obs in live:
        if obs["kind"] == "config_url" and obs["value"] not in config_hosts:
            config_hosts.append(obs["value"])
    skill_texts = [docs.get(s["file"], "") for s in structure.get("skills", [])]
    label = {
        "network": network[:12], "network_dynamic": bool(dynamic),
        "from_code": in_code[:12], "from_code_total": len(in_code),
        "writes_outside_skill_dir": outside[:8],
        "declared_writes": [str(item)[:120] for item in
                            (declared["raw"].get("writes_outside_skill_dir") or [])[:4]],
        "writes_files": any(o["kind"] == "write" for o in code),
        "subprocess": sorted({o["value"] or "?" for o in code if o["kind"] == "exec"})[:12],
        "env_reads": env_names[:16], "secrets_read": secret_names[:12],
        "runtime_installs": sorted({o["value"] for o in installs})[:8],
        "exec_surfaces": [{k: s.get(k) for k in ("kind", "event", "timing", "file", "command",
                                                 "url") if s.get(k)} for s in auto[:24]],
        "from_prose": prose, "from_config": config_hosts[:12], "registries": registries[:4],
        "reads_all_env": bool(env_all),
        "reads_stdin": any(o["kind"] == "stdin" for o in code),
        "dotenv": bool(dotenv), "code_files": langs,
        "manifest": "present" if declared["present"] else (
            "invalid" if declared.get("invalid") else "absent"),
        "timeline": timeline, "analysis": surfaces.get("analysis", {}),
    }
    tokens = [s.get("tokens", 0) for s in structure.get("skills", [])]
    badges = {
        "hebrew": any(HEBREW.search(t) for t in skill_texts) or any(
            e["p"].endswith("SKILL.he.md") for e in intake["files"]),
        "portable": bool(structure.get("skills")) and not any(
            s["kind"] in ("hook", "mcp", "monitor", "module") for s in auto),
        "asks_before_acting": any(ASK_WORDS.search(t) for t in skill_texts),
        "context_cost_tokens": max(tokens) if tokens else 0,
    }
    stated = " ".join(str(item).lower() for item in
                      (declared["raw"].get("writes_outside_skill_dir") or []))
    covers = {"otherskill_write": ".claude/skills" in stated or ".agents/skills" in stated,
              "settings_write": ".claude/settings" in stated}
    reclassify = [{"rule_id": "SR-SF-007", "file": item.get("file"), "line": item.get("line"),
                   "to": "SR-DF-020"} for item in surfaces.get("findings", [])
                  if item.get("rule_id") == "SR-SF-007" and covers.get(item.get("sub"))]
    return {"label": label, "promises": promises, "badges": badges, "findings": findings,
            "reclassify": reclassify}
