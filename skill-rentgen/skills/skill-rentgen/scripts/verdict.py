"""Stage 7: the verdict and the report.

WHY: the report is the product. A founder reads one word, one sentence and
three lines, and decides. So the verdict is computed from findings only, by
a fixed table, and every sentence the user reads comes from the i18n files.
Nothing here is written by a model, and nothing here can turn a red line
into a green light.

Rules that tests check:
1. The verdict depends on findings only. The score never changes it.
2. "Do not install" needs a red line or a refused intake. Any number of
   high warnings stays "caution".
3. A stage that failed on the skill's own content adds SR-FAIL-CLOSED.
4. Severity is read again from the rules files; a stage cannot lower it.
5. The same input gives the same report, apart from run id and times.
"""
from __future__ import annotations

import os
import re

from common import (SEV_RANK, SKILL_DIR, TOOL_NAME, TOOL_VERSION, _UNSAFE, clean_snippet,
                    dump_json, finding, load_json, read_text, rule_file, rule_table)

STAGES = ("intake", "structure", "text_rules", "surfaces", "contract")
PENALTY = {"red": 40, "high": 15, "medium": 5, "low": 1, "info": 0}
EXIT = {"approve": 0, "approve_with_notes": 0, "caution": 1, "blocked": 2, "reject": 2}
USER = {"approve": "install", "approve_with_notes": "install", "caution": "caution",
        "blocked": "block", "reject": "block"}
TERMINAL = {"approve": "INSTALL", "approve_with_notes": "INSTALL (with notes)",
            "caution": "CAUTION", "blocked": "DO NOT INSTALL", "reject": "DO NOT INSTALL"}
SLOTS = ("install", "session_start", "every_prompt", "every_tool", "every_reply",
         "session_end", "background", "in_process", "on_command", "on_file")
PER_RULE = 5
NO_SNIPPET = {"SR-SF-009", "SR-DF-006", "SR-DF-007", "SR-IN-007", "SR-CD-001", "SR-DF-011",
              "SR-DF-001", "SR-DF-010", "SR-DF-009"}


def collect(work, run):
    """Load every stage output. Return (data, findings, failed_stages)."""
    table = rule_table()
    data, findings, failed = {}, [], []
    for stage in STAGES:
        state = run.get("stages", {}).get(stage, {"status": "missing"})
        path = os.path.join(work, stage + ".json")
        if state.get("status") == "ok":
            try:
                data[stage] = load_json(path)
            except (ValueError, OSError, RecursionError):
                state = {"status": "failed", "detail": "stage output is unreadable"}
        if stage not in data:
            failed.append({"stage": stage, "status": state.get("status", "missing"),
                           "detail": clean_snippet(state.get("detail", "")),
                           "file": clean_snippet(state.get("file", ""), 200)})
            continue
        for item in data[stage].get("findings", []):
            rule = table.get(item.get("rule_id"))
            if rule is None:
                raise KeyError("stage %s reported an unknown rule" % stage)
            item["severity"] = rule["severity"]
            item["red_line"] = rule["severity"] == "red"
            item["snippet"] = clean_snippet(item.get("snippet", ""))
            item["file"] = clean_snippet(item.get("file", ""), 240)
            item["stage"] = stage
            findings.append(item)
    # A write the skill declares is a note, not a caution. Only the contract
    # stage, which reads the declaration, can say so, and only for this rule.
    moves = {(m.get("rule_id"), m.get("file"), m.get("line")): m.get("to")
             for m in data.get("contract", {}).get("reclassify", [])}
    for item in findings:
        target = moves.get((item["rule_id"], item.get("file"), item.get("line")))
        if item.get("stage") == "surfaces" and item["rule_id"] == "SR-SF-007" \
                and target == "SR-DF-020":
            item["rule_id"] = target
            item["severity"] = table[target]["severity"]
            item["red_line"] = False
    for item in failed:
        if item["status"] != "skipped":
            findings.append(finding("SR-FAIL-CLOSED", item["file"], 0,
                                    "%s: %s" % (item["stage"], item["detail"] or item["status"]),
                                    stage=item["stage"], kind="input"))
    source = run.get("source", {})
    if source.get("reject"):
        rule = source["reject"].get("rule")
        findings.append(finding(rule if rule in ("SR-IN-003", "SR-IN-011") else "SR-IN-011",
                                "", 0, source["reject"].get("detail", ""), stage="fetch"))
    if source.get("skipped_members"):
        findings.append(finding("SR-IN-008", "", 0,
                                "%d special entries in the archive were skipped"
                                % source["skipped_members"], stage="fetch"))
    return data, findings, failed


def tidy(findings):
    """Drop exact repeats, cap each rule, sort by severity then place."""
    seen, kept, counts, extra = set(), [], {}, {}
    order = sorted(findings, key=lambda f: (-SEV_RANK[f["severity"]], f["rule_id"],
                                            f.get("file", ""), f.get("line", 0),
                                            f.get("snippet", "")))
    for item in order:
        key = (item["rule_id"], item.get("file"), item.get("line"), item.get("sub"),
               item.get("host"))
        if key in seen:
            continue
        seen.add(key)
        rule = item["rule_id"]
        counts[rule] = counts.get(rule, 0) + 1
        if counts[rule] > PER_RULE:
            extra[rule] = extra.get(rule, 0) + 1
            continue
        kept.append(item)
    for item in kept:
        item["message_key"] = "rules." + item["rule_id"]
        if extra.get(item["rule_id"]) and "more" not in item:
            item["more"] = extra.pop(item["rule_id"])
    return kept, counts


def decide(findings, data, run):
    """The fixed table. Returns (internal_verdict, reasons)."""
    rejected = bool(data.get("intake", {}).get("reject")) or bool(run.get("source", {}).get("reject"))
    by_level = {}
    for item in findings:
        by_level.setdefault(item["severity"], set()).add(item["rule_id"])
    if rejected:
        reasons = sorted(r for r in by_level.get("red", ()) if r.startswith("SR-IN-"))
        return "reject", reasons or sorted(by_level.get("red", ()))
    if by_level.get("red"):
        return "blocked", sorted(by_level["red"])
    if by_level.get("high"):
        return "caution", sorted(by_level["high"])
    notes = sorted(by_level.get("medium", set()) | by_level.get("low", set()))
    if notes:
        return "approve_with_notes", notes
    return "approve", []


def score(counts):
    table = rule_table()
    total = 0
    for rule, count in counts.items():
        total += PENALTY[table[rule]["severity"]] * min(count, 3)
    return max(0, 100 - total)


def top_items(findings, limit=3):
    out, seen = [], set()
    for item in findings:
        if item["severity"] == "info" or item["rule_id"] in seen:
            continue
        seen.add(item["rule_id"])
        out.append(item)
    return out[:limit]


def _where(item):
    if not item.get("file"):
        return ""
    return "%s:%d" % (item["file"], item["line"]) if item.get("line") else item["file"]


def _code(text, limit=80, table=False):
    text = clean_snippet(text, limit).replace("`", "'")
    if table:
        text = text.replace("|", "\\|")
    return "`%s`" % text if text else ""


def _plain(text, limit=110):
    return clean_snippet(text, limit).replace("`", "'").replace("|", "/").replace("\"", "'")


def describe(item, t):
    """One line about one finding, from fixed strings plus quoted data."""
    ui, rule = t["ui"], t["rules"][item["rule_id"]]
    where = _where(item)
    if item["rule_id"] == "SR-RL-08" and item.get("evidence"):
        value = _code(item.get("evidence_value") or "")
        line = ui["claim_line"].format(text=_code(item["snippet"], 110), where=_code(where, 160),
                                       value=value or ui["claim_other"],
                                       evidence=_code(item["evidence"], 160))
    else:
        detail = item.get("host") or ", ".join(item.get("names") or [])
        if not detail and item["rule_id"] not in NO_SNIPPET:
            detail = item.get("snippet", "")
        line = rule["title"]
        if detail:
            line += ": " + _code(detail)
        if where:
            line += " (%s)" % _code(where, 160)
    if item.get("decoded"):
        line += ". %s: %s" % (ui["decodes_to"], _code(item["decoded"], 100))
    if item.get("more"):
        line += " " + ui["more"].format(n=item["more"])
    line += "."
    if item["red_line"]:
        line += " %s %s." % (ui["red"].capitalize() if ui["red"][:1].isascii() else ui["red"],
                             item["rule_id"])
    return line


def label_lines(label, t):
    ui = t["ui"]
    lines = []
    hosts = ["%s (%s)" % (_code(n["host"]), ui["declared"] if n["declared"] else ui["undeclared"])
             for n in label.get("network", [])]
    if label.get("network_dynamic"):
        hosts.append(ui["net_dyn"])
    lines.append("%s: %s" % (ui["net"], ", ".join(hosts) if hosts else ui["no_net"]))
    outside = label.get("writes_outside_skill_dir") or []
    if outside:
        files = "%s: %s" % (ui["files_out"], ", ".join(_code(p) for p in outside[:4]))
    elif label.get("declared_writes"):
        files = "%s: %s" % (ui["files_declared"],
                            "; ".join(_plain(p, 90) for p in label["declared_writes"]))
    else:
        files = ui["files_in"] if label.get("writes_files") else ui["files_none"]
    lines.append("%s: %s" % (ui["files"], files))
    runs = label.get("subprocess") or []
    shown = [_code(r, 30) for r in runs[:8] if r not in ("?", "{}")]
    if len(shown) < len(runs[:8]):
        shown.append(ui["runs_unknown"])
    lines.append("%s: %s" % (ui["runs"], ", ".join(shown) if shown else ui["runs_none"]))
    kinds = {}
    for surface in label.get("exec_surfaces", []):
        kinds[surface["kind"]] = kinds.get(surface["kind"], 0) + 1
    auto = ", ".join("%s (%d)" % (t["surface"].get(k, k), n) for k, n in sorted(kinds.items()))
    lines.append("%s: %s" % (ui["auto"], auto or ui["auto_none"]))
    if label.get("secrets_read"):
        lines.append("%s: %s %s" % (ui["secrets"], ui["reads"],
                                    ", ".join(_code(n, 40) for n in label["secrets_read"][:6])))
    if label.get("runtime_installs"):
        lines.append("%s: %s" % (ui["installs"],
                                 ", ".join(_code(v, 50) for v in label["runtime_installs"][:4])))
    if label.get("from_prose"):
        seen, parts = set(), []
        for item in label["from_prose"]:
            if item["value"] not in seen and len(parts) < 6:
                seen.add(item["value"])
                parts.append(_code(item["value"], 50))
        lines.append("%s: %s" % (ui["from_text"], ", ".join(parts)))
    known = {n["host"] for n in label.get("network", [])}
    extra = [h for h in label.get("from_config") or [] if h not in known]
    if extra:
        lines.append("%s: %s" % (ui["from_config"], ", ".join(_code(h, 50) for h in extra[:6])))
    langs = label.get("code_files") or {}
    code = ", ".join("%s (%d)" % (k or "?", v) for k, v in sorted(langs.items()))
    lines.append("%s: %s" % (ui["code"], code or ui["no_code"]))
    return lines


def timeline_lines(label, t):
    ui, lines = t["ui"], []
    timeline = label.get("timeline") or {}
    for slot in SLOTS:
        items = timeline.get(slot) or []
        if not items:
            continue
        parts = []
        for item in items[:4]:
            kind = t["surface"].get(item["what"], item["what"])
            parts.append("%s %s (%s)" % (kind, _code(item["detail"], 90), _code(item["file"], 80)))
        if len(items) > 4:
            parts.append(ui["more"].format(n=len(items) - 4))
        lines.append("**%s**: %s" % (t["timing"][slot], "; ".join(parts)))
    langs = sorted(k for k in (label.get("code_files") or {}) if k)
    if not lines:
        lines.append(ui["nothing_auto"] if langs else ui["nothing_auto_text"])
    if langs:
        uses = [t["on_use"]["scripts"].format(langs=", ".join(langs))]
        if label.get("network") or label.get("network_dynamic"):
            uses.append(t["on_use"]["network"])
        if label.get("runtime_installs"):
            uses.append(t["on_use"]["installs"])
        lines.append("**%s**: %s" % (t["timing"]["on_use"], "; ".join(uses)))
    return lines


def promise_lines(promises, t):
    ui, lines = t["ui"], []
    rank = {"contradicted": 0, "softened": 1, "kept": 2}
    best = {}
    for item in promises:
        key = (item["file"], item["line"])
        mine = (rank[item["status"]], 0 if item.get("evidence_value") else 1)
        if key not in best or mine < best[key][0]:
            best[key] = (mine, item)
    chosen = [pair[1] for _, pair in sorted(best.items())]
    for item in sorted(chosen, key=lambda p: rank[p["status"]])[:8]:
        line = "%s: %s (%s). %s" % (ui["says"], _code(item["text"], 110),
                                     _code("%s:%d" % (item["file"], item["line"]), 160),
                                     ui[item["status"]])
        if item["status"] != "kept" and item.get("evidence"):
            line += ": %s" % _code(item["evidence"], 160)
            if item.get("evidence_value"):
                line += " %s" % _code(item["evidence_value"], 60)
        lines.append(line + ("" if line.endswith(".") else "."))
    return lines


NOT_READ = ("SR-FAIL-CLOSED", "SR-CD-001", "SR-CD-002", "SR-CD-005", "SR-IN-004", "SR-IN-006",
            "SR-IN-007", "SR-IN-008", "SR-IN-009", "SR-SF-001")


def not_checked(label, failed, findings, stopped):
    """What the scan did not cover. kind: scope, input or environment."""
    if stopped:
        return [{"kind": "input", "key": "nc_stopped"}]
    out = [{"kind": "scope", "key": "nc_quality"}, {"kind": "scope", "key": "nc_runtime"}]
    analysis = label.get("analysis") or {}
    if analysis.get("patterns") or analysis.get("not_analysed"):
        out.append({"kind": "scope", "key": "nc_patterns"})
    if label and not label.get("code_files"):
        out.append({"kind": "scope", "key": "nc_text_only"})
    seen = set()
    for item in findings:
        if item["rule_id"] in NOT_READ and item["rule_id"] not in seen and len(seen) < 8:
            seen.add(item["rule_id"])
            out.append({"kind": "input", "key": "rules." + item["rule_id"],
                        "file": item.get("file", "")})
    for item in failed:
        if item["status"] != "skipped":
            out.append({"kind": "input", "key": "nc_stage", "stage": item["stage"],
                        "status": item["status"]})
    out.append({"kind": "environment", "key": "nc_external"})
    return out


def render(report, t, sandbox_name):
    ui = t["ui"]
    verdict = report["verdict"]["internal"]
    name = report["subject"]["name"]
    findings = report["findings"]
    label = report["label"]
    top = top_items(findings)
    head = report["head"][t["lang"]]
    out = ["# %s: %s" % (t["verdict"][verdict], name), "", head, ""]
    if top:
        out += ["## %s" % (ui["top"] if verdict in ("caution", "blocked", "reject") else ui["notes"]), ""]
        out += ["%d. %s" % (index, describe(item, t)) for index, item in enumerate(top, 1)]
        out.append("")
        if verdict in ("blocked", "reject"):
            said = [t["rules"][i["rule_id"]]["you"] for i in top if i["red_line"]][:2]
            if said:
                out += ["**%s:** %s" % (ui["would"], " ".join(said)), ""]
        elif verdict == "caution":
            said = t["rules"][top[0]["rule_id"]]["you"]
            if said:
                out += ["**%s:** %s" % (ui["you"], said), ""]
    now = t["now"][verdict]
    if sandbox_name and verdict not in ("blocked", "reject"):
        now += " " + ui["sandbox_hint"].format(file=_code(sandbox_name, 120))
    out += ["**%s:** %s" % (ui["now"], now), ""]
    if label:
        out += ["## %s" % ui["label"], ""]
        out += ["- " + line for line in label_lines(label, t)]
        out += ["", "## %s" % ui["timeline"], ""]
        out += ["- " + line for line in timeline_lines(label, t)]
        out.append("")
    if report["promises"]:
        out += ["## %s" % ui["promise"], ""]
        out += ["- " + line for line in promise_lines(report["promises"], t)]
        out.append("")
    out += ["## %s" % ui["not_checked"], ""]
    for item in report["not_checked"]:
        if item["key"].startswith("rules."):
            text = t["rules"][item["key"][6:]]["title"]
            if item.get("file"):
                text += " (%s)" % _code(item["file"], 160)
        else:
            text = ui[item["key"]]
        if item["key"] == "nc_stage":
            text = "%s: %s (%s)" % (text, item["stage"], item["status"])
        out.append("- " + text)
    out += ["", "<details>", "<summary>%s</summary>" % ui["details"], ""]
    badges = report["badges"]
    if badges:
        yes_no = lambda value: ui["yes"] if value else ui["no"]
        out.append("- %s: %s: %s, %s: %s, %s: %s, %s: %s" % (
            ui["badges"], ui["b_hebrew"], yes_no(badges.get("hebrew")),
            ui["b_portable"], yes_no(badges.get("portable")),
            ui["b_asks"], yes_no(badges.get("asks_before_acting")),
            ui["b_tokens"], badges.get("context_cost_tokens", 0)))
    out.append("- %s: %d" % (ui["score"], report["security_score"]))
    analysis = label.get("analysis") or {}
    if label:
        out.append("- %s: %s" % (ui["depth"], ui["depth_line"].format(
            a=analysis.get("python_ast", 0), p=analysis.get("patterns", 0),
            n=analysis.get("not_analysed", 0))))
        out.append("- " + (ui["manifest_present"] if label.get("manifest") == "present"
                           else ui["manifest_absent"]))
    hashes = report["hashes"]
    if hashes.get("file_map_sha256"):
        out.append("- %s: `%s` (%s)" % (ui["hashes"], hashes["file_map_sha256"],
                                        hashes.get("hash_algo", "")))
    source = report["subject"]["source"]
    if source.get("url"):
        out.append("- %s: %s %s" % (ui["source"], _code(source["url"], 200),
                                    _code(source.get("commit") or "", 40)))
    out.append("- %s: %d. %s %s, %s %s. %s" % (
        ui["scanned"], report["subject"]["files"], TOOL_NAME, report["tool"]["version"],
        ui["rules_ver"], report["tool"]["rules_version"], ui["tier"]))
    if findings:
        out += ["", "### %s" % ui["all"], "",
                "| %s | %s | %s | %s |" % (ui["col_rule"], ui["col_sev"], ui["col_where"], ui["col_what"]),
                "| --- | --- | --- | --- |"]
        for item in findings:
            what = t["rules"][item["rule_id"]]["title"]
            detail = item.get("host") or item.get("snippet") or ""
            if detail and item["rule_id"] not in NO_SNIPPET:
                what += ": " + _code(detail, 70, True)
            if item.get("more"):
                what += " " + ui["more"].format(n=item["more"])
            out.append("| %s | %s | %s | %s |" % (item["rule_id"], t["severity"][item["severity"]],
                                                  _code(_where(item), 160, True), what))
        out += ["", ui["data_note"]]
    out += ["", "</details>", "", "---", "", "> " + report["share"][t["lang"]], ""]
    return "\n".join(out)


CSS = (
    "body{font-family:-apple-system,'Segoe UI',Arial,sans-serif;max-width:760px;margin:24px auto;"
    "padding:0 16px;line-height:1.6;color:#1c1c1c;background:#fff}"
    "code{direction:ltr;unicode-bidi:isolate;background:#f1f1ee;padding:1px 5px;border-radius:4px;"
    "font-size:.92em;word-break:break-all}"
    ".verdict{padding:14px 18px;border-radius:10px;font-size:1.5em;font-weight:700;margin-bottom:8px}"
    ".install{background:#e4f3e7;color:#14532d}.caution{background:#fdf3d3;color:#7a4b00}"
    ".block{background:#fbe3e1;color:#8a1c14}h2{font-size:1.1em;margin-top:28px;"
    "border-bottom:1px solid #ddd;padding-bottom:4px}li{margin:6px 0}"
    "table{border-collapse:collapse;width:100%;font-size:.9em}td,th{border:1px solid #ddd;"
    "padding:5px 7px;text-align:start;vertical-align:top}.note{color:#555;font-size:.9em}"
    ".box{background:#f7f7f5;border-radius:8px;padding:10px 14px;margin:10px 0}"
    "@media(prefers-color-scheme:dark){body{background:#161616;color:#e8e8e8}"
    "code,.box{background:#262626}td,th,h2{border-color:#444}.note{color:#aaa}"
    ".install{background:#12351d;color:#b7ebc4}.caution{background:#3d2f08;color:#f5dc9a}"
    ".block{background:#431512;color:#f6b9b3}}")


def _inline(text):
    """Escape everything, then turn `code` and **bold** into tags. Nothing
    from the scanned skill can reach the page as markup."""
    import html
    out = html.escape(str(text), quote=True)
    out = re.sub(r"`([^`]*)`", r"<code>\1</code>", out)
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)


def render_html(report, t, sandbox_name):
    """The same report as a single page with no scripts and no outside files."""
    ui = t["ui"]
    verdict = report["verdict"]["internal"]
    rtl = t["lang"] == "he"
    findings, label = report["findings"], report["label"]
    top = top_items(findings)
    out = ["<!doctype html>", "<html lang=\"%s\" dir=\"%s\">" % (t["lang"], "rtl" if rtl else "ltr"),
           "<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,"
           "initial-scale=1\">", "<title>%s</title>" % _inline("SkillRentgen: " + report["subject"]["name"]),
           "<style>%s</style></head><body>" % CSS,
           "<div class=\"verdict %s\">%s: %s</div>" % (
               report["verdict"]["user"], _inline(t["verdict"][verdict]),
               _inline(report["subject"]["name"])),
           "<p>%s</p>" % _inline(report["head"][t["lang"]])]

    def section(title, lines, ordered=False):
        if lines:
            tag = "ol" if ordered else "ul"
            out.append("<h2>%s</h2><%s>%s</%s>" % (
                _inline(title), tag, "".join("<li>%s</li>" % _inline(line) for line in lines), tag))

    section(ui["top"] if verdict in ("caution", "blocked", "reject") else ui["notes"],
            [describe(item, t) for item in top], ordered=True)
    said = ""
    if top and verdict in ("blocked", "reject"):
        said = " ".join([t["rules"][i["rule_id"]]["you"] for i in top if i["red_line"]][:2])
        said = said and "**%s:** %s" % (ui["would"], said)
    elif top and verdict == "caution" and t["rules"][top[0]["rule_id"]]["you"]:
        said = "**%s:** %s" % (ui["you"], t["rules"][top[0]["rule_id"]]["you"])
    now = t["now"][verdict]
    if sandbox_name and verdict not in ("blocked", "reject"):
        now += " " + ui["sandbox_hint"].format(file=_code(sandbox_name, 120))
    out.append("<div class=\"box\">%s<p>%s</p></div>" % (
        "<p>%s</p>" % _inline(said) if said else "", _inline("**%s:** %s" % (ui["now"], now))))
    if label:
        section(ui["label"], label_lines(label, t))
        section(ui["timeline"], timeline_lines(label, t))
    section(ui["promise"], promise_lines(report["promises"], t))
    missed = []
    for item in report["not_checked"]:
        if item["key"].startswith("rules."):
            text = t["rules"][item["key"][6:]]["title"]
            text += " (%s)" % _code(item["file"], 160) if item.get("file") else ""
        else:
            text = ui[item["key"]]
        missed.append(text)
    section(ui["not_checked"], missed)
    if findings:
        rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _inline(i["rule_id"]), _inline(t["severity"][i["severity"]]),
            _inline(_code(_where(i), 160)),
            _inline(t["rules"][i["rule_id"]]["title"] + (
                ": " + _code(i.get("host") or i.get("snippet"), 70)
                if (i.get("host") or i.get("snippet")) and i["rule_id"] not in NO_SNIPPET else "")))
            for i in findings)
        out.append("<h2>%s</h2><table><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>%s</table>"
                   "<p class=\"note\">%s</p>" % (_inline(ui["all"]), _inline(ui["col_rule"]),
                                                  _inline(ui["col_sev"]), _inline(ui["col_where"]),
                                                  _inline(ui["col_what"]), rows, _inline(ui["data_note"])))
    out.append("<p class=\"note\">%s: %d. %s %s, %s %s. %s: <code>%s</code></p>" % (
        _inline(ui["scanned"]), report["subject"]["files"], TOOL_NAME, _inline(report["tool"]["version"]),
        _inline(ui["rules_ver"]), _inline(report["tool"]["rules_version"]), _inline(ui["hashes"]),
        _inline(report["hashes"].get("file_map_sha256", ""))))
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def sandbox_prompt(root, structure, label, t):
    """A page the user pastes into a clean chat to see the instructions first."""
    ui = t["ui"]
    skills = sorted(structure.get("skills", []), key=lambda s: s["file"])
    if not skills:
        return None
    out = ["# %s" % ui["sandbox_title"], "", ui["sandbox_body"], ""]
    removed = 0
    for skill in skills[:3]:
        try:
            text, truncated = read_text(os.path.join(root, skill["file"]), 60000)
        except OSError:
            continue
        cleaned = _UNSAFE.sub("", text)
        removed += len(text) - len(cleaned)
        fence = "~~~~"
        while fence in cleaned:
            fence += "~"
        out += ["## `%s`" % clean_snippet(skill["file"], 200).replace("`", "'"), "", fence,
                cleaned.rstrip("\n") + ("\n[...]" if truncated else ""), fence, ""]
    if len(skills) > 3:
        out += [ui["sandbox_more"].format(n=len(skills) - 3), ""]
    surfaces = label.get("exec_surfaces") or []
    if surfaces:
        out += ["## %s" % ui["sandbox_auto"], ""]
        for surface in surfaces[:12]:
            detail = surface.get("command") or surface.get("url") or ""
            out.append("- %s, %s: %s" % (t["surface"].get(surface["kind"], surface["kind"]),
                                         t["timing"].get(surface.get("timing"), ""),
                                         _code(detail, 110)))
        out.append("")
    if removed:
        out += [ui["sandbox_removed"].format(n=removed), ""]
    return "\n".join(out)


def run(root, work, opts):
    run_info = load_json(os.path.join(work, "run.json"))
    data, raw, failed = collect(work, run_info)
    findings, counts = tidy(raw)
    internal, reasons = decide(findings, data, run_info)
    structure = data.get("structure", {})
    contract = data.get("contract", {})
    intake = data.get("intake", {})
    label = contract.get("label", {})
    name = re.sub(r"^\.+", "", structure.get("name") or run_info.get("name") or "skill") or "skill"
    langs = {"he": ["he"], "en": ["en"], "both": ["he", "en"]}[run_info.get("lang", "he")]
    texts = {}
    for lang in ("he", "en"):
        texts[lang] = load_json(os.path.join(SKILL_DIR, "i18n", lang + ".json"))
        texts[lang]["lang"] = lang
    top = top_items(findings)
    head, share = {}, {}
    for lang, t in texts.items():
        sentence = t["summary"][internal]
        if top and internal != "approve_with_notes" and t["rules"][top[0]["rule_id"]]["head"]:
            sentence = t["rules"][top[0]["rule_id"]]["head"]
        head[lang] = sentence
        share[lang] = t["ui"]["share"].format(name=name, verdict=t["verdict"][internal],
                                               head=sentence)
    report = {
        "schema_version": "1.0",
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION,
                 "rules_version": rule_file("red-lines.json")["rules_version"], "tier": "A"},
        "run": {"id": run_info.get("id", ""), "started_at": run_info.get("started_at", ""),
                "duration_ms": 0},
        "subject": {"name": name, "unit": structure.get("unit", "unknown"),
                    "source": {key: run_info.get("source", {}).get(key)
                               for key in ("kind", "url", "commit")},
                    "files": intake.get("stats", {}).get("files", 0),
                    "skills": len(structure.get("skills", []))},
        "hashes": intake.get("hashes", {}),
        "verdict": {"user": USER[internal], "internal": internal, "exit_code": EXIT[internal],
                    "reasons": reasons},
        "head": head,
        "findings": findings,
        "label": label,
        "promises": contract.get("promises", []),
        "not_checked": [],
        "security_score": score(counts),
        "badges": contract.get("badges", {}),
        "share": share,
        "external": {"skills_sh_audit": None},
    }
    primary = texts[langs[0]]
    report["not_checked"] = not_checked(label, failed, findings, internal == "reject")
    files = {}
    sandbox_name = ""
    if internal not in ("reject", "blocked") and structure.get("skills"):
        prompt = sandbox_prompt(root, structure, label, primary)
        if prompt:
            sandbox_name = "%s.sandbox-prompt.md" % name
            files[sandbox_name] = prompt
    for lang in langs:
        files["%s.%s.md" % (name, lang)] = render(report, texts[lang], sandbox_name)
        files["%s.%s.html" % (name, lang)] = render_html(report, texts[lang], sandbox_name)
    for filename, text in files.items():
        with open(os.path.join(work, "out-" + filename), "w", encoding="utf-8") as handle:
            handle.write(text)
    hosts = ", ".join("%s (%s)" % (n["host"], "declared" if n["declared"] else "undeclared")
                      for n in label.get("network", [])[:3]) or "none found"
    red = sum(1 for item in findings if item["red_line"])
    terminal = ["%s  %s  (exit %d)" % (TERMINAL[internal], name, EXIT[internal]),
                "%d findings, %d red lines. Network: %s" % (len(findings), red, hosts)]
    dump_json(report, os.path.join(work, "out-%s.report.json" % name))
    return {"name": name, "internal": internal, "exit_code": EXIT[internal],
            "terminal": terminal, "files": sorted(files) + ["%s.report.json" % name],
            "primary": "%s.%s.md" % (name, langs[0])}
