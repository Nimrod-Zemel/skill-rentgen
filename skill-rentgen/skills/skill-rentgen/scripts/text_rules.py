"""Stage 2: text rules. Hidden characters, instructions aimed at the agent, secrets.

WHY: a skill is mostly text that an agent will obey. The dangerous parts are
the ones a person reviewing it cannot see (invisible characters, HTML
comments) and the ones that tell the agent to act behind the user's back.
A document that only quotes such a phrase as an example of an attack must
not be blocked, so every match is checked for where and how it appears.

Rules that tests check:
1. Direction marks U+200E and U+200F, balanced isolates, and emoji joiners
   are allowed. Hebrew and Arabic documents must pass.
2. Bidi overrides, Unicode Tags and unbalanced embeddings are always a red
   line, in any file.
3. A phrase inside a code span, a quote, or a line that discusses attacks is
   reported as a mention, not as an instruction.
4. A secret is reported by its first characters and a short hash, never whole.
"""
from __future__ import annotations

import hashlib
import os
import re

from common import (SELECTORS_FIRST, TAGS_ASCII_LAST, TAGS_CLASS, TAGS_FIRST, TAGS_LAST, finding,
                    is_doc_path, is_test_path, line_of, line_text, load_json, no_addresses,
                    progress, read_text, referenced_files, rule_file)

HIDDEN = re.compile("[\u00ad\u200b-\u200d\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
                    "\ufe00-\ufe0f]|" + TAGS_CLASS)
COMMENT = re.compile(r"<!--(.{8,4000}?)-->", re.S)
ALT = re.compile(r"!\[([^\]\n]{12,600})\]\(")
LINKDEF = re.compile(r"^\s{0,3}\[[^\]\n]+\]:\s*\S+\s+[\"'(]([^\n]{12,600})[\"')]\s*$", re.M)
EXECISH = re.compile(r"\b(?:curl|wget)\b[^\n]{0,80}https?://|\|\s*(?:ba|z)?sh\b|base64\s+(?:-d|--decode)",
                     re.I)
OPENERS = {"\u202a": "e", "\u202b": "e", "\u2066": "i", "\u2067": "i", "\u2068": "i"}
QUOTES = "\"'\u201c\u201d\u2018\u2019\u00ab`"


def fence_lines(text):
    """Return the set of 1-based line numbers that sit inside a code fence."""
    inside, marker, out = False, "", set()
    for number, line in enumerate(text.split("\n"), 1):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            if not inside:
                inside, marker = True, stripped[:3]
            elif stripped.startswith(marker):
                inside = False
            out.add(number)
        elif inside:
            out.add(number)
    return out


def code_blocks(text):
    """Yield (language, first_line_number, body) for each fenced block."""
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        if stripped.startswith(("```", "~~~")):
            marker, lang = stripped[:3], stripped[3:].strip().split(" ")[0].lower()
            start = index + 1
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith(marker):
                index += 1
            yield lang, start + 1, "\n".join(lines[start:index])
        index += 1


def _in_span(line, column):
    return line.count("`", 0, column) % 2 == 1


def _hidden_class(text, pos):
    char = text[pos]
    code = ord(char)
    prev = text[pos - 1] if pos else ""
    prev_code = ord(prev) if prev else 0
    if code in (0x202D, 0x202E):
        return "override"
    if TAGS_FIRST <= code <= TAGS_ASCII_LAST:
        back = pos - 1
        while back >= 0 and TAGS_FIRST <= ord(text[back]) <= TAGS_ASCII_LAST:
            back -= 1
        return "ok" if back >= 0 and ord(text[back]) == 0x1F3F4 else "tag"
    if SELECTORS_FIRST <= code <= TAGS_LAST:
        return "ok" if prev_code >= 0x3400 else "tag"
    if char in OPENERS or code in (0x202C, 0x2069):
        line = line_text(text, pos)
        embed = sum(1 for c in line if OPENERS.get(c) == "e") - line.count("\u202c")
        isolate = sum(1 for c in line if OPENERS.get(c) == "i") - line.count("\u2069")
        return "bidi" if embed == 0 and isolate == 0 else "unbalanced"
    if 0xFE00 <= code <= 0xFE0F:
        if prev and (prev.isdigit() or prev in "#*\u00a9\u00ae" or prev_code >= 0x2030):
            return "ok"
        return "zw"
    if code in (0x200C, 0x200D):
        return "ok" if prev_code >= 0x0590 else "zw"
    if code == 0xFEFF and pos == 0:
        return "ok"
    return "zw"


def _neighbours(text, pos):
    """The visible characters on both sides, and the length of the hidden run."""
    left = pos - 1
    while left >= 0 and HIDDEN.match(text[left]):
        left -= 1
    right = pos + 1
    while right < len(text) and HIDDEN.match(text[right]):
        right += 1
    before = text[left] if left >= 0 else "\n"
    after = text[right] if right < len(text) else "\n"
    return before, after, text[left + 1:right]


def _hidden(rel, text, is_code, fences, findings, relaxed=False):
    """Report invisible characters.

    Calibrated on real skills: code that cleans up or compares invisible
    characters holds them inside quotes or a regex class, one or two at a
    time. An attack hides them inside a word, in a long run, or uses them
    to reorder a line of code. Only the second group is a red line.
    """
    counts = {}
    for match in HIDDEN.finditer(text):
        pos = match.start()
        kind = _hidden_class(text, pos)
        if kind == "ok":
            continue
        line_no = line_of(text, pos)
        line = line_text(text, pos)
        column = pos - (text.rfind("\n", 0, pos) + 1)
        in_code = is_code or line_no in fences or _in_span(line, column)
        before, after, run = _neighbours(text, pos)
        # A regex class or a lookup table lists each invisible character once.
        # Hidden data needs repeats: a run with repeats, or a long run, is a payload.
        payload = len(run) >= 12 or (len(run) >= 3 and len(set(run)) < len(run))
        word = lambda c: c.isascii() and c.isalnum()
        literal = not (word(before) or word(after) or before.isspace() or after.isspace())
        if kind in ("override", "tag"):
            red = True
        elif payload:
            red = True
        elif kind == "zw":
            red = in_code and word(before) and word(after)
        elif kind == "bidi":
            if not is_code:
                continue
            red = not literal
        else:
            red = in_code and not literal
        if relaxed:
            red = False
        rule = "SR-RL-07" if red else "SR-TX-001"
        if rule == "SR-TX-001" and is_code and literal:
            continue
        key = (rule, kind)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= 2:
            findings.append(finding(rule, rel, line_no, line, sub=kind,
                                    codepoint="U+%04X" % ord(match.group(0))))
    return counts


def _lookalikes(rel, text, is_code, fences, chars, findings):
    """A word that reads as Latin but carries a Cyrillic or Greek letter."""
    token = re.compile("[A-Za-z0-9%s]*[%s][A-Za-z0-9%s]*" % (chars, chars, chars))
    hits = 0
    for match in token.finditer(text):
        word = match.group(0)
        if len(word) < 3 or not re.search("[A-Za-z]", word):
            continue
        pos = match.start()
        line = line_text(text, pos)
        column = pos - (text.rfind("\n", 0, pos) + 1)
        in_url = bool(re.search(r"://[^\s]*$", line[:column]))
        if not (is_code or in_url or line_of(text, pos) in fences or _in_span(line, column)):
            continue
        hits += 1
        if hits <= 2:
            odd = next(c for c in word if c in chars)
            findings.append(finding("SR-RL-07", rel, line_of(text, pos), line, sub="homoglyph",
                                    codepoint="U+%04X" % ord(odd)))


ESCAPED_TAG = re.compile(r"\\U000[eE]00[0-7][0-9a-fA-F]|\\u\{[eE]00[0-7][0-9a-fA-F]\}"
                         r"|\\u[dD][bB]40\\u[dD][cC][0-7][0-9a-fA-F]|0x[eE]00[0-7][0-9a-fA-F]\b")


def _escaped_tags(rel, text, findings):
    match = ESCAPED_TAG.search(text)
    if match:
        findings.append(finding("SR-TX-001", rel, line_of(text, match.start()),
                                line_text(text, match.start()), sub="escaped-tag"))


def _secret_snippet(value):
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
    return "%s... sha256:%s" % (value[:6], digest)


def _secrets(rel, text, patterns, findings, in_tests):
    seen = 0
    for name, regex in patterns:
        for match in regex.finditer(text):
            value = match.group(0)
            body = value.split("-----")[-1] if name == "private-key" else value
            if len(set(body)) < 10 or "EXAMPLE" in value.upper() or "XXXX" in value.upper():
                continue
            if in_tests and name != "private-key":
                continue
            seen += 1
            if seen <= 3:
                findings.append(finding("SR-TX-003", rel, line_of(text, match.start()),
                                        _secret_snippet(value), sub=name))


# Records and legal texts describe what happened; they are not instructions to an agent.
RECORD_DOC = re.compile(r"^(?:CHANGELOG|CHANGES|HISTORY|RELEASES?|RELEASE[-_]NOTES|LICEN[CS]E|NOTICE|COPYING"
                        r"|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY|AUTHORS|THIRD[-_]PARTY[-_]NOTICES)"
                        r"(?:[-_.][\w.-]*)?$", re.I)
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")


def _lead_in(text, pos):
    """For a list item: the line that introduces the list, and the nearest heading."""
    lines = text[:pos].split("\n")
    if not LIST_ITEM.match(lines[-1] if lines else ""):
        return ""
    found, steps = [], 0
    for line in reversed(lines[:-1]):
        steps += 1
        if steps > 60 or len(found) == 2:
            break
        stripped = line.strip()
        if not stripped or LIST_ITEM.match(line):
            continue
        if stripped.startswith("#"):
            found.append(stripped)
            break
        if not found:
            found.append(stripped)
    return "\n".join(found)


SENTENCE_START = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|#+\s+|>\s*)?(?:\*\*|__|\*|_)?\s*$")


def _is_mention(text, match, fences, guard):
    """True when the phrase is quoted or described, not given as an order.

    Calibrated twice. Security documentation quotes these phrases inside
    quotes, code spans, tables and "look for" lists: those are mentions.
    A sentence that opens with the phrase is an order, whatever words sit
    in the lines around it. A heading that says "injection test" above an
    injection does not make it harmless.
    """
    pos = match.start()
    line_no = line_of(text, pos)
    line = line_text(text, pos)
    column = pos - (text.rfind("\n", 0, pos) + 1)
    if line_no in fences or _in_span(line, column):
        return True
    before = line[:column]
    last = before.rstrip()[-1:]
    if (last and last in QUOTES) or line.lstrip().startswith(">"):
        return True
    lead = _lead_in(text, pos)
    if lead and guard.search(no_addresses(lead)):
        return True
    opens = bool(SENTENCE_START.match(before)) or bool(re.search(r"[.!?:;]\s+$", before))
    if opens:
        return False
    return bool(guard.search(no_addresses(line)))


def _instructions(rel, text, pats, fences, findings, in_tests):
    guard, negation = pats["guard"], pats["negation"]

    def emit(rule, match, sub, **extra):
        findings.append(finding(rule, rel, line_of(text, match.start()),
                                line_text(text, match.start()), sub=sub, **extra))

    for group in ("conceal", "override", "bypass"):
        hits = 0
        for regex in pats[group]:
            for match in regex.finditer(text):
                negated = False
                if group == "bypass":
                    lead = text[max(0, match.start() - 48):match.start()]
                    negated = bool(negation.search(lead))
                mention = in_tests or negated or _is_mention(text, match, fences, guard)
                hits += 1
                if hits <= 3:
                    emit("SR-TX-004" if mention else "SR-RL-06", match, group)
    hits = 0
    for regex in pats["no_ask"]:
        for match in regex.finditer(text):
            if in_tests or _is_mention(text, match, fences, guard):
                continue
            hits += 1
            if hits <= 2:
                emit("SR-TX-002", match, "no_ask")
    hits = 0
    for regex in pats["indirect"]:
        for match in regex.finditer(text):
            if in_tests or _is_mention(text, match, fences, guard):
                continue
            hits += 1
            if hits <= 2:
                emit("SR-TX-007", match, "indirect")
    for regex in pats["remote_load"]:
        for match in regex.finditer(text):
            url = match.group(match.lastindex or 0)
            host = re.sub(r"^https?://", "", url).split("/")[0].lower()
            if pats["placeholder"].search(host) or re.search(r"[0-9a-f]{40}", url):
                continue
            mention = in_tests or _is_mention(text, match, fences, guard)
            # "fetch it and follow it" loads instructions; "download it and run it" runs a program
            program = bool(re.search(r"\b(?:and|then)\s+(?:run|execute)\b", match.group(0), re.I))
            if mention:
                rule = "SR-TX-004"
            elif not program:
                rule = "SR-RL-12"
            else:
                known = any(host == h or host.endswith("." + h) for h in pats["installers"])
                rule = "SR-TX-005" if known else "SR-RL-02"
            emit(rule, match, "instructed-download" if program else "remote_load", host=host)
    regions = [m for m in COMMENT.finditer(text)] + [m for m in ALT.finditer(text)]
    regions += [m for m in LINKDEF.finditer(text)]
    for region in regions:
        body = region.group(1)
        hit = EXECISH.search(body)
        for group in ("conceal", "override", "bypass", "remote_load"):
            if hit:
                break
            for regex in pats[group]:
                hit = regex.search(body)
                if hit:
                    break
        if hit and not in_tests:
            findings.append(finding("SR-RL-07", rel, line_of(text, region.start()),
                                    body, sub="hidden-instruction"))


SECRET_WORD = r"\b(?:password|passcode|pwd)\b\s*(?:is\s*[:=]?|[:=])\s*[`\"'*]{0,3}[^\s`\"'*]{3,40}"
ARCHIVE_WORD = r"(?:\.zip|\.7z|\.rar|\barchive\b|\bunzip\b|\bextract\b)"
PASSWORD_ARCHIVE = re.compile(ARCHIVE_WORD + r"[^\n]{0,160}" + SECRET_WORD + "|" + SECRET_WORD
                              + r"[^\n]{0,160}" + ARCHIVE_WORD, re.I)
INSTALL_CONTEXT = re.compile(
    r"prerequisit|must\s+be\s+installed|needs?\s+to\s+be\s+installed|install(?:ed|er|ation)?\b[^\n]{0,80}\bfrom\b"
    r"|download(?:ed)?\b[^\n]{0,80}\bfrom\b|download\s+(?:it|and)\b|required\s+(?:before|cli|tool|driver|utility)"
    r"|\u05d9\u05e9\s+\u05dc\u05d4\u05ea\u05e7\u05d9\u05df|\u05d4\u05d5\u05e8\u05d3\s+\u05d0\u05ea|\u05d3\u05e8\u05d9\u05e9\u05d4\s+\u05de\u05d5\u05e7\u05d3\u05de\u05ea", re.I)
URL = re.compile(r"https?://([^/\s)>\]\"'`<|\\:]+)[^\s)>\]\"'`<|\\]*", re.I)


def _prerequisites(rel, text, pats, fences, findings):
    """Two shapes seen in skills that carried real malware: a password on an
    archive, and a 'prerequisite' that must be fetched from a free-hosting
    site or through a short link."""
    guard = pats["guard"]
    match = PASSWORD_ARCHIVE.search(text)
    if match and not guard.search(no_addresses(line_text(text, match.start()))):
        findings.append(finding("SR-TX-008", rel, line_of(text, match.start()),
                                line_text(text, match.start())))
    seen = set()
    for match in URL.finditer(text):
        host = match.group(1).lower()
        if host in seen or re.search(r"[{}<>$*%\[\]]", host) or not any(
                host == h or host.endswith("." + h) for h in pats["free_hosting"]):
            continue
        start = text.rfind("\n", 0, max(0, text.rfind("\n", 0, match.start()))) + 1
        end = text.find("\n", text.find("\n", match.end()) + 1)
        window = no_addresses(text[start:end if end != -1 else len(text)])
        if not INSTALL_CONTEXT.search(window) or guard.search(window):
            continue
        seen.add(host)
        if len(seen) <= 2:
            findings.append(finding("SR-TX-009", rel, line_of(text, match.start()),
                                    line_text(text, match.start()), host=host))


def compile_patterns():
    raw = rule_file("text-patterns.json")["text"]
    known = rule_file("known.json")
    flags = re.I | re.M
    pats = {group: [re.compile(p, flags) for p in raw[group]]
            for group in ("conceal", "override", "bypass", "no_ask", "remote_load", "indirect")}
    pats["guard"] = re.compile(raw["mention_guard"], re.I)
    pats["negation"] = re.compile(r"\b" + raw["negation"] + r"\b", re.I)
    pats["secrets"] = [(name, re.compile(p)) for name, p in raw["secrets"]]
    pats["lookalikes"] = raw["homoglyph"]
    pats["free_hosting"] = known.get("free_hosting", [])
    pats["installers"] = known.get("installer_hosts", [])
    pats["placeholder"] = re.compile(known["placeholder_host_re"], re.I)
    return pats


def run(root, work, opts):
    intake = load_json(os.path.join(work, "intake.json"))
    structure = load_json(os.path.join(work, "structure.json"))
    pats = compile_patterns()
    pointed = referenced_files(root, intake, structure)
    findings = []
    for entry in intake.get("files", []):
        if entry["kind"] not in ("code", "doc", "data"):
            continue
        rel = entry["p"]
        progress(work, "text_rules", rel)
        try:
            text, _ = read_text(os.path.join(root, rel))
        except OSError:
            continue
        in_tests = (is_test_path(rel) or bool(RECORD_DOC.match(rel.rsplit("/", 1)[-1]))) \
            and rel not in pointed
        is_doc = entry["kind"] == "doc" or is_doc_path(rel)
        fences = fence_lines(text) if is_doc else set()
        _hidden(rel, text, entry["kind"] == "code", fences, findings, relaxed=in_tests)
        if not in_tests:
            _lookalikes(rel, text, entry["kind"] == "code", fences, pats["lookalikes"], findings)
            if entry["kind"] == "code":
                _escaped_tags(rel, text, findings)
        _secrets(rel, text, pats["secrets"], findings, in_tests)
        if is_doc or entry.get("lang") == "markup":
            _instructions(rel, text, pats, fences, findings, in_tests)
            parts = rel.split("/")
            instructs = parts[-1] in ("SKILL.md", "README.md") or (
                len(parts) >= 2 and parts[-2] in ("agents", "commands", "references"))
            if instructs and not in_tests:
                _prerequisites(rel, text, pats, fences, findings)
    return {"findings": findings, "pointed": sorted(pointed)}
