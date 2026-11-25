"""Unit tests for the pieces that the verdict rests on."""
from __future__ import annotations

import ast
import json
import os
import re
import unittest

import helpers
import common
import intake
import structure
import verdict


class Hashing(unittest.TestCase):
    """The content hash must match the skills.sh lock v2 algorithm."""

    def _hash(self, files):
        with helpers.Workspace() as ws:
            for rel, data in files.items():
                path = ws.join(rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as handle:
                    handle.write(data)
            return intake.computed_hash(ws.path, list(files))

    def test_vectors(self):
        self.assertEqual(self._hash({}),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(self._hash({"SKILL.md": b"# hi\n"}),
                         "93c36952d8843b33e68ae970ebabcc03e1687c9bb0dd1ecaf357060318952f55")
        self.assertEqual(self._hash({"SKILL.md": b"a\n", "docs/b.md": b"b\n"}),
                         "b22c4d22aa319d2924312fa18fcbfedc88fa89c74dbd8f298c683e1caf7b7f24")

    def test_line_endings_and_skips(self):
        unix = self._hash({"SKILL.md": b"a\nb\n"})
        self.assertEqual(self._hash({"SKILL.md": b"a\r\nb\r\n"}), unix)
        self.assertEqual(self._hash({"SKILL.md": b"a\nb\n", "metadata.json": b"{}",
                                     "__pycache__/x.pyc": b"\x00"}), unix)


class Frontmatter(unittest.TestCase):
    def test_shapes_found_in_real_skills(self):
        data, _, error = structure.parse_frontmatter(
            '---\nname: a\ndescription:\n  "folded over\n  two lines"\nallowed-tools:\n  [\n    "Read",\n  ]\n---\n')
        self.assertIsNone(error)
        self.assertEqual(data["description"], "folded over two lines")
        self.assertEqual(data["allowed-tools"], ["Read"])

    def test_refuses_what_can_blow_up_a_parser(self):
        for block in ("a: &x [1]\nb: *x", "a: !!python/object:os.system x", "<<: {a: 1}",
                      "a:\n" + "".join(" " * (2 * i) + "k:\n" for i in range(1, 12)) + " " * 24 + "v: 1"):
            _, _, error = structure.parse_frontmatter("---\n" + block + "\n---\n")
            self.assertTrue(error and error.startswith("refused:"), block[:30])

    def test_unknown_shape_is_not_a_refusal(self):
        _, _, error = structure.parse_frontmatter("---\nname: w\n? odd\n: shape\n---\n")
        self.assertTrue(error and not error.startswith("refused:"))


class Snippets(unittest.TestCase):
    def test_snippets_are_short_and_inert(self):
        dirty = "a\u202eb\u200bc" + chr(common.TAGS_FIRST + 65) + "\x1b[31m" + "x" * 500
        clean = common.clean_snippet(dirty)
        self.assertLessEqual(len(clean), 120)
        self.assertFalse(common._UNSAFE.search(clean))

    def test_unknown_rule_id_is_an_error(self):
        with self.assertRaises(KeyError):
            common.finding("SR-NOT-A-RULE")


class PathMatching(unittest.TestCase):
    """Which files does a document point at. A wrong answer here once made
    every SKILL.md in a tree count as live because one page said SKILL.md."""

    def test_a_bare_name_means_the_file_beside_the_document(self):
        paths = ["skills/a/SKILL.md", "examples/x/SKILL.md", "skills/a/run.py", "tests/helpers/run.py"]
        self.assertEqual(common.path_matches("save it next to SKILL.md", "skills/a", paths),
                         {"skills/a/SKILL.md"})
        self.assertEqual(common.path_matches("python3 run.py", "skills/a", paths), {"skills/a/run.py"})

    def test_a_path_with_a_folder_matches_by_its_tail(self):
        paths = ["plugin/hooks/warm.sh", "plugin/tests/helpers/run.py"]
        self.assertEqual(common.path_matches("bash ${CLAUDE_PLUGIN_ROOT}/hooks/warm.sh", "plugin/hooks", paths),
                         {"plugin/hooks/warm.sh"})
        self.assertEqual(common.path_matches("Run `python3 tests/helpers/run.py` first", "plugin", paths),
                         {"plugin/tests/helpers/run.py"})


class Placeholders(unittest.TestCase):
    def test_real_domains_are_not_placeholders(self):
        pattern = re.compile(common.rule_file("known.json")["placeholder_host_re"], re.I)
        for host in ("x.com", "evil.com", "foo.io", "server.com", "api.enrich-leads.example"):
            self.assertFalse(pattern.search(host), host)
        for host in ("example.com", "api.example.com", "foo.example", "localhost", "your-domain.com"):
            self.assertTrue(pattern.search(host), host)


class VerdictTable(unittest.TestCase):
    def _decide(self, severities, reject=False):
        table = common.rule_table()
        pick = {}
        for rule, meta in sorted(table.items()):
            pick.setdefault(meta["severity"], rule)
        findings = [common.finding(pick[s]) for s in severities]
        data = {"intake": {"reject": reject}}
        return verdict.decide(findings, data, {"source": {}})[0]

    def test_table(self):
        self.assertEqual(self._decide([]), "approve")
        self.assertEqual(self._decide(["info"]), "approve")
        self.assertEqual(self._decide(["low", "medium"]), "approve_with_notes")
        self.assertEqual(self._decide(["high"]), "caution")
        self.assertEqual(self._decide(["red", "low"]), "blocked")
        self.assertEqual(self._decide(["red"], reject=True), "reject")

    def test_many_warnings_never_block(self):
        self.assertEqual(self._decide(["high"] * 40), "caution")

    def test_a_stage_cannot_lower_a_severity(self):
        with helpers.Workspace() as ws:
            forged = common.finding("SR-RL-01", "x.py", 1, "x")
            forged["severity"], forged["red_line"] = "info", False
            common.dump_json({"findings": [forged], "files": [], "reject": False},
                             ws.join("intake.json"))
            run = {"stages": {"intake": {"status": "ok"}}, "source": {}}
            _, findings, _ = verdict.collect(ws.path, run)
            self.assertEqual(findings[0]["severity"], "red")

    def test_a_failed_stage_fails_closed(self):
        with helpers.Workspace() as ws:
            run = {"stages": {"intake": {"status": "ok"}, "structure": {"status": "ok"},
                              "text_rules": {"status": "timeout", "detail": "no result"},
                              "surfaces": {"status": "ok"}, "contract": {"status": "ok"}}, "source": {}}
            for stage in ("intake", "structure", "surfaces", "contract"):
                common.dump_json({"findings": []}, ws.join(stage + ".json"))
            data, findings, failed = verdict.collect(ws.path, run)
            self.assertEqual([f["rule_id"] for f in findings], ["SR-FAIL-CLOSED"])
            self.assertEqual(verdict.decide(findings, data, run)[0], "caution")


class Limits(unittest.TestCase):
    """Size limits, tested with the limits lowered so the test stays fast."""

    def _run(self, count, **limits):
        saved = dict(common.LIMITS)
        common.LIMITS.update(limits)
        try:
            with helpers.Workspace() as ws:
                os.makedirs(ws.join("skill"))
                for index in range(count):
                    with open(ws.join("skill", "f%03d.md" % index), "w") as handle:
                        handle.write("x")
                return intake.run(ws.join("skill"), ws.path, {})
        finally:
            common.LIMITS.clear()
            common.LIMITS.update(saved)

    def test_past_the_soft_limit_the_scan_is_partial(self):
        result = self._run(8, soft_files=5)
        self.assertTrue(result["partial"])
        self.assertFalse(result["reject"])
        self.assertIn("SR-IN-004", [f["rule_id"] for f in result["findings"]])
        self.assertIsNone(result["hashes"]["computed_hash"]["value"])

    def test_past_the_hard_limit_the_intake_is_refused(self):
        result = self._run(8, soft_files=3, hard_files=5)
        self.assertTrue(result["reject"])
        self.assertIn("SR-IN-003", [f["rule_id"] for f in result["findings"]])


class Strings(unittest.TestCase):
    """Every sentence a report can contain lives in i18n, in both languages."""

    def setUp(self):
        self.texts = {lang: json.load(open(os.path.join(helpers.SKILL, "i18n", lang + ".json"),
                                           encoding="utf-8")) for lang in ("he", "en")}

    def _keys(self, node, prefix=""):
        out = set()
        for key, value in node.items():
            out |= self._keys(value, prefix + key + ".") if isinstance(value, dict) else {prefix + key}
        return out

    def test_both_languages_have_the_same_keys(self):
        self.assertEqual(self._keys(self.texts["he"]) ^ self._keys(self.texts["en"]), set())

    def test_every_rule_has_a_title(self):
        for rule in common.rule_table():
            for lang in ("he", "en"):
                self.assertTrue(self.texts[lang]["rules"].get(rule, {}).get("title"), rule + " " + lang)

    def test_every_rule_a_stage_names_exists(self):
        used = set()
        for name in os.listdir(helpers.SCRIPTS):
            if name.endswith(".py"):
                used |= set(re.findall(r"\"(SR-[A-Z]+-(?:\d+|CLOSED))\"",
                                       open(os.path.join(helpers.SCRIPTS, name), encoding="utf-8").read()))
        self.assertEqual(sorted(used - set(common.rule_table())), [])

    def test_no_long_dashes_and_no_invisible_characters(self):
        for root, _, files in os.walk(helpers.REPO):
            if ".git" in root.split(os.sep):
                continue
            for name in files:
                if not name.endswith((".md", ".json", ".py", ".yml", ".txt")):
                    continue
                text = open(os.path.join(root, name), encoding="utf-8").read()
                self.assertFalse(re.search("[\u2013\u2014]", text), name + " has a long dash")
                self.assertFalse(common._UNSAFE.search(text.replace("\n", "").replace("\t", "")),
                                 name + " has an invisible character")


class OwnCode(unittest.TestCase):
    def test_python_floor_and_standard_library_only(self):
        import sys
        allowed = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
        own = {name[:-3] for name in os.listdir(helpers.SCRIPTS) if name.endswith(".py")}
        for name in sorted(own):
            source = open(os.path.join(helpers.SCRIPTS, name + ".py"), encoding="utf-8").read()
            tree = ast.parse(source, feature_version=(3, 9))
            self.assertTrue(source.isascii(), name + " holds non-ASCII characters")
            for node in ast.walk(tree):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    modules = [(node.module or "").split(".")[0]]
                for module in modules:
                    if allowed is not None:
                        self.assertTrue(module in allowed or module in own, "%s imports %s" % (name, module))


if __name__ == "__main__":
    unittest.main()
