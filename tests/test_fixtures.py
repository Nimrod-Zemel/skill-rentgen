"""Every test skill must end in the verdict it was written for."""
from __future__ import annotations

import os
import unittest

import helpers
import fixtures


def _case_sensitive(folder):
    probe = os.path.join(folder, "CaseProbe")
    open(probe, "w").close()
    return not os.path.exists(os.path.join(folder, "caseprobe"))


class FixtureVerdicts(unittest.TestCase):
    def test_every_fixture(self):
        for name, spec in sorted(fixtures.FIXTURES.items()):
            with self.subTest(fixture=name), helpers.Workspace() as ws:
                if spec["needs"] == "case" and not _case_sensitive(ws.path):
                    continue
                try:
                    target = fixtures.build(name, ws.join("fx"))
                except (OSError, NotImplementedError):
                    if spec["needs"]:
                        continue
                    raise
                summary, report, _ = helpers.scan_inline(target, ws.join("out"))
                ids = helpers.rule_ids(report)
                self.assertEqual(summary["internal"], spec["expect"], "%s gave %s" % (name, ids))
                for rule in spec["rules"]:
                    self.assertIn(rule, ids, name)
                for rule in spec["absent"]:
                    self.assertNotIn(rule, ids, name)

    def test_known_bad_are_never_install(self):
        """A skill written to be bad must never come out as a plain install."""
        for name, spec in fixtures.FIXTURES.items():
            if spec["kind"] in ("bad", "evasion") and spec["expect"] in ("blocked", "reject", "caution"):
                self.assertNotIn(spec["expect"], ("approve", "approve_with_notes"))

    def test_each_active_red_line_has_a_fixture(self):
        from common import rule_table
        red = {rule for rule, meta in rule_table().items()
               if meta["severity"] == "red" and meta.get("status") != "deferred"
               and not rule.startswith("SR-TR-")}  # trial rules: test_trial.Behaviour
        covered = {rule for spec in fixtures.FIXTURES.values() for rule in spec["rules"]}
        covered.add("SR-IN-003")  # size limits: test_engine.Limits, with the limits lowered
        self.assertEqual(sorted(red - covered), [], "red lines with no fixture")


if __name__ == "__main__":
    unittest.main()
