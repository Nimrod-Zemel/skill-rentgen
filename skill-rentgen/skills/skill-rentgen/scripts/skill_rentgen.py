#!/usr/bin/env python3
"""SkillRentgen: check an agent skill before you install it.

WHY: a skill is instructions and code that run with your permissions. This
tool reads a skill without running it and answers three questions in plain
words: what does it do, does that match what it promises, and what would
run on your machine without you asking. The code decides; no model is asked.

Usage:
  python3 skill_rentgen.py scan <folder | file.zip | https://github.com/owner/repo>
          [--lang he|en|both] [--out DIR] [--output-format text|json]
          [--fail-on caution|block]
  python3 skill_rentgen.py inventory [--scan] [--output-format text|json]
  python3 skill_rentgen.py add <skill folder | file.zip | github address> [--project] [--replace]
  python3 skill_rentgen.py baseline
  python3 skill_rentgen.py adopt <folder> [--accept-caution] [--source GITHUB_URL]
  python3 skill_rentgen.py check [name] [--upstream] [--hook]
  python3 skill_rentgen.py list
  python3 skill_rentgen.py notify --email you@company.com | --clear
  python3 skill_rentgen.py trial <folder | file.zip | github address> [--run "command"]
          [--engine docker|podman] [--image IMAGE] [--timeout SECONDS] [--no-scripts]
  python3 skill_rentgen.py trial <target> --agent-pack [--own-skill] [--prompt TEXT]
  python3 skill_rentgen.py trial --agent-result result.json
  python3 skill_rentgen.py block <skill-name> [--yes]   |   unblock <skill-name> [--yes]
  python3 skill_rentgen.py declare <folder>      (for builders)
  python3 skill_rentgen.py report <name> [--lang he|en] [--out DIR]
  python3 skill_rentgen.py version

Exit codes: 0 install, 1 caution, 2 do not install, 10 the tool itself failed.

Rules that tests check:
1. A scan never executes and never imports the scanned skill. Only the
   trial command starts anything, and only inside a sealed container.
2. Every stage runs in its own isolated Python process, with a time limit.
3. A stage that fails never produces "install". The scan fails closed.
4. An archive is unpacked entry by entry; nothing is written outside the
   quarantine folder and no link from the archive is created on disk.
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 9):
    sys.stderr.write("skill-rentgen needs Python 3.9 or newer\n")
    sys.exit(10)

import os

HERE = os.path.dirname(os.path.abspath(__file__))
NO_PYC = os.path.join(os.devnull, "skill-rentgen")
ISOLATION = ["-I", "-B", "-X", "utf8", "-X", "pycache_prefix=" + NO_PYC]


def _isolate():
    """Start again in isolated mode, so nothing in the environment or the
    current folder can be imported in place of the standard library."""
    if sys.flags.isolated and sys.dont_write_bytecode:
        return
    import subprocess
    try:
        code = subprocess.call([sys.executable] + ISOLATION + [os.path.abspath(__file__)]
                               + sys.argv[1:])
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    _isolate()

sys.path.insert(0, HERE)

import argparse  # noqa: E402
import datetime  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import subprocess  # noqa: E402
import tarfile  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402
import uuid  # noqa: E402
import zipfile  # noqa: E402

import agent_trial  # noqa: E402
import inventory  # noqa: E402
import registry  # noqa: E402
import trial as trial_mod  # noqa: E402
import watch  # noqa: E402
from common import LIMITS, TOOL_NAME, TOOL_VERSION, clean_snippet, dump_json, load_json  # noqa: E402

STAGES = ("intake", "structure", "text_rules", "surfaces", "contract")
NEEDS = {"intake": (), "structure": ("intake",), "text_rules": ("intake", "structure"),
         "surfaces": ("intake", "structure"), "contract": ("intake", "structure", "surfaces")}
GITHUB = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?"
                    r"(?:/(?:tree|blob)/([^/?#]+)(?:/([^?#]*))?)?/?$")
ALLOWED_HOSTS = ("github.com", "codeload.github.com", "api.github.com")
DOWNLOAD_CAP = 200 * 1024 * 1024
ARCHIVE_EXT = (".zip", ".skill", ".tar.gz", ".tgz", ".tar")


class ToolError(Exception):
    """Something went wrong in the tool or its inputs, not in the skill."""


class Unreachable(ToolError):
    """GitHub's download host cannot be reached from this machine."""


COPY_HINT = ("If this environment has its own way to bring in repositories, fetch this one "
             "with it and run again with --copy <that folder>. Or download the skill and "
             "give the folder")


class Refused(Exception):
    """The archive itself is hostile. The scan stops with a reject."""

    def __init__(self, rule, detail):
        Exception.__init__(self, detail)
        self.rule, self.detail = rule, detail


# ---------------------------------------------------------------- fetching

class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = urllib.request.urlparse(newurl).hostname or ""
        if not newurl.startswith("https://") or host not in ALLOWED_HOSTS:
            raise ToolError("the download was redirected to a host that is not GitHub")
        return urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)


def download(path, dest):
    """Fetch one archive from GitHub's download host into dest."""
    opener = urllib.request.build_opener(_Redirects)
    request = urllib.request.Request("https://codeload.github.com/" + path,
                                     headers={"User-Agent": TOOL_NAME + "/" + TOOL_VERSION})
    try:
        with opener.open(request, timeout=45) as response, open(dest, "wb") as handle:
            total = 0
            while True:
                block = response.read(1024 * 256)
                if not block:
                    break
                total += len(block)
                if total > DOWNLOAD_CAP:
                    raise Refused("SR-IN-003", "download is larger than %d MB"
                                  % (DOWNLOAD_CAP // 1024 // 1024))
                handle.write(block)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise ToolError("GitHub answered 404. Check the address, and that the repository is public")
        if error.code in (403, 407, 429):
            raise Unreachable("GitHub's download host answered %d: a proxy, a firewall or a rate "
                              "limit is in the way. %s" % (error.code, COPY_HINT))
        raise ToolError("GitHub answered %d" % error.code)
    except (urllib.error.URLError, OSError) as error:
        raise Unreachable("could not reach GitHub's download host: %s. %s"
                          % (clean_snippet(str(error), 100), COPY_HINT))


# ------------------------------------------------- a copy already on disk

_SHA = re.compile(r"^[0-9a-f]{40}$")
_GIT_URL = re.compile(r"^[ \t]*url[ \t]*=[ \t]*(\S+)[ \t]*$", re.M)
_REPO_OF = re.compile(r"[:/]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def _small(path, limit=4 * 1024 * 1024):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def git_facts(top):
    """What a copy of a repository says about itself. Read from the plain
    text files of its .git folder; git itself is never started.
    Returns {"remotes": [address], "branch": name, "commit": id, "refs": {name: [ids]}}."""
    facts = {"remotes": [], "branch": None, "commit": None, "refs": {}}
    git = os.path.join(top, ".git")
    # A worktree or a submodule has a one-line .git file that points at
    # another folder. That pointer is not followed: the copy then says
    # nothing about itself, and no version is recorded.
    if os.path.islink(git) or not os.path.isdir(git):
        return facts
    facts["remotes"] = _GIT_URL.findall(_small(os.path.join(git, "config")))[:20]
    last = None
    for line in _small(os.path.join(git, "packed-refs")).splitlines():
        parts = line.split()
        if len(parts) == 2 and _SHA.match(parts[0]):
            last = parts[1]
            facts["refs"].setdefault(last, []).append(parts[0])
        elif line.startswith("^") and last and _SHA.match(line[1:].strip()):
            facts["refs"][last].append(line[1:].strip())      # what an annotated tag points at
    head = _small(os.path.join(git, "HEAD"), 4096).strip()
    if head.startswith("ref:"):
        ref = head[4:].strip()
        if re.match(r"^refs/[A-Za-z0-9_./-]+$", ref) and ".." not in ref:
            if ref.startswith("refs/heads/"):
                facts["branch"] = ref[len("refs/heads/"):]
            loose = _small(os.path.join(git, ref), 4096).strip()
            if _SHA.match(loose):
                facts["commit"] = loose
            elif facts["refs"].get(ref):
                facts["commit"] = facts["refs"][ref][0]
    elif _SHA.match(head):
        facts["commit"] = head
    return facts


def _at_ref(top, facts, ref):
    """True when the copy is at the version the address names."""
    commit = facts["commit"] or ""
    if ref == facts["branch"] or (len(ref) >= 7 and commit.startswith(ref.lower())):
        return True
    if not re.match(r"^[A-Za-z0-9_.-]+$", ref):
        return False
    for kind in ("tags", "heads", "remotes/origin"):
        ref_name = "refs/%s/%s" % (kind, ref)
        if commit in facts["refs"].get(ref_name, []):
            return True
        if _small(os.path.join(top, ".git", ref_name), 4096).strip() == commit:
            return True
    return False


def _copy_root(target, match, copy, source):
    """The folder to scan when the repository is already on this disk."""
    owner, repo, ref, sub = match.groups()
    top = os.path.realpath(copy)
    if not os.path.isdir(top):
        raise ToolError("--copy takes the folder that holds a copy of the repository")
    facts = git_facts(top)
    wanted = ("%s/%s" % (owner, repo)).lower()
    names = []
    for address in facts["remotes"]:
        found = _REPO_OF.search(address)
        names.append(("%s/%s" % found.groups()).lower() if found else "")
    if facts["remotes"] and wanted not in names:
        raise ToolError("that folder is a copy of %s, not of %s" % (
            clean_snippet(names[0] or facts["remotes"][0], 80), wanted))
    if ref and facts["commit"] and not _at_ref(top, facts, ref):
        raise ToolError("the copy is at %s, and the address asks for %s. Fetch that version, "
                        "or give the address without it" % (
                            clean_snippet(facts["branch"] or facts["commit"][:12], 60),
                            clean_snippet(ref, 60)))
    source.update(kind="github", url=target, commit=facts["commit"], copy=True)
    root, name = top, repo
    if sub:
        sub = _safe_rel(sub, 0)
        root = os.path.realpath(os.path.join(top, sub))
        if not (root + os.sep).startswith(top + os.sep):
            raise ToolError("the folder %s is not in that repository" % clean_snippet(sub))
        name = sub.rstrip("/").rsplit("/", 1)[-1]
        if os.path.isfile(root):
            root = os.path.dirname(root)
            name = os.path.basename(root) if root != top else repo
        if not os.path.isdir(root):
            raise ToolError("the folder %s is not in that repository" % clean_snippet(sub))
    return root, name


def _safe_rel(name, strip):
    parts = [part for part in name.replace("\\", "/").split("/") if part not in ("", ".")]
    if name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":") or ".." in parts:
        raise Refused("SR-IN-011", clean_snippet(name))
    parts = parts[strip:]
    return "/".join(parts)


class _Budget:
    def __init__(self):
        self.files = self.bytes = self.skipped = 0
        self.links = []

    def file(self, size):
        self.files += 1
        self.bytes += size
        if (self.files > LIMITS["hard_files"] or self.bytes > LIMITS["hard_bytes"]
                or size > LIMITS["hard_file_bytes"]):
            raise Refused("SR-IN-003", "%d files, %d bytes" % (self.files, self.bytes))

    def link(self, rel, target):
        if len(self.links) < 2000:
            self.links.append([rel, clean_snippet(target, 200)])


def _write(stream, path, budget, declared):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    written = 0
    with open(path, "wb") as handle:
        while True:
            block = stream.read(1024 * 256)
            if not block:
                break
            written += len(block)
            if written > LIMITS["hard_file_bytes"] or budget.bytes + written > LIMITS["hard_bytes"]:
                raise Refused("SR-IN-003", "an entry unpacks to more than the limit")
            handle.write(block)
    budget.file(written)


def unpack_tar(archive, dest, strip, budget):
    """Unpack entry by entry. Returns the commit id GitHub wrote, if any."""
    commit = None
    try:
        with tarfile.open(archive, mode="r:*") as tar:
            for member in tar:
                if commit is None:
                    commit = (tar.pax_headers or {}).get("comment") or ""
                rel = _safe_rel(member.name, strip)
                if not rel:
                    continue
                if member.issym() or member.islnk():
                    if member.issym():
                        budget.link(rel, member.linkname)
                    else:
                        budget.skipped += 1
                elif member.isdir():
                    os.makedirs(os.path.join(dest, rel), exist_ok=True)
                elif member.isreg():
                    stream = tar.extractfile(member)
                    if stream is not None:
                        _write(stream, os.path.join(dest, rel), budget, member.size)
                else:
                    budget.skipped += 1
    except (tarfile.TarError, EOFError, OSError) as error:
        raise Refused("SR-IN-011", "the archive is damaged: %s" % clean_snippet(str(error), 80))
    return commit or None


def unpack_zip(archive, dest, budget):
    try:
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                rel = _safe_rel(info.filename, 0)
                if not rel:
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    with bundle.open(info) as stream:
                        budget.link(rel, stream.read(4096).decode("utf-8", "replace"))
                elif info.filename.endswith("/"):
                    os.makedirs(os.path.join(dest, rel), exist_ok=True)
                else:
                    with bundle.open(info) as stream:
                        _write(stream, os.path.join(dest, rel), budget, info.file_size)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError) as error:
        raise Refused("SR-IN-011", "the archive is damaged: %s" % clean_snippet(str(error), 80))


def _single_folder(dest):
    entries = os.listdir(dest)
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        return os.path.join(dest, entries[0]), entries[0]
    return dest, ""


def resolve(target, quarantine, copy=None):
    """Turn what the user gave into (root_folder, source_info, display_name).
    `copy` is a folder that already holds the repository a GitHub address names."""
    source = {"kind": "local", "url": None, "commit": None}
    budget = _Budget()
    match = GITHUB.match(target)
    if copy is not None and not match:
        raise ToolError("--copy goes with a https://github.com/owner/repo address: the address "
                        "says what to scan, the folder is where a copy of it already is")
    try:
        if match and copy is not None:
            root, name = _copy_root(target, match, copy, source)
        elif match:
            owner, repo, ref, sub = match.groups()
            source.update(kind="github", url=target)
            archive = os.path.join(quarantine, "download.tar.gz")
            download("%s/%s/tar.gz/%s" % (owner, repo, ref or "HEAD"), archive)
            dest = os.path.join(quarantine, "src")
            os.makedirs(dest)
            source["commit"] = unpack_tar(archive, dest, 1, budget)
            os.unlink(archive)
            root, name = dest, repo
            if sub:
                sub = _safe_rel(sub, 0)
                root = os.path.join(dest, sub)
                name = sub.rstrip("/").rsplit("/", 1)[-1]
                if os.path.isfile(root):
                    root, name = os.path.dirname(root), os.path.basename(os.path.dirname(root)) or repo
                if not os.path.isdir(root):
                    raise ToolError("the folder %s is not in that repository" % clean_snippet(sub))
                prefix = sub.rstrip("/") + "/"
                budget.links = [[rel[len(prefix):], to] for rel, to in budget.links
                                if rel.startswith(prefix)]
        elif re.match(r"^[a-z][a-z0-9+.-]*://", target, re.I):
            raise ToolError("only https://github.com/owner/repo addresses are supported. "
                            "Download the skill and give the folder instead")
        elif os.path.isdir(target):
            root = os.path.realpath(target)
            name = os.path.basename(root)
        elif os.path.isfile(target) and target.lower().endswith(ARCHIVE_EXT):
            source["kind"] = "archive"
            dest = os.path.join(quarantine, "src")
            os.makedirs(dest)
            if target.lower().endswith((".zip", ".skill")):
                unpack_zip(target, dest, budget)
            else:
                source["commit"] = unpack_tar(target, dest, 0, budget)
            root, inner = _single_folder(dest)
            name = inner or re.sub(r"(\.tar\.gz|\.tgz|\.tar|\.zip|\.skill)$", "",
                                   os.path.basename(target), flags=re.I)
            if inner:
                budget.links = [[rel[len(inner) + 1:], to] for rel, to in budget.links
                                if rel.startswith(inner + "/")]
        elif os.path.isfile(target) and os.path.basename(target) == "SKILL.md":
            root = os.path.dirname(os.path.realpath(target))
            name = os.path.basename(root)
        elif os.path.exists(target):
            raise ToolError("give a skill folder, a .zip or .skill file, or a GitHub address")
        else:
            hint = ""
            if re.match(r"^[\w.-]+/[\w.-]+$", target):
                hint = ". For a GitHub repository write https://github.com/" + target
            raise ToolError("not found: %s%s" % (clean_snippet(target), hint))
    except Refused as refusal:
        source["reject"] = {"rule": refusal.rule, "detail": refusal.detail}
        name = re.sub(r"(\.tar\.gz|\.tgz|\.tar|\.zip|\.skill|\.git)$", "",
                      os.path.basename(target.rstrip("/")), flags=re.I)
        root, name = quarantine, clean_snippet(name, 60) or "skill"
    source["links"] = budget.links
    source["skipped_members"] = budget.skipped
    return root, source, name


# ------------------------------------------------------------------ stages

def _limits():
    if os.name != "posix":
        return None
    try:
        import resource
    except ImportError:
        return None

    def apply():
        wanted = (("RLIMIT_CPU", LIMITS["stage_cpu"]), ("RLIMIT_AS", LIMITS["stage_mem"]),
                  ("RLIMIT_FSIZE", 512 * 1024 * 1024), ("RLIMIT_CORE", 0))
        for name, value in wanted:
            try:
                kind = getattr(resource, name)
                hard = resource.getrlimit(kind)[1]
                if hard != resource.RLIM_INFINITY:
                    value = min(value, hard)
                resource.setrlimit(kind, (value, hard))
            except (ValueError, OSError, AttributeError):
                pass
    return apply


def run_stage(name, root, work):
    """Run one stage as an isolated child. Returns its status record."""
    cmd = [sys.executable] + ISOLATION + [os.path.join(HERE, "skill_rentgen.py"),
                                          "_stage", name, root, work]
    env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8"}
    for key in ("SYSTEMROOT", "TEMP", "TMP", "TMPDIR"):
        if key in os.environ:
            env[key] = os.environ[key]
    status, detail = "ok", ""
    try:
        proc = subprocess.run(cmd, cwd=work, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              timeout=LIMITS["stage_timeout"], preexec_fn=_limits())
        if proc.returncode != 0 or not os.path.exists(os.path.join(work, name + ".json")):
            status = "failed"
            lines = proc.stderr[-4000:].decode("utf-8", "replace").strip().split("\n")
            detail = lines[-1] if lines else ""
            if proc.returncode < 0:
                detail = "stopped by signal %d" % -proc.returncode
    except subprocess.TimeoutExpired:
        status, detail = "timeout", "no result after %d seconds" % LIMITS["stage_timeout"]
    record = {"status": status}
    if status != "ok":
        record["detail"] = clean_snippet(detail)
        try:
            with open(os.path.join(work, name + ".progress"), encoding="utf-8") as handle:
                record["file"] = clean_snippet(handle.read(), 240)
        except OSError:
            pass
    return record


def stage_main(name, root, work):
    """Entry point of a child process: run one stage and write its JSON."""
    if name not in STAGES + ("verdict",):
        return 10
    opts = load_json(os.path.join(work, "run.json"))
    sys.setrecursionlimit(4000)
    module = __import__(name)
    result = module.run(root, work, opts)
    dump_json(result, os.path.join(work, name + ".json"))
    return 0


def run_stage_inline(name, root, work):
    """Same contract as run_stage, inside this process. For tests only:
    it has no isolation and no limits, so the command line never uses it."""
    try:
        stage_main(name, root, work)
        return {"status": "ok"}
    except Exception as error:  # the stage failed on its input; report it like a child would
        record = {"status": "failed",
                  "detail": clean_snippet("%s: %s" % (type(error).__name__, error))}
        try:
            with open(os.path.join(work, name + ".progress"), encoding="utf-8") as handle:
                record["file"] = clean_snippet(handle.read(), 240)
        except OSError:
            pass
        return record


def scan(target, lang="he", out_dir=None, keep=False, runner=None, then=None, copy=None):
    """Scan one skill. Returns (summary, report_dict, out_dir).

    `then`, when given, is called with (root, work, summary, report, out_dir)
    while the scanned files still exist, so that a later step works on
    exactly the bytes that were scanned."""
    started = time.time()
    runner = runner or run_stage
    quarantine = tempfile.mkdtemp(prefix="skill-rentgen-")
    try:
        work = os.path.join(quarantine, "work")
        os.makedirs(work)
        root, source, name = resolve(target, quarantine, copy)
        out_dir = os.path.abspath(out_dir or os.path.join(os.getcwd(), "skill-rentgen-report"))
        real_root, real_out = os.path.realpath(root), os.path.realpath(out_dir)
        in_place = source["kind"] == "local" or source.pop("copy", False)
        if in_place and (real_out + os.sep).startswith(real_root + os.sep):
            raise ToolError("the report folder would sit inside the skill being scanned. "
                            "Run from another folder, or pass --out")
        run = {"id": str(uuid.uuid4()), "lang": lang, "name": name, "display_root": name,
               "started_at": datetime.datetime.now(datetime.timezone.utc)
               .strftime("%Y-%m-%dT%H:%M:%SZ"), "source": source, "stages": {}}
        blocked = bool(source.get("reject"))
        for stage in STAGES:
            dump_json(run, os.path.join(work, "run.json"))
            waiting = [dep for dep in NEEDS[stage] if run["stages"][dep]["status"] != "ok"]
            if blocked or waiting:
                run["stages"][stage] = {"status": "skipped"}
                continue
            run["stages"][stage] = runner(stage, root, work)
            if stage == "intake" and run["stages"][stage]["status"] == "ok":
                blocked = bool(load_json(os.path.join(work, "intake.json")).get("reject"))
        dump_json(run, os.path.join(work, "run.json"))
        final = runner("verdict", root, work)
        if final["status"] != "ok":
            raise ToolError("could not write the report: %s" % final.get("detail", ""))
        summary = load_json(os.path.join(work, "verdict.json"))
        try:
            summary["files_sha256"] = {entry["p"]: entry["sha256"] for entry in
                                       load_json(os.path.join(work, "intake.json"))["files"]}
        except (OSError, ValueError, KeyError):
            summary["files_sha256"] = {}
        report_path = os.path.join(work, "out-%s.report.json" % summary["name"])
        report = load_json(report_path)
        report["run"]["duration_ms"] = int((time.time() - started) * 1000)
        dump_json(report, report_path)
        os.makedirs(out_dir, exist_ok=True)
        for filename in summary["files"]:
            shutil.copyfile(os.path.join(work, "out-" + filename), os.path.join(out_dir, filename))
        if then:
            then(root, work, summary, report, out_dir)
        return summary, report, out_dir
    finally:
        if keep:
            sys.stderr.write("work folder kept: %s\n" % quarantine)
        else:
            shutil.rmtree(quarantine, ignore_errors=True)


def sarif(report):
    """The findings in SARIF 2.1.0, the format code-scanning tools read."""
    level = {"red": "error", "high": "warning", "medium": "note", "low": "note", "info": "none"}
    titles = load_json(os.path.join(os.path.dirname(HERE), "i18n", "en.json"))["rules"]
    rules, results = {}, []
    for item in report["findings"]:
        rule = item["rule_id"]
        rules[rule] = {"id": rule, "shortDescription": {"text": titles[rule]["title"]},
                       "fullDescription": {"text": titles[rule]["you"] or titles[rule]["title"]},
                       "defaultConfiguration": {"level": level[item["severity"]]}}
        result = {"ruleId": rule, "level": level[item["severity"]],
                  "message": {"text": titles[rule]["title"]}}
        if item.get("file"):
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": item["file"]},
                "region": {"startLine": max(1, item.get("line") or 1)}}}]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "SkillRentgen", "version": report["tool"]["version"],
                                          "informationUri": "https://github.com/Nimrod-Zemel/skill-rentgen",
                                          "rules": [rules[key] for key in sorted(rules)]}},
                      "results": results}]}


def declaration(report):
    """A first draft of skill-capabilities.json, from what the scan observed.
    The builder fills in the purposes. A declaration never excuses a red line."""
    label = report["label"]
    by_kind = {}
    for surface in label.get("exec_surfaces", []):
        by_kind.setdefault(surface["kind"], []).append(
            {key: surface[key] for key in ("event", "command", "url", "file") if surface.get(key)})
    return {
        "schema_version": "1.0", "name": report["subject"]["name"],
        "network": [{"host": item["host"], "purpose": "", "when": ""}
                    for item in label.get("network", [])],
        "hooks": by_kind.get("hook", []), "mcp_servers": by_kind.get("mcp", []),
        "monitors": by_kind.get("monitor", []), "bin": by_kind.get("bin", []),
        "modules": by_kind.get("module", []),
        "writes_outside_skill_dir": label.get("writes_outside_skill_dir", []),
        "env_reads": label.get("env_reads", []), "subprocess": label.get("subprocess", []),
        "runtime_installs": label.get("runtime_installs", []),
        "reads_stdin": bool(label.get("reads_stdin")), "paid_services": [], "telemetry": "",
    }


def exit_code(summary, fail_on):
    code = summary["exit_code"]
    if fail_on == "block" and code == 1:
        return 0
    return code


# ---------------------------------------------------------------- registry

def current_hashes(path, runner=None):
    """Hash every file of a folder with the intake stage. None when it fails."""
    work = tempfile.mkdtemp(prefix="skill-rentgen-check-")
    try:
        dump_json({"source": {}}, os.path.join(work, "run.json"))
        record = (runner or run_stage)("intake", path, work)
        if record["status"] != "ok":
            return None
        return {entry["p"]: entry["sha256"] for entry in
                load_json(os.path.join(work, "intake.json"))["files"]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def upstream_head(url):
    """The newest commit of a GitHub repository, and whether GitHub sent us
    to another address on the way. Returns (commit or None, moved)."""
    match = GITHUB.match(url or "")
    if not match:
        return None, False
    path = "%s/%s/commits/%s" % (match.group(1), match.group(2), match.group(3) or "HEAD")
    request = urllib.request.Request(
        "https://api.github.com/repos/" + path,
        headers={"User-Agent": TOOL_NAME + "/" + TOOL_VERSION,
                 "Accept": "application/vnd.github.sha"})
    try:
        with urllib.request.build_opener(_Redirects).open(request, timeout=15) as response:
            text = response.read(100).decode("ascii", "replace").strip()
            landed = response.geturl()
    except (urllib.error.URLError, OSError, ToolError):
        return None, False
    moved = ("/repos/" + path).lower() not in landed.lower()
    return (text if re.match(r"^[0-9a-f]{40}$", text) else None), moved


plugin_installs = inventory.plugin_installs
installed = inventory.installed


def _plugin_of(path):
    real = os.path.realpath(path)
    for key, info in plugin_installs().items():
        if info["path"] == real:
            return {"key": key, "version": info["version"]}
    return {}


def _record(target, summary, report, source, how, home):
    """Write the approval of one scanned folder into the registry."""
    upstream = {}
    if source:
        if not GITHUB.match(source):
            raise ToolError("--source takes a https://github.com/owner/repo address")
        known = ((report.get("subject") or {}).get("source") or {})
        commit = known.get("commit") if known.get("url") == source else None
        if not (commit and _SHA.match(commit)):
            commit, _ = upstream_head(source)
        upstream = {"url": source, "commit": commit}
    plugin = _plugin_of(target)
    data = registry.load(home)
    accepted = report["verdict"]["reasons"] if summary["internal"] == "caution" else []
    key = registry.skill_id(target, plugin.get("key", ""))
    data["skills"][key] = registry.make_record(target, summary, report, accepted, upstream,
                                               plugin, how)
    registry.save(home, data)
    state = registry.load_state(home)
    state["full_check"][key] = registry.now()
    registry.save_state(home, state)
    return key


def adopt(target, lang, out_dir, home, accept_caution, source, runner=None, how="adopt"):
    """Scan a folder and, if the verdict allows, record it as approved."""
    if not os.path.isdir(target):
        raise ToolError("adopt works on a folder that is already on this machine")
    summary, report, out_dir = scan(target, lang, out_dir, runner=runner)
    verdict = summary["internal"]
    if verdict in ("blocked", "reject"):
        return summary, out_dir, "refused"
    if verdict == "caution" and not accept_caution:
        return summary, out_dir, "needs-acceptance"
    _record(target, summary, report, source, how, home)
    return summary, out_dir, "adopted"


def package(root, name, wanted, out_dir):
    """Write exactly the scanned files as one file a person can install:
    <name>.skill for a skill, <name>.plugin for a plugin. The file is read
    back and every member is compared with the hash from the scan.
    Returns the path, or None when the folder is neither."""
    is_plugin = os.path.isfile(os.path.join(root, ".claude-plugin", "plugin.json"))
    if not is_plugin and not os.path.isfile(os.path.join(root, "SKILL.md")):
        return None
    prefix = "" if is_plugin else name + "/"
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name + (".plugin" if is_plugin else ".skill"))
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for rel in sorted(wanted):
                source_file = os.path.join(root, rel)
                member = zipfile.ZipInfo(prefix + rel, date_time=(1980, 1, 1, 0, 0, 0))
                member.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if os.stat(source_file).st_mode & 0o111 else 0o644
                member.external_attr = (0o100000 | mode) << 16
                with open(source_file, "rb") as handle:
                    archive.writestr(member, handle.read())
        with zipfile.ZipFile(path) as archive:
            names = sorted(archive.namelist())
            same = names == sorted(prefix + rel for rel in wanted) and all(
                hashlib.sha256(archive.read(prefix + rel)).hexdigest() == wanted[rel]
                for rel in wanted)
    except (OSError, zipfile.BadZipFile, KeyError) as error:
        same = False
        detail = clean_snippet(str(error), 100)
    else:
        detail = "the file does not match what was scanned"
    if not same:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise ToolError("could not write the package: %s; nothing was written" % detail)
    return path


def add(target, lang, out_dir, home, accept_caution, project=False, replace=False, runner=None,
        copy=None, as_file=False):
    """Scan a skill and, if the verdict allows, install exactly the bytes
    that were scanned, then record them. Returns (summary, out_dir, outcome, where)."""
    box = {}
    base = os.path.join(os.getcwd() if project else os.path.expanduser("~"), ".claude", "skills")

    def install(root, work, summary, report, report_dir):
        verdict = summary["internal"]
        if verdict in ("blocked", "reject"):
            box["outcome"] = "refused"
            return
        if verdict == "caution" and not accept_caution:
            box["outcome"] = "needs-acceptance"
            return
        name = re.sub(r"[^A-Za-z0-9._-]", "-", summary["name"]).strip(".-") or "skill"
        if as_file:
            made = package(root, name, summary.get("files_sha256", {}), report_dir)
            box["outcome"], box["where"] = ("packaged", made) if made else ("not-one-skill", "")
            return
        if not os.path.isfile(os.path.join(root, "SKILL.md")):
            box["outcome"] = "plugin" if os.path.isdir(os.path.join(root, ".claude-plugin")) \
                else "not-one-skill"
            return
        dest = os.path.join(base, name)
        if os.path.lexists(dest) and not replace:
            box["outcome"], box["where"] = "exists", dest
            return
        os.makedirs(base, exist_ok=True)
        staging = tempfile.mkdtemp(prefix=".skill-rentgen-add-", dir=base)
        try:
            wanted = summary.get("files_sha256", {})
            for rel in wanted:
                source_file = os.path.join(root, rel)
                copy = os.path.join(staging, "skill", rel)
                os.makedirs(os.path.dirname(copy), exist_ok=True)
                shutil.copyfile(source_file, copy)
                if os.stat(source_file).st_mode & 0o111:
                    os.chmod(copy, 0o755)
            copied = current_hashes(os.path.join(staging, "skill"), runner)
            if copied != wanted:
                raise ToolError("the copy does not match what was scanned; nothing was installed")
            old = os.path.join(staging, "old")
            had_old = os.path.lexists(dest)
            if had_old:
                os.rename(dest, old)
            try:
                os.rename(os.path.join(staging, "skill"), dest)
            except OSError:
                if had_old:
                    os.rename(old, dest)  # put back what was there
                raise ToolError("could not put the skill in place; nothing was changed")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        source = target if GITHUB.match(target) else None
        if source and "/tree/" in source:
            source = source.split("/tree/")[0]
        _record(dest, summary, report, source, "add", home)
        box["outcome"], box["where"] = "installed", dest

    summary, _, out_dir = scan(target, lang, out_dir, runner=runner, then=install, copy=copy)
    return summary, out_dir, box.get("outcome", "refused"), box.get("where", "")


def baseline(home, lang, out_dir, runner=None, settings=True):
    """Scan everything installed that has no record yet, and record what
    passes. Also takes a fingerprint of the agent settings. Returns rows."""
    data = registry.load(home)
    known = {record.get("path") for record in data["skills"].values()}
    rows = []
    for item in installed():
        if item["path"] in known:
            continue
        try:
            summary, _, outcome = adopt(item["path"], lang, out_dir, home, False, None, runner,
                                        "baseline")
            rows.append({"name": item["name"], "path": item["path"], "kind": item["kind"],
                         "outcome": outcome, "verdict": summary["internal"]})
        except ToolError as error:
            rows.append({"name": item["name"], "path": item["path"], "kind": item["kind"],
                         "outcome": "error", "verdict": "", "detail": clean_snippet(str(error))})
    if settings:
        data = registry.load(home)
        data["agent_settings"] = {"recorded_at": registry.now(),
                                  "files": registry.settings_fingerprint(registry.settings_files())}
        registry.save(home, data)
    return rows


def check(home, name="", lang="he", out_dir=None, hook=False, upstream=False, runner=None):
    """Compare every approved skill to its record, scan again what changed,
    and write the report. Returns (changes, files_written, extras) where
    extras holds the skills never checked and the agent settings that changed."""
    if name and not any(name in (key, record.get("name"))
                        for key, record in registry.load(home)["skills"].items()):
        raise ToolError("no approved skill is called %s. See the names with: list"
                        % clean_snippet(name, 60))
    changes, extras, data = watch.compare(home, name, hook, upstream_head if upstream else None)
    written = []
    if hook:
        return changes, written, extras
    for item in changes:
        if item["status"] in ("changed", "tampered", "updated", "rules"):
            try:
                summary, _, _ = scan(item["path"], lang, out_dir, runner=runner)
                item["verdict_now"] = summary["internal"]
            except ToolError:
                item["verdict_now"] = "error"
    out_dir = os.path.abspath(out_dir or os.path.join(os.getcwd(), "skill-rentgen-report"))
    os.makedirs(out_dir, exist_ok=True)
    report_file = os.path.join(out_dir, "changes.%s.md" % lang)
    with open(report_file, "w", encoding="utf-8") as handle:
        handle.write(registry.change_report(changes, lang, extras["unknown"], extras["settings"]))
    written.append(report_file)
    email = data["settings"].get("email")
    if email and (changes or extras["settings"]):
        mail_file = os.path.join(out_dir, "alert-email.txt")
        with open(mail_file, "w", encoding="utf-8") as handle:
            handle.write(registry.email_draft(changes, email, lang, extras["unknown"],
                                              extras["settings"]))
        written.append(mail_file)
    return changes, written, extras


def carry_out(home, out_dir, force=False):
    """On a machine whose disk does not last, write the registry as one
    small file next to the reports, so it can be kept elsewhere.
    Returns (path, sign) or None."""
    sign = registry.short_lived()
    if not (sign or force):
        return None
    out_dir = os.path.abspath(out_dir or os.path.join(os.getcwd(), "skill-rentgen-report"))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, registry.CARRY_NAME)
    dump_json(registry.export_data(home), path)
    return path, sign


def _say_carry(made):
    if made:
        print("This machine does not keep its disk between sessions (%s is set). The registry "
              "was also written to one small file: %s" % (made[1], made[0]))
        print("Keep that file somewhere that lasts. Next time, start with: registry import <file>")


# ----------------------------------------------------------------- helpers

BLOCK_NAME = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,79}$")


def block(name, undo=False, yes=False, project=None):
    """Add (or remove) a deny rule for one skill in the project's local
    settings file, so the agent will not start it there. Best effort: it
    does not remove a plugin's hooks or servers, and it does not undo what
    already ran in this session. Returns (path, rules, changed)."""
    if not BLOCK_NAME.match(name or ""):
        raise ToolError("give the skill's name as the agent shows it, for example: pdf-tools")
    path = os.path.join(project or os.getcwd(), ".claude", "settings.local.json")
    rules = ["Skill(%s)" % name, "Skill(%s *)" % name]
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError):
        raise ToolError("%s is not valid JSON, so it was left untouched" % path)
    if not isinstance(data, dict) or not isinstance(data.get("permissions", {}), dict) or \
            not isinstance(data.get("permissions", {}).get("deny", []), list):
        raise ToolError("%s has a shape this tool does not edit, so it was left untouched" % path)
    deny = list(data.get("permissions", {}).get("deny", []))
    wanted = [r for r in deny if r not in rules] if undo else deny + [r for r in rules if r not in deny]
    if wanted == deny or not yes:
        return path, rules, False
    data.setdefault("permissions", {})["deny"] = wanted
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return path, rules, True


def plugin_doctor(which=shutil.which):
    """Ask claude-plugin-doctor (cpd, by Yaniv Golan), when it is installed,
    which copies of each plugin exist on this machine and which are out of
    step. Claude Code and Claude Cowork keep a plugin in several places, and
    the copy that runs is not always the one that was updated.
    Returns {"status", "copies": [...], "stale": [...]}. Reads only."""
    program = which("cpd")
    if not program:
        return {"status": "absent", "copies": [], "stale": []}
    try:
        proc = subprocess.run([program, "list", "--json", "--no-log-file"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=180)
        data = json.loads(proc.stdout[:16 * 1024 * 1024].decode("utf-8", "replace"))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"status": "failed", "copies": [], "stale": []}
    if not isinstance(data, dict) or data.get("ok") is False:
        return {"status": "failed", "copies": [], "stale": [],
                "code": clean_snippet(str((data or {}).get("code", "")) if isinstance(data, dict)
                                      else "", 60)}
    copies, stale = [], []
    for plugin in data.get("plugins") or []:
        if not isinstance(plugin, dict):
            continue
        name = clean_snippet(str(plugin.get("id") or plugin.get("pluginName") or ""), 80)
        for scope in plugin.get("scopes") or []:
            folder = scope.get("installPath") if isinstance(scope, dict) else None
            if isinstance(folder, str):
                copies.append({"name": name, "path": folder, "layer": "install",
                               "version": clean_snippet(str(scope.get("version") or ""), 40)})
        checks = plugin.get("checks") if isinstance(plugin.get("checks"), dict) else {}
        late = sorted(clean_snippet(str(layer), 40) for layer, result in checks.items()
                      if isinstance(result, dict) and result.get("status") == "stale")
        if late:
            stale.append({"name": name, "layers": late})
    for root in data.get("coworkRoots") or []:
        folder = root.get("path") if isinstance(root, dict) else None
        if not isinstance(folder, str):
            continue
        for key, info in plugin_installs(folder).items():
            copies.append({"name": key, "path": info["path"], "layer": "cowork",
                           "version": info["version"]})
        personal = os.path.join(folder, "rpm")
        try:
            names = sorted(os.listdir(personal))[:200]
        except OSError:
            names = []
        for entry in names:
            if os.path.isfile(os.path.join(personal, entry, ".claude-plugin", "plugin.json")):
                copies.append({"name": entry, "path": os.path.join(personal, entry),
                               "layer": "cowork-personal", "version": ""})
    return {"status": "ok", "copies": copies, "stale": stale}


# ------------------------------------------------------------------- trial

def _save_text(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def trial_command(args):
    """The three uses of `trial`: run in a container, write an agent pack,
    or read an agent result."""
    langs = ("he", "en") if args.lang == "both" else (args.lang,)
    if args.agent_result:
        out_dir = os.path.abspath(args.out or "skill-rentgen-report")
        try:
            runs = agent_trial.load_results(args.agent_result)
        except (OSError, ValueError) as error:
            raise ToolError("could not read the agent result: %s" % clean_snippet(str(error)))
        os.makedirs(out_dir, exist_ok=True)
        worst = 0
        for index, run in enumerate(runs, 1):
            findings, facts = agent_trial.judge_result(run)
            findings = trial_mod.tidy(findings)
            verdict = trial_mod.decide(findings)
            safe = re.sub(r"[^A-Za-z0-9._-]", "-", facts["scenario"])[:60] or "agent-%d" % index
            for code in langs:
                path = _save_text(os.path.join(out_dir, "%s.agent-trial.%s.md" % (safe, code)),
                                  agent_trial.render_result(facts, findings, code))
            print("AGENT TRIAL  %s  %s  %d seen" % (
                {"quiet": "NOTHING SEEN", "notes": "NOTES", "caution": "CAUTION",
                 "blocked": "DO NOT INSTALL"}[verdict], facts["tier"] or "?",
                len([f for f in findings if f["severity"] != "info"])))
            print("Report: %s" % path)
            worst = max(worst, trial_mod.EXIT[verdict])
        return 0 if (worst == 1 and args.fail_on == "block") else worst
    if not args.target:
        raise ToolError("give a skill to try, or --agent-result FILE")
    if not 5 <= args.timeout <= 120:
        raise ToolError("--timeout takes 5 to 120 seconds")
    box = {}

    def after(root, work, summary, report, out_dir):
        name = summary["name"]
        if args.agent_pack:
            try:
                names = [item.get("name") or "" for item in
                         load_json(os.path.join(work, "structure.json")).get("skills", [])]
            except (OSError, ValueError):
                names = []
            if summary["internal"] == "reject":
                box["pack_error"] = "the scan refused this skill at intake"
                return
            try:
                box["pack"], box["removed"] = agent_trial.build_pack(
                    root, name, [n for n in names if n], out_dir, args.lang,
                    "container" if args.own_skill else "microvm", args.prompt,
                    os.path.join(HERE, "skill_rentgen.py"), summary["internal"])
            except agent_trial.PackRefused as error:
                box["pack_error"] = str(error)
            return
        if summary["internal"] == "reject":
            record = trial_mod.not_run(name, "rejected")
        else:
            declared = [item["host"] for item in (report.get("label") or {}).get("network", [])
                        if item.get("declared")]
            record = trial_mod.run(root, work, name, declared, args.run or (), not args.no_scripts,
                                   args.engine, args.image, args.timeout,
                                   start=args.start_engine)
        for code in langs:
            box["report"] = _save_text(os.path.join(out_dir, "%s.trial.%s.md" % (name, code)),
                                       trial_mod.render(record, code))
        dump_json(record, os.path.join(out_dir, "%s.trial.json" % name))
        box["trial"] = record

    summary, report, out_dir = scan(args.target, args.lang, args.out, False, then=after,
                                    copy=args.copy)
    static = exit_code(summary, args.fail_on)
    if args.agent_pack:
        print("\n".join(summary["terminal"]))
        if box.get("pack_error"):
            raise ToolError("no agent pack was written: %s" % box["pack_error"])
        print("Agent trial pack: %s (%d items removed from the copy)" % (
            box["pack"], len(box["removed"])))
        return static
    record = box["trial"]
    if args.output_format == "json":
        json.dump({"scan": report, "trial": record}, sys.stdout, ensure_ascii=False, indent=2,
                  sort_keys=True)
        sys.stdout.write("\n")
    else:
        print("\n".join(summary["terminal"]))
        print("Report: %s" % os.path.join(out_dir, summary["primary"]))
        print(trial_mod.terminal(record))
        print("Trial report: %s" % box["report"])
    code = record["exit_code"]
    if code == 1 and args.fail_on == "block":
        code = 0
    return max(static, code)


# --------------------------------------------------------------------- cli

def main(argv):
    if len(argv) >= 4 and argv[0] == "_stage":
        return stage_main(argv[1], argv[2], argv[3])
    parser = argparse.ArgumentParser(prog="skill_rentgen.py", description=(
        "Check an agent skill before you install it. Reads the skill, never runs it."))
    commands = parser.add_subparsers(dest="command")
    scan_cmd = commands.add_parser("scan", help="check one skill")
    scan_cmd.add_argument("target", help="a folder, a .zip or .skill file, or https://github.com/owner/repo")
    inventory_cmd = commands.add_parser("inventory", help="list the skills already on this machine")
    inventory_cmd.add_argument("--scan", action="store_true", help="also check each one")
    inventory_cmd.add_argument("--doctor", action="store_true",
                               help="also ask claude-plugin-doctor (cpd), if installed, for every "
                                    "copy of each plugin, including the ones Claude Cowork keeps")
    report_cmd = commands.add_parser("report", help="print a saved report")
    report_cmd.add_argument("name")
    for cmd in (scan_cmd, inventory_cmd, report_cmd):
        cmd.add_argument("--lang", choices=("he", "en", "both"), default="he")
        cmd.add_argument("--out", help="folder for the reports (default: ./skill-rentgen-report)")
    for cmd in (scan_cmd, inventory_cmd):
        cmd.add_argument("--output-format", choices=("text", "json", "sarif"), default="text")
        cmd.add_argument("--fail-on", choices=("caution", "block"), default="caution")
        cmd.add_argument("--keep-work", action="store_true", help=argparse.SUPPRESS)
    adopt_cmd = commands.add_parser("adopt", help="scan a skill and record it as approved")
    adopt_cmd.add_argument("target", help="the folder of an installed skill or plugin")
    adopt_cmd.add_argument("--accept-caution", action="store_true",
                           help="record a skill whose verdict is caution, after you read the report")
    adopt_cmd.add_argument("--source", help="the GitHub address it came from, to watch for updates")
    add_cmd = commands.add_parser(
        "add", help="scan a skill and, if it passes, install exactly what was scanned")
    add_cmd.add_argument("target", help="a skill folder, an archive, or its GitHub address")
    add_cmd.add_argument("--accept-caution", action="store_true",
                         help="install a skill whose verdict is caution, after you read the report")
    add_cmd.add_argument("--project", action="store_true",
                         help="install into ./.claude/skills instead of ~/.claude/skills")
    add_cmd.add_argument("--replace", action="store_true", help="replace a skill of the same name")
    add_cmd.add_argument("--as-file", action="store_true",
                         help="do not install here: write exactly the scanned files as one "
                              ".skill or .plugin file to install. This is what happens by "
                              "itself on a machine that does not keep its disk")
    baseline_cmd = commands.add_parser(
        "baseline", help="check everything installed that has no record yet, and record what passes")
    check_cmd = commands.add_parser("check", help="see whether approved skills changed")
    check_cmd.add_argument("name", nargs="?", default="")
    check_cmd.add_argument("--hook", action="store_true",
                           help="one short line for the start of a session; never fails")
    check_cmd.add_argument("--upstream", action="store_true",
                           help="also ask GitHub whether a newer version exists")
    list_cmd = commands.add_parser("list", help="list the skills you approved")
    notify_cmd = commands.add_parser("notify", help="set the address for alert drafts")
    notify_cmd.add_argument("--email")
    notify_cmd.add_argument("--clear", action="store_true")
    registry_cmd = commands.add_parser(
        "registry", help="carry the registry to another machine or session as one small file")
    registry_actions = registry_cmd.add_subparsers(dest="action")
    export_cmd = registry_actions.add_parser("export", help="write the registry as one file")
    export_cmd.add_argument("--to", metavar="FILE", help="default: ./skill-rentgen-report/%s"
                            % registry.CARRY_NAME)
    import_cmd = registry_actions.add_parser("import", help="take approvals from such a file")
    import_cmd.add_argument("file")
    import_cmd.add_argument("--replace", action="store_true",
                            help="drop what is here first, instead of keeping the newer record")
    where_cmd = registry_actions.add_parser("where", help="say where the registry is and what it holds")
    for cmd in (adopt_cmd, check_cmd, list_cmd, notify_cmd, add_cmd, baseline_cmd, export_cmd,
                import_cmd, where_cmd):
        cmd.add_argument("--home", help="registry folder (default: SKILL_RENTGEN_HOME, "
                                        "or ~/.skill-rentgen)")
    for cmd in (adopt_cmd, check_cmd, add_cmd, baseline_cmd):
        cmd.add_argument("--lang", choices=("he", "en"), default=None)
        cmd.add_argument("--out", help="folder for the reports (default: ./skill-rentgen-report)")
    for cmd in (check_cmd, list_cmd, baseline_cmd):
        cmd.add_argument("--output-format", choices=("text", "json"), default="text")
    declare_cmd = commands.add_parser(
        "declare", help="for builders: draft a skill-capabilities.json from what a scan observes")
    declare_cmd.add_argument("target", help="the folder of your own skill or plugin")
    declare_cmd.add_argument("--out", help="folder for the scan reports")
    for word, text in (("block", "stop the agent from starting one skill in this project"),
                       ("unblock", "remove that rule again")):
        cmd = commands.add_parser(word, help=text)
        cmd.add_argument("name", help="the skill's name, as the agent shows it")
        cmd.add_argument("--yes", action="store_true",
                         help="write the change. Without it the command only shows what it would do")
    trial_cmd = commands.add_parser(
        "trial", help="start the skill's own commands in a sealed container and report what they tried")
    trial_cmd.add_argument("target", nargs="?", help="a folder, an archive, or a GitHub address")
    trial_cmd.add_argument("--run", action="append", metavar="COMMAND",
                           help="one more command to start inside the sandbox (repeatable)")
    trial_cmd.add_argument("--no-scripts", action="store_true",
                           help="do not start the scripts that the instructions point to")
    trial_cmd.add_argument("--engine", choices=trial_mod.ENGINES, help="default: the first that answers")
    trial_cmd.add_argument("--image", help="sandbox image (default: %s; when it cannot be fetched, "
                                           "on Linux: this machine's own programs, read-only. "
                                           "`host` asks for that directly)" % trial_mod.DEFAULT_IMAGE)
    trial_cmd.add_argument("--start-engine", action="store_true",
                           help="when Docker is installed and its service is not running: start "
                                "the service for this run and stop it afterwards (Linux, as root)")
    trial_cmd.add_argument("--timeout", type=int, default=15, help="seconds for each command (5 to 120)")
    trial_cmd.add_argument("--agent-pack", action="store_true",
                           help="write a pack for an agent trial in cowork-harness, and start nothing")
    trial_cmd.add_argument("--own-skill", action="store_true",
                           help="with --agent-pack: the skill is yours, so the container tier is enough")
    trial_cmd.add_argument("--prompt", help="with --agent-pack: the request the agent gets")
    trial_cmd.add_argument("--agent-result", metavar="FILE",
                           help="read a result file that cowork-harness wrote")
    trial_cmd.add_argument("--lang", choices=("he", "en", "both"), default="he")
    trial_cmd.add_argument("--out", help="folder for the reports (default: ./skill-rentgen-report)")
    trial_cmd.add_argument("--output-format", choices=("text", "json"), default="text")
    trial_cmd.add_argument("--fail-on", choices=("caution", "block"), default="caution")
    for cmd in (scan_cmd, add_cmd, trial_cmd):
        cmd.add_argument("--copy", metavar="FOLDER",
                         help="with a GitHub address: a folder that already holds a copy of that "
                              "repository. The copy is read; nothing is downloaded")
    commands.add_parser("version", help="print the version")
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

    if args.command == "version":
        print("%s %s" % (TOOL_NAME, TOOL_VERSION))
        return 0
    if args.command == "report":
        folder = os.path.abspath(args.out or "skill-rentgen-report")
        lang = "he" if args.lang == "both" else args.lang
        name = re.sub(r"[^A-Za-z0-9._-]", "-", args.name)
        try:
            with open(os.path.join(folder, "%s.%s.md" % (name, lang)), encoding="utf-8") as handle:
                sys.stdout.write(handle.read())
        except OSError:
            raise ToolError("no saved report for %s in %s" % (name, folder))
        return 0
    if args.command == "scan":
        summary, report, out_dir = scan(args.target, args.lang, args.out, args.keep_work,
                                        copy=args.copy)
        if args.output_format in ("json", "sarif"):
            json.dump(report if args.output_format == "json" else sarif(report), sys.stdout,
                      ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print("\n".join(summary["terminal"]))
            print("Report: %s" % os.path.join(out_dir, summary["primary"]))
        return exit_code(summary, args.fail_on)
    if args.command == "trial":
        return trial_command(args)
    if args.command in ("block", "unblock"):
        path, rules, changed = block(args.name, undo=args.command == "unblock", yes=args.yes)
        verb = "Removed from" if args.command == "unblock" else "Added to"
        if changed:
            print("%s %s: %s" % (verb, path, ", ".join(rules)))
            print("It takes effect in the next session. A plugin's hooks and servers are not "
                  "stopped by this rule; disable the plugin itself for that.")
            return 0
        if args.yes:
            print("Nothing to change in %s" % path)
            return 0
        print("Would change %s (permissions.deny): %s" % (path, ", ".join(rules)))
        print("Nothing was written. Run again with --yes to write it.")
        return 1
    if args.command == "declare":
        summary, report, _ = scan(args.target, "en", args.out, False)
        if not report["label"]:
            raise ToolError("the scan stopped at intake, so there is nothing to declare")
        json.dump(declaration(report), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        sys.stderr.write("Draft only. Fill in every purpose, check each line, and save it as "
                         "skill-capabilities.json next to SKILL.md.\n")
        return 0
    if args.command == "registry":
        if not args.action:
            raise ToolError("say what to do: registry export, registry import <file>, or registry where")
        home = registry.home_dir(args.home)
        if args.action == "export":
            if args.to:
                path = os.path.abspath(args.to)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                dump_json(registry.export_data(home), path)
            else:
                path = carry_out(home, None, force=True)[0]
            print("Registry written to: %s (%d approved)" % (path, len(registry.load(home)["skills"])))
            print("It holds names, paths and hashes, and no file of any skill. "
                  "Load it elsewhere with: registry import <file>")
            return 0
        if args.action == "import":
            try:
                result = registry.import_data(home, registry.read_carry(args.file), args.replace)
            except ValueError as error:
                raise ToolError("nothing was taken: %s" % error)
            print("Taken: %d approvals written %s. Kept %d newer records that were already here."
                  % (result["taken"], result["exported_at"] or "at an unknown time", result["kept"]))
            if result["dropped"]:
                print("Left out: %d entries that are not valid records." % result["dropped"])
            print("An approval is tied to the folder the skill was in. Run `check` to compare "
                  "what is installed here with what was approved.")
            return 0
        data = registry.load(home)
        sign = registry.short_lived()
        print("Registry folder: %s (%s)" % (home, "exists" if os.path.isfile(
            registry.registry_path(home)) else "nothing saved here yet"))
        print("Approved: %d. Agent settings fingerprint: %s" % (
            len(data["skills"]), "saved" if data["agent_settings"] else "none"))
        print("Disk: %s" % ("does not last beyond this session (%s is set). Keep the registry "
                            "with `registry export`, load it with `registry import`" % sign
                            if sign else "kept between sessions, as far as this tool can tell"))
        return 0
    if args.command in ("adopt", "check", "list", "notify", "add", "baseline"):
        home = registry.home_dir(args.home)
        settings = registry.load(home)["settings"]
        lang = getattr(args, "lang", None) or settings.get("lang") or "he"
        if (args.command in ("check", "list", "baseline") and not getattr(args, "hook", False)
                and registry.short_lived() and not os.path.isfile(registry.registry_path(home))):
            sys.stderr.write("No registry in this session yet. If you kept a registry file from an "
                             "earlier session, load it first: registry import <file>\n")
    if args.command == "notify":
        data = registry.load(home)
        if args.clear:
            data["settings"].pop("email", None)
        elif args.email and re.match(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$", args.email):
            data["settings"]["email"] = args.email
        else:
            raise ToolError("give --email with one address, or --clear")
        registry.save(home, data)
        print("Alert drafts go to: %s" % data["settings"].get("email", "nobody"))
        return 0
    if args.command == "list":
        records = registry.load(home)["skills"]
        if args.output_format == "json":
            json.dump(records, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        elif not records:
            print("Nothing approved yet. Use: adopt <folder>")
        else:
            for key, record in sorted(records.items(), key=lambda kv: kv[1].get("name", "")):
                verdict = record.get("verdict", "")
                if record.get("accepted"):
                    verdict += " (accepted: %s)" % ", ".join(record["accepted"][:4])
                print("%-28s %-18s %s  %d files  %s" % (
                    record.get("name", key), verdict,
                    record.get("adopted_at", "")[:10],
                    len(record.get("files") or {}) or record.get("file_count", 0),
                    record.get("path", "")))
        return 0
    if args.command == "add":
        sign = registry.short_lived()
        as_file = args.as_file or bool(sign and not args.project)
        summary, out_dir, outcome, where = add(args.target, lang, args.out, home,
                                               args.accept_caution, args.project, args.replace,
                                               copy=args.copy, as_file=as_file)
        print("\n".join(summary["terminal"]))
        print("Report: %s" % os.path.join(out_dir, summary["primary"]))
        if outcome == "installed":
            print("Installed and recorded: %s" % where)
            _say_carry(carry_out(home, out_dir))
            return 0
        if outcome == "packaged":
            if sign and not args.as_file:
                print("This machine does not keep its disk between sessions (%s is set), so "
                      "installing into it would not last." % sign)
            print("Packaged, exactly the files that were scanned: %s" % where)
            print("Hand that file to the person to install. Once it is installed, run `baseline` "
                  "to record it and start watching it.")
            return 0
        print({"refused": "Not installed. The verdict is: do not install.",
               "needs-acceptance": "Not installed yet. Read the report. If you accept what it "
                                   "says, run again with --accept-caution",
               "plugin": "Not installed: this is a plugin. Install it with the agent's own "
                         "/plugin install command, then run: adopt <its folder>",
               "not-one-skill": "Not installed: this folder is not one skill. Point at the "
                                "folder that holds a SKILL.md",
               "exists": "Not installed: %s already exists. Add --replace to replace it" % where,
               }[outcome])
        return {"refused": 2, "needs-acceptance": 1}.get(outcome, 10)
    if args.command == "baseline":
        rows = baseline(home, lang, args.out)
        if args.output_format == "json":
            json.dump(rows, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            for row in rows:
                print("%-18s %-7s %-28s %s" % ({"adopted": "RECORDED", "refused": "DO NOT INSTALL",
                                                "needs-acceptance": "CAUTION, NOT RECORDED",
                                                "error": "TOOL ERROR"}[row["outcome"]],
                                               row["kind"], row["name"], row["path"]))
            print("%d checked, %d recorded. Agent settings fingerprint saved." % (
                len(rows), sum(1 for row in rows if row["outcome"] == "adopted")))
            _say_carry(carry_out(home, args.out))
        if any(row["outcome"] == "refused" for row in rows):
            return 2
        return 1 if any(row["outcome"] == "needs-acceptance" for row in rows) else 0
    if args.command == "adopt":
        summary, out_dir, outcome = adopt(args.target, lang, args.out, home,
                                          args.accept_caution, args.source)
        print("\n".join(summary["terminal"]))
        print("Report: %s" % os.path.join(out_dir, summary["primary"]))
        if outcome == "refused":
            print("Not recorded. The verdict is: do not install.")
            return 2
        if outcome == "needs-acceptance":
            print("Not recorded yet. Read the report. If you accept what it says, "
                  "run again with --accept-caution")
            return 1
        print("Recorded as approved: %s (%d files)" % (summary["name"],
                                                       len(summary.get("files_sha256", {}))))
        _say_carry(carry_out(home, out_dir))
        return 0
    if args.command == "check":
        if args.hook:
            try:
                line = watch.session_line(home, lang)
                if line:
                    print(line)
            except Exception:  # a session must never fail to start because of this check
                pass
            return 0
        changes, written, extras = check(home, args.name, lang, args.out, upstream=args.upstream)
        if args.output_format == "json":
            json.dump({"changes": changes, "never_checked": extras["unknown"],
                       "settings": extras["settings"]}, sys.stdout, ensure_ascii=False, indent=2,
                      sort_keys=True)
            sys.stdout.write("\n")
        else:
            total = len(registry.load(home)["skills"])
            print("%d approved, %d changed, %d never checked, %d settings changes" % (
                total, len(changes), len(extras["unknown"]),
                sum(len(item["keys"]) for item in extras["settings"])))
            for item in changes:
                print("  %-9s %s  +%d -%d ~%d  %s" % (
                    item["status"].upper(), item["name"], len(item["added"]),
                    len(item["removed"]), len(item["changed"]), item.get("verdict_now", "")))
            for item in extras["settings"]:
                print("  SETTINGS  %s  %s" % (item["path"], ", ".join(item["keys"])))
            for path in written:
                print("Wrote: %s" % path)
        if any(item.get("verdict_now") in ("blocked", "reject") for item in changes) or any(
                item["status"] == "tampered" for item in changes):
            return 2
        return 1 if (changes or extras["settings"]) else 0
    if args.command == "inventory":
        items = installed()
        doctor = plugin_doctor() if args.doctor else None
        if doctor:
            seen_paths = {item["path"] for item in items}
            for copy in doctor["copies"]:
                real = os.path.realpath(copy["path"])
                if real in seen_paths or not os.path.isdir(real):
                    continue
                seen_paths.add(real)
                items.append({"kind": "plugin", "where": copy["layer"], "path": real,
                              "name": copy["name"].split("@")[0], "version": copy["version"],
                              "found_by": "claude-plugin-doctor"})
        worst = 0
        for item in items:
            if not args.scan:
                continue
            try:
                summary, _, _ = scan(item["path"], args.lang, args.out, False)
                item["verdict"] = summary["terminal"][0].split("  ")[0]
                item["report"] = summary["primary"]
                worst = max(worst, exit_code(summary, args.fail_on))
            except ToolError as error:
                item["verdict"] = "TOOL ERROR"
                item["error"] = clean_snippet(str(error))
                worst = max(worst, 10)
        if args.output_format == "json":
            json.dump({"items": items, "doctor": doctor} if doctor else items, sys.stdout,
                      ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        elif not items:
            print("No skills or plugins found in ~/.claude, ./.claude, ~/.agents or ./.agents")
        else:
            for item in items:
                print("%-22s %-7s %-15s %s  %s" % (item.get("verdict", "").upper(), item["kind"],
                                                   item["where"], item["name"], item["path"]))
            twice = sorted({item["name"] for item in items if item.get("shadowed")})
            if twice:
                print("Same name in two places, so only one of them is the one your agent uses: %s"
                      % ", ".join(twice))
            if not args.scan:
                print("%d found. Add --scan to check each one." % len(items))
        if doctor and args.output_format != "json":
            if doctor["status"] == "absent":
                print("claude-plugin-doctor (cpd) is not installed, so only the copies Claude Code "
                      "lists are shown. On a Mac it also finds the copies Claude Cowork keeps: "
                      "npm i -g claude-plugin-doctor")
            elif doctor["status"] == "failed":
                print("claude-plugin-doctor did not answer. Only the copies Claude Code lists are shown.")
            else:
                print("claude-plugin-doctor: %d plugin copies on this machine, %d out of step" % (
                    len(doctor["copies"]), len(doctor["stale"])))
                for entry in doctor["stale"][:20]:
                    print("  OUT OF STEP  %s  (%s). Run cpd for the fix." % (
                        entry["name"], ", ".join(entry["layers"])))
        return worst
    parser.print_help()
    return 10


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ToolError as error:
        sys.stderr.write("skill-rentgen: %s\n" % error)
        sys.exit(10)
    except KeyboardInterrupt:
        sys.exit(130)
