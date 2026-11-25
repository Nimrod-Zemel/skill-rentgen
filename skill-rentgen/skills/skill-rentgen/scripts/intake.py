"""Stage 0: intake. Walk the skill, classify every file, hash it.

WHY: a scanner that trusts the tree it is handed can be pointed at the
user's own files through a symlink, drowned in 200,000 files, or shown one
file while a second file with the same name in another case gets installed.
Nothing here opens a file for analysis; it only measures and classifies.

Rules that tests check:
1. A symlink is never followed. An absolute target, or a target that names a
   credentials folder, rejects the intake.
2. Two paths that differ only by case or Unicode form reject the intake.
3. Past the soft limits the scan is marked partial; past the hard limits it
   is rejected.
4. An executable binary, or a .pyc with no matching .py, is a red line.
5. computed_hash matches the skills.sh lock v2 algorithm (see tests).
"""
from __future__ import annotations

import hashlib
import os
import stat
import unicodedata

from common import LIMITS, finding

PY = {".py", ".pyw", ".pyi"}
SH = {".sh", ".bash", ".zsh", ".fish", ".ksh", ".command"}
JS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
WIN = {".ps1", ".psm1", ".bat", ".cmd"}
OTHER = {".rb", ".go", ".rs", ".php", ".pl", ".pm", ".lua", ".java", ".kt", ".kts", ".c",
         ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".m", ".r", ".jl", ".ex", ".exs",
         ".scala", ".clj", ".hs", ".dart", ".vb", ".groovy", ".tcl", ".applescript",
         ".nim", ".zig", ".ipynb"}
DOC = {".md", ".mdx", ".markdown", ".txt", ".rst", ".adoc", ".mdc"}
SHELL_NAMES = {"makefile", "gnumakefile", "dockerfile", "justfile", "containerfile"}
EXEC_EXT = {".so", ".dylib", ".dll", ".exe", ".jar", ".class", ".wasm", ".node", ".o", ".a",
            ".bin", ".app", ".msi", ".deb", ".rpm", ".dmg", ".pkg"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".whl"}
DOCUMENT_EXT = {".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".odt", ".ods",
                ".odp", ".epub", ".key", ".pages", ".numbers", ".xlsm", ".dotx", ".potx"}
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".icns", ".tif",
             ".tiff", ".heic", ".avif", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".mp3",
             ".wav", ".ogg", ".flac", ".m4a", ".mp4", ".mov", ".webm", ".mkv", ".avi", ".psd"}
EXEC_MAGIC = (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
              b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x00asm")
CRED_PARTS = {".ssh", ".aws", ".gnupg", ".kube", ".docker", ".netrc", ".env", ".config",
              ".claude", ".gemini", "keychains", ".npmrc", ".pypirc", ".git-credentials"}
HASH_SKIP_FILES = {"metadata.json"}
HASH_SKIP_DIRS = {".git", "__pycache__", "__pypackages__"}


def classify(name, head):
    """Return (kind, lang) for a file from its name and first bytes."""
    lower = name.lower()
    ext = os.path.splitext(lower)[1]
    if ext in (".pyc", ".pyo"):
        return "bytecode", ""
    binary = b"\x00" in head
    if binary:
        if head.startswith(EXEC_MAGIC) or (head[:2] == b"MZ" and ext not in MEDIA_EXT):
            return "exec-binary", ""
        if ext in EXEC_EXT and ext not in (".bin", ".o", ".a", ".app"):
            return "exec-binary", ""
        if ext in DOCUMENT_EXT or head.startswith(b"%PDF"):
            return "document", ""
        if ext in ARCHIVE_EXT:
            return "archive", ""
        if ext in MEDIA_EXT:
            return "asset", ""
        if head.startswith((b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"\xfd7zXZ")):
            return "archive", ""
        if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OTTO", b"wOFF",
                            b"wOF2", b"ID3", b"OggS", b"\x00\x01\x00\x00", b"\x00\x00\x01\x00")):
            return "asset", ""
        return "unknown-binary", ""
    if ext in EXEC_EXT and ext not in (".bin", ".app", ".o", ".a"):
        return "exec-binary", ""
    if ext in PY:
        return "code", "python"
    if ext in SH or lower in SHELL_NAMES:
        return "code", "shell"
    if ext in JS:
        return "code", "js"
    if ext in WIN:
        return "code", "winshell"
    if ext in OTHER:
        return "code", "other"
    if ext in DOC:
        return "doc", ""
    if ext in DOCUMENT_EXT:
        return "document", ""
    if ext in ARCHIVE_EXT:
        return "archive", ""
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0].decode("utf-8", "replace").lower()
        if "python" in first:
            return "code", "python"
        if any(word in first for word in ("bash", "/sh", " sh", "zsh", "dash", "ksh", "fish")):
            return "code", "shell"
        if any(word in first for word in ("node", "deno", "bun")):
            return "code", "js"
        return "code", "other"
    if ext in (".html", ".htm", ".svg", ".vue", ".svelte"):
        return "data", "markup"
    return "data", ""


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def computed_hash(root, rel_paths):
    """The skills.sh lock v2 content hash for the files in rel_paths."""
    kept = []
    for rel in rel_paths:
        parts = rel.split("/")
        if parts[-1] in HASH_SKIP_FILES or any(part in HASH_SKIP_DIRS for part in parts[:-1]):
            continue
        kept.append(rel)
    kept.sort(key=lambda value: value.encode("utf-8"))
    digest = hashlib.sha256()
    for rel in kept:
        with open(os.path.join(root, rel), "rb") as handle:
            content = handle.read()
        if b"\x00" not in content and b"\r\n" in content:
            content = content.replace(b"\r\n", b"\n")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(content)
    return digest.hexdigest()


def _symlink_finding(rel, target):
    norm = target.replace("\\", "/")
    parts = [part.lower() for part in norm.split("/") if part]
    absolute = norm.startswith(("/", "~")) or (len(norm) > 1 and norm[1] == ":")
    if absolute or any(part in CRED_PARTS for part in parts):
        return finding("SR-IN-001", rel, 0, "-> " + target, kind="symlink")
    return finding("SR-IN-005", rel, 0, "-> " + target)


def run(root, work, opts):
    findings, files, seen = [], [], {}
    total = count = 0
    reject = partial = git_present = False
    stack = [("", 0)]
    while stack and not reject:
        rel_dir, depth = stack.pop()
        try:
            entries = sorted(os.scandir(os.path.join(root, rel_dir)), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            rel = (rel_dir + "/" + entry.name) if rel_dir else entry.name
            key = unicodedata.normalize("NFC", rel).casefold()
            if key in seen and seen[key] != rel:
                findings.append(finding("SR-IN-002", rel, 0, seen[key]))
                reject = True
                break
            seen[key] = rel
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISLNK(info.st_mode):
                try:
                    target = os.readlink(entry.path)
                except OSError:
                    target = "?"
                item = _symlink_finding(rel, target)
                findings.append(item)
                reject = reject or item["rule_id"] == "SR-IN-001"
                continue
            if stat.S_ISDIR(info.st_mode):
                if entry.name == ".git":
                    git_present = True
                    continue
                if depth + 1 > LIMITS["max_depth"]:
                    findings.append(finding("SR-IN-004", rel, 0, "depth", kind="input"))
                    partial = True
                    continue
                stack.append((rel, depth + 1))
                continue
            if not stat.S_ISREG(info.st_mode):
                findings.append(finding("SR-IN-008", rel, 0, "special file"))
                continue
            count += 1
            total += info.st_size
            if (count > LIMITS["hard_files"] or total > LIMITS["hard_bytes"]
                    or info.st_size > LIMITS["hard_file_bytes"]):
                findings.append(finding("SR-IN-003", rel, 0,
                                        "%d files, %d bytes" % (count, total)))
                reject = True
                break
            if count > LIMITS["soft_files"] or total > LIMITS["soft_bytes"]:
                if not partial:
                    findings.append(finding("SR-IN-004", rel, 0,
                                            "%d files, %d bytes" % (count, total), kind="input"))
                partial = True
                continue
            try:
                with open(entry.path, "rb") as handle:
                    head = handle.read(8192)
                digest = _sha256(entry.path)
            except OSError:
                findings.append(finding("SR-IN-008", rel, 0, "unreadable"))
                continue
            kind, lang = classify(entry.name, head)
            files.append({"p": rel, "size": info.st_size, "sha256": digest,
                          "kind": kind, "lang": lang})

    for rel, target in (opts.get("source") or {}).get("links") or []:
        item = _symlink_finding(str(rel), str(target))
        findings.append(item)
        reject = reject or item["rule_id"] == "SR-IN-001"

    present = {entry["p"] for entry in files}
    documents = []
    for entry in files:
        rel, kind = entry["p"], entry["kind"]
        if kind == "exec-binary":
            findings.append(finding("SR-RL-04", rel, 0, "executable binary", sub="binary"))
        elif kind == "bytecode":
            folder, base = os.path.split(rel)
            stem = base.split(".")[0]
            if os.path.basename(folder) == "__pycache__":
                source = os.path.join(os.path.dirname(folder), stem + ".py")
            else:
                source = os.path.join(folder, stem + ".py")
            if source.replace("\\", "/").lstrip("/") in present:
                findings.append(finding("SR-IN-010", rel, 0, "bytecode shipped with source"))
            else:
                findings.append(finding("SR-RL-04", rel, 0, "bytecode without source", sub="pyc"))
        elif kind == "archive":
            findings.append(finding("SR-IN-006", rel, 0, "archive"))
        elif kind == "unknown-binary":
            findings.append(finding("SR-IN-008", rel, 0, "unknown binary"))
        elif kind == "document":
            documents.append(rel)
        elif kind in ("code", "doc", "data") and entry["size"] > LIMITS["analyze_bytes"]:
            findings.append(finding("SR-IN-009", rel, 0, "%d bytes" % entry["size"]))
    if documents:
        findings.append(finding("SR-IN-007", documents[0], 0,
                                "%d documents" % len(documents), count=len(documents)))

    file_map = hashlib.sha256()
    for entry in sorted(files, key=lambda e: e["p"].encode("utf-8")):
        file_map.update(entry["p"].encode("utf-8") + b"\x00" + entry["sha256"].encode() + b"\n")
    hashes = {"file_map_sha256": file_map.hexdigest(), "hash_algo": "sha256-filemap-v1",
              "computed_hash": {"algo": "skills-sh@57217cf", "value": None}}
    if not reject and not partial:
        try:
            hashes["computed_hash"]["value"] = computed_hash(root, [e["p"] for e in files])
        except OSError:
            pass
    return {"files": files, "findings": findings, "reject": reject, "partial": partial,
            "git_present": git_present, "hashes": hashes,
            "stats": {"files": count, "bytes": total}}
