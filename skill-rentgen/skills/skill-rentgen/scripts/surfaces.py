"""Stage 3: what runs on its own, and what the code does.

WHY: the part of a skill that hurts is rarely the part the user asked for.
It is the hook that fires on every session, the MCP server that starts in
the background, the file in bin/ that takes the name of git. This stage
lists every such surface, then reads the code: Python through its syntax
tree, shell and JavaScript through published patterns (and says so).

Rules that tests check:
1. Nothing from the scanned skill is imported or executed.
2. Python is analysed by AST. Shell and JavaScript findings carry
   confidence "low". Any other language is reported as not analysed.
3. The same download-and-run command is a red line in an auto-run surface,
   and in a script unless the host is a well-known installer.
4. Known evasions resolve: getattr(os, "system"), __import__("os"),
   exec(base64.b64decode(...)), Path.home() / ".ssh".
"""
from __future__ import annotations

import ast
import base64
import binascii
import json
import math
import os
import re

from common import (clean_snippet, finding, is_doc_path, is_test_path, line_of, line_text,
                    load_json, no_addresses, path_matches, progress, read_text, referenced_files,
                    rule_file)
from text_rules import code_blocks

NET_CALLS = {
    "urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve",
    "urllib.urlopen", "urllib2.urlopen", "requests.get", "requests.post", "requests.put",
    "requests.delete", "requests.patch", "requests.head", "requests.request", "httpx.get",
    "httpx.post", "httpx.put", "httpx.delete", "httpx.patch", "httpx.request", "httpx.stream",
    "http.client.HTTPSConnection", "http.client.HTTPConnection", "socket.create_connection",
    "ftplib.FTP", "ftplib.FTP_TLS", "smtplib.SMTP", "smtplib.SMTP_SSL",
    "websocket.create_connection", "websockets.connect", "telnetlib.Telnet",
    "xmlrpc.client.ServerProxy", "aiohttp.request"}
NET_OBJECTS = ("requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient",
               "aiohttp.ClientSession", "socket.socket", "paramiko.SSHClient",
               "urllib3.PoolManager")
NET_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "connect",
               "sendall", "send", "fetch", "stream", "urlopen"}
SEND_METHODS = {"post", "put", "patch", "sendall", "send", "sendmail", "send_message",
                "storbinary", "upload"}
EXEC_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "os.system",
    "os.popen", "os.execv", "os.execve", "os.execvp", "os.execvpe", "os.execl", "os.execlp",
    "os.spawnv", "os.spawnl", "os.spawnvp", "os.spawnlp", "os.posix_spawn", "pty.spawn",
    "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell", "commands.getoutput"}
DECODERS = {
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.a85decode",
    "base64.b85decode", "base64.urlsafe_b64decode", "base64.decodebytes",
    "binascii.unhexlify", "binascii.a2b_base64", "bytes.fromhex", "bytearray.fromhex",
    "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress",
    "codecs.decode", "marshal.loads"}
PATH_WRAPPERS = {"os.path.expanduser", "os.path.abspath", "os.path.realpath",
                 "os.path.normpath", "os.path.expandvars", "os.fspath", "str",
                 "pathlib.Path", "pathlib.PosixPath", "pathlib.PurePath", "Path"}
PASS_METHODS = {"format", "strip", "decode", "encode", "lower", "rstrip", "lstrip", "resolve",
                "expanduser", "absolute", "as_posix", "read", "text"}
READ_CALLS = {"os.listdir", "os.scandir", "os.walk", "glob.glob", "glob.iglob", "shutil.copy",
              "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.make_archive",
              "tarfile.open", "zipfile.ZipFile"}
DELETE_CALLS = {"os.remove", "os.unlink", "shutil.rmtree", "os.rmdir", "os.rename",
                "os.replace", "shutil.move"}
STDIN_CALLS = {"sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines", "input",
               "fileinput.input", "sys.stdin.buffer.read"}
CRED_PY = re.compile(
    r"\.ssh(?:/(?:id_[a-z0-9_]+|identity|authorized_keys|[\w.-]*key[\w.-]*|\*)?)?$|\.ssh/\*"
    r"|\.aws/credentials|\.aws/?$|\.gnupg|\.netrc$|\.config/gh/hosts\.yml|\.docker/config\.json"
    r"|\.kube/config|\.git-credentials|\.npmrc$|\.pypirc$|\.claude/\.credentials\.json"
    r"|\.claude\.json$|\.gemini/oauth_creds\.json|\.config/gcloud|Library/Keychains"
    r"|\.bitcoin/wallet|\.ethereum/keystore|/etc/shadow$")
SETTINGS_PY = re.compile(r"\.claude/settings(?:\.local)?\.json|\.claude\.json$"
                         r"|\.gemini/settings\.json|\.codex/config\.toml|\.cursor/mcp\.json")
OTHERSKILL_PY = re.compile(r"^(?:~|\{\})/\.(?:claude|agents|gemini|codex|cursor)/"
                           r"(?:skills|plugins|agents|commands|hooks)(?:/|$)")
URL_HOST = re.compile(r"^(?:https?|wss?|ftp)://([^/:\s\"'?#]+)", re.I)
URL_ANY = re.compile(r"https?://[^\s)>\]\"'`<|\\]+", re.I)
# A string that begins with an address, and a setting whose name says it holds a host.
CODE_URL = re.compile(r"""["'`]((?:https?|wss?)://[^\s"'`<>\\]{3,300})""")
CODE_HOST_KEY = re.compile(
    r"""\b(?:hostname|host|baseURL|baseUrl|base_url|endpoint|origin)["']?\s*[:=]\s*["'`]"""
    r"""((?:[a-z0-9-]+\.)+[a-z]{2,24})(?::\d+)?["'`/]""", re.I)
JS_VAR_URL = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]{1,60})\s*(?::\s*[\w.<>\[\] |]{1,40})?=\s*"""
    r"""["'`]((?:https?|wss?)://[^\s"'`$]{3,300})["'`]""")
JS_NET_FUNCS = (r"fetch|axios(?:\.\w+)?|got(?:\.\w+)?|ky(?:\.\w+)?|request|https?\.(?:get|request)"
                r"|undici\.(?:request|fetch)|sendBeacon|WebSocket|EventSource")
VAR_URL = re.compile(r"^\s*(?:export\s+|readonly\s+|local\s+)?([A-Za-z_]\w*)=[\"']?(https?://[^\s\"']+)",
                     re.M)
PKG_PINNED = re.compile(r"@v?\d+(?:\.\d+)*[\w.+-]*$|==\d|@sha256:|@[0-9a-f]{7,40}$")


LOCAL_HOST = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\]|10\.\d+\.\d+\.\d+"
                        r"|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+"
                        r"|host\.docker\.internal)$")
SEARCH_LINE = re.compile(r"^\s*(?:rg|grep|egrep|fgrep|ag|ack|awk|sed\s+-n)\b")


def is_local_host(host):
    """Loopback and private addresses stay on the machine or the local network."""
    return bool(LOCAL_HOST.match(host or ""))


def host_of(url):
    if not url:
        return ""
    match = URL_HOST.match(url.strip())
    if not match:
        return ""
    host = match.group(1).lower().split("@")[-1]
    return "" if "{" in host or "$" in host else host


def entropy(text):
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    size = float(len(text))
    return -sum(n / size * math.log(n / size, 2) for n in counts.values())


DOWNLOAD_TO = re.compile(
    r"\b(?:curl\b[^\n;&|]*?\s(?:-o|--output|-[a-zA-Z]*o)\s+|wget\b[^\n;&|]*?\s(?:-[a-zA-Z]*O\s*|--output-document(?:=|\s+)))"
    r"[\"']?([\w./${}~-]{2,160})[\"']?")
AUTO_APPROVE = re.compile(r"[\"']?permissionDecision[\"']?\s*[:=]\s*\\?[\"']allow|[\"']behavior[\"']\s*:\s*\\?[\"']allow"
                          r"|[\"']decision[\"']\s*:\s*\\?[\"']approve\\?[\"']")
BLOB = re.compile(r"[\"']([A-Za-z0-9+/_-]{24,8000}={0,2})[\"']")


def decode_blob(text):
    """Decode a base64 literal found in text, when it holds readable text.
    Decoding is arithmetic on bytes. Nothing decoded is ever run."""
    match = BLOB.search(text or "")
    if not match:
        return ""
    raw = match.group(1).replace("-", "+").replace("_", "/")
    try:
        data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
    except (binascii.Error, ValueError):
        return ""
    out = data.decode("utf-8", "replace")
    readable = sum(1 for c in out if c.isprintable() or c in "\n\t")
    return out if out and readable / len(out) > 0.9 else ""


MESSAGE_LINE = re.compile(r"^\s*(?:echo|printf|print|log\w*|warn\w*|info|error|die|fail\w*|say|note"
                          r"|hint|usage|check_\w+|\w+_(?:msg|error|warn|log|hint|info))\b")


def _is_message(line, matched):
    """True when a download-and-run command only appears inside a message,
    such as: echo "Install bun: curl ... | bash"."""
    if MESSAGE_LINE.match(line) and not re.search(r"[\"']\s*\|\s*(?:ba|z)?sh\b", line):
        return True
    head = line[:line.find(matched)] if matched in line else ""
    quote = max(head.rfind("\""), head.rfind("'"))
    return quote != -1 and bool(re.search(r"\w[:(]\s*$", head[quote + 1:]))


class Collector:
    """Holds observations and findings, and applies the context rules."""

    def __init__(self):
        known = rule_file("known.json")
        raw = rule_file("patterns-sh-js.json")
        text = rule_file("text-patterns.json")["text"]
        self.shell = [(p["id"], p["obs"], re.compile(p["re"], re.I | re.M)) for p in raw["shell"]]
        self.js = [(p["id"], p["obs"], re.compile(p["re"], re.M)) for p in raw["js"]]
        self.placeholder = re.compile(known["placeholder_host_re"], re.I)
        self.guard = re.compile(text["mention_guard"], re.I)
        self.negation = re.compile(r"\b" + text["negation"] + r"\b", re.I)
        stores = known["secret_stores_re"]
        self.stores = re.compile(stores)
        self.shell.append(("sh.secret-store", "cred_read", re.compile(
            r"\b(?:cat|cp|scp|rsync|tar|zip|sqlite3|base64|curl|find|ditto|less|strings|security)\b"
            r"[^\n|;]{0,220}(?:%s)" % stores, re.M)))
        self.js.append(("js.secret-store", "cred_read", re.compile(
            r"\b(?:readFile(?:Sync)?|copyFile(?:Sync)?|createReadStream|readTextFile)\s*\("
            r"[^\n]{0,260}(?:%s)" % stores, re.M)))
        self.depth = 0
        self.installers = set(known["installer_hosts"])
        self.names = set(known.get("name_hosts", []))
        self.known = known
        self.obs, self.findings, self.surfaces = [], [], []
        self._seen = set()
        self.live = set()

    def tests(self, rel):
        """True when rel is test or example material that nothing points at."""
        return is_test_path(rel) and rel not in self.live

    def add_obs(self, kind, value, rel, line, snippet="", source="code", confidence="high",
                **extra):
        key = (kind, value, rel, line)
        if key in self._seen or len(self.obs) > 4000:
            return
        self._seen.add(key)
        item = {"kind": kind, "value": value or "", "file": rel, "line": int(line or 0),
                "source": source, "confidence": confidence, "in_tests": self.tests(rel)}
        item.update({k: v for k, v in extra.items() if v is not None})
        self.obs.append(item)

    def add_finding(self, rule_id, rel, line, snippet, confidence="high", **extra):
        key = ("F", rule_id, rel, line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(finding(rule_id, rel, line, snippet, confidence, **extra))

    def is_placeholder(self, host):
        return (not host) or bool(self.placeholder.search(host))

    def name_only(self, host):
        """True for an address that code carries as a name: an XML namespace,
        a schema id, a licence link."""
        return host in self.names

    def installer(self, host):
        return any(host == h or host.endswith("." + h) for h in self.installers)

    def scan_text(self, text, rel, lang, ctx, base_line=0, confidence="low", whole_file=False):
        """Apply the shell or JavaScript patterns to text. ctx: auto, code or prose."""
        patterns = self.js if lang == "js" else self.shell
        if lang != "js":
            for name, url in VAR_URL.findall(text):
                text = re.sub(r"\$\{?%s\}?(?![\w])" % re.escape(name), url, text)
        else:
            # A constant that holds an address, used in the same file: put the
            # address where the name is used, so the call is seen with its host.
            # Lines keep their numbers.
            for name, url in JS_VAR_URL.findall(text)[:200]:
                safe = re.escape(name)
                text = re.sub(r"\$\{\s*%s\s*\}" % safe, lambda m, u=url: u, text)
                text = re.sub(r"(\b(?:%s)\s*\(\s*)%s\b(?!\s*[.(\[])" % (JS_NET_FUNCS, safe),
                              lambda m, u=url: m.group(1) + "'" + u + "'", text)
        in_tests = self.tests(rel)
        for _, kind, regex in patterns:
            for match in regex.finditer(text):
                line = line_text(text, match.start())
                stripped = line.lstrip()
                if (ctx != "auto" or whole_file) and (stripped.startswith(("//", "* ", "/*")) or (
                        stripped.startswith("#") and not stripped.startswith("#!"))):
                    continue
                number = base_line + line_of(text, match.start())
                self.handle(kind, match, rel, number, line, ctx, in_tests, confidence, lang)
        if lang != "js":
            self.two_step(text, rel, ctx, base_line, in_tests, confidence)

    def two_step(self, text, rel, ctx, base_line, in_tests, confidence):
        """Download to a file, then make it executable or run it."""
        for match in DOWNLOAD_TO.finditer(text):
            target = match.group(1)
            if target in ("/dev/null", "-") or target.startswith("/dev/"):
                continue
            name = re.escape(target)
            after = text[match.end():match.end() + 700]
            ran = re.search(r"\bchmod\s+(?:\+x|a\+x|u\+x|[0-7]{3,4})\s+[\"']?%s|\b(?:(?:ba|z)?sh|source|python3?"
                            r"|node|open|installer\s+-pkg)\s+[\"']?%s|(?:^|[;&|\n]\s*)(?:sudo\s+)?[\"']?(?:\./)?%s"
                            r"(?=[\"'\s;&|]|$)" % (name, name, name), after)
            if not ran:
                continue
            line = line_text(text, match.start())
            stripped = line.lstrip()
            if stripped.startswith("#") and not stripped.startswith("#!"):
                continue
            url = re.search(r"https?://[^\s\"'`)]+", line)
            host = host_of(url.group(0)) if url else ""
            number = base_line + line_of(text, match.start())
            self.remote_exec(host, bool(url), rel, number, line, ctx, in_tests, confidence, "shell",
                             line, sub="download-then-run")

    def remote_exec(self, host, has_url, rel, number, line, ctx, in_tests, confidence, lang,
                    matched, sub=None):
        """Download-and-run, judged by where it sits and what it fetches."""
        if (has_url and self.is_placeholder(host)) or in_tests:
            return
        if ctx == "prose" and (self.guard.search(no_addresses(line)) or not has_url):
            return
        if ctx != "prose" and lang != "js" and _is_message(line, matched):
            return
        self.add_obs("remote_exec", host, rel, number, source=ctx, confidence=confidence)
        known_installer = bool(host) and self.installer(host)
        if ctx == "auto":
            rule = "SR-CD-004" if known_installer else "SR-RL-13"
        elif ctx == "code":
            base = rel.rsplit("/", 1)[-1].lower()
            container = base.startswith(("dockerfile", "containerfile")) or base.endswith(
                (".dockerfile", ".containerfile"))
            rule = "SR-CD-004" if container or known_installer else "SR-RL-02"
        else:
            parts = rel.split("/")
            instructs = parts[-1] == "SKILL.md" or (
                len(parts) >= 2 and parts[-2] in ("agents", "commands"))
            rule = "SR-TX-005" if known_installer else ("SR-CD-004" if instructs else "SR-TX-006")
        self.add_finding(rule, rel, number, line, confidence, host=host, sub=sub)

    def handle(self, kind, match, rel, number, line, ctx, in_tests, confidence, lang):
        groups = [g for g in match.groups() if g]
        if kind == "remote_exec":
            host = host_of(groups[0]) if groups else ""
            self.remote_exec(host, bool(groups), rel, number, line, ctx, in_tests, confidence, lang,
                             match.group(0))
        elif kind == "encoded_exec":
            if in_tests or (ctx == "prose" and self.guard.search(no_addresses(line))):
                return
            decoded = decode_blob(line)
            self.add_obs("encoded_exec", "", rel, number, source=ctx, confidence=confidence)
            self.add_finding("SR-RL-07", rel, number, line, confidence, sub="encoded-command",
                             decoded=clean_snippet(decoded, 110) or None)
            if decoded and self.depth < 2:
                self.depth += 1
                self.scan_text(decoded, rel, "shell", "auto" if ctx == "auto" else "code",
                               number - 1, confidence)
                self.depth -= 1
        elif kind in ("quarantine", "password_prompt"):
            if in_tests or (ctx == "prose" and self.guard.search(no_addresses(line))):
                return
            if kind == "quarantine" and (MESSAGE_LINE.match(line) or ctx == "prose"):
                # A document that explains the command is not a script that runs it.
                return
            self.add_obs(kind, "", rel, number, source=ctx, confidence=confidence)
            self.add_finding("SR-CD-006" if kind == "quarantine" else "SR-RL-16", rel, number, line,
                             confidence)
        elif kind in ("registry", "install_url"):
            host = host_of(groups[0]) if groups else ""
            if in_tests or not host or self.is_placeholder(host) or is_local_host(host):
                return
            if MESSAGE_LINE.match(line) or SEARCH_LINE.match(line):
                return
            if ctx == "prose" and self.guard.search(no_addresses(line)):
                return
            official = any(host == h or host.endswith("." + h) for h in self.known[
                "default_registries" if kind == "registry" else "code_hosts"])
            if kind == "registry":
                if not official:
                    self.add_obs("registry", host, rel, number, source=ctx, confidence=confidence)
                return
            self.add_obs("install", "install from " + host, rel, number, source=ctx,
                         confidence=confidence)
            if official:
                return
            parts = rel.split("/")
            instructs = parts[-1] == "SKILL.md" or (len(parts) >= 2 and parts[-2] in ("agents", "commands"))
            rule = "SR-CD-004" if ctx != "prose" or instructs else "SR-TX-006"
            self.add_finding(rule, rel, number, line, confidence, host=host, sub="install-url")
        elif kind == "env_all":
            if not in_tests:
                self.add_obs("env_all", "", rel, number, source=ctx, confidence=confidence)
        elif kind == "cred_read":
            lead = match.group(0)
            redirect = re.search(r">>?\s*[\"']?((?:~|\$HOME|\$\{HOME\}|/)[^\s>\"']*)$", lead)
            if redirect:
                if not in_tests:
                    self.add_obs("write_out", redirect.group(1), rel, number, source=ctx,
                                 confidence=confidence, op="w")
                return
            tail = line[line.find(match.group(0)) + len(match.group(0)):][:5]
            if tail.startswith(".pub") or ".pub" in match.group(0)[-6:] or in_tests:
                return
            quiet = re.match(r"grep\s+(?:-[a-zA-Z]*[qcl][a-zA-Z]*|--quiet|--count|--files-with-matches)\b",
                             match.group(0))
            if quiet or (ctx == "prose" and self.guard.search(no_addresses(line))):
                self.add_obs("cred_ref", "", rel, number, source=ctx, confidence=confidence)
                return
            self.add_obs("cred_read", "", rel, number, source=ctx, confidence=confidence)
            self.add_finding("SR-RL-01", rel, number, line, confidence)
        elif kind == "cred_ref":
            if not in_tests and ".pub" not in line[match.end():match.end() + 5]:
                self.add_obs("cred_ref", "", rel, number, source=ctx, confidence=confidence)
        elif kind in ("settings_write", "otherskill_write"):
            if in_tests:
                return
            self.add_obs(kind, "", rel, number, source=ctx, confidence=confidence)
            if ctx == "auto":
                self.add_finding("SR-RL-05", rel, number, line, confidence, sub=kind)
            elif ctx == "code":
                self.add_finding("SR-SF-007", rel, number, line, confidence, sub=kind)
        elif kind == "skip_perms":
            if in_tests:
                return
            lead = line[:max(0, line.find(match.group(0)))][-48:]
            if ctx == "prose":
                if not (self.negation.search(lead) or self.guard.search(no_addresses(line))):
                    self.add_obs("skip_perms", "", rel, number, source=ctx, confidence=confidence)
                    self.add_finding("SR-TX-002", rel, number, line, confidence, sub="skip_perms")
            else:
                self.add_obs("skip_perms", "", rel, number, source=ctx, confidence=confidence)
                self.add_finding("SR-SF-008", rel, number, line, confidence)
        elif kind == "install":
            self.add_obs("install", match.group(0).strip()[:40], rel, number, source=ctx,
                         confidence=confidence)
        elif kind == "network":
            host = host_of(groups[0]) if groups else ""
            if groups and groups[0].startswith("git@"):
                host = groups[0][4:].split(":")[0].lower()
            if host and not self.is_placeholder(host) and not is_local_host(host):
                self.add_obs("network", host, rel, number, source=ctx, confidence=confidence)
        elif kind == "network_dyn":
            self.add_obs("network_dyn", "", rel, number, source=ctx, confidence=confidence)
        elif kind == "network_dyn_wide":
            if len(line) <= 2000:       # not on a minified line: see the pattern's own note
                self.add_obs("network_dyn", "", rel, number, source=ctx, confidence=confidence)
        elif kind == "env":
            self.add_obs("env", groups[0] if groups else "", rel, number, source=ctx,
                         confidence=confidence)
        elif kind == "exec":
            self.add_obs("exec", "child process", rel, number, source=ctx, confidence=confidence)
        elif kind == "dyn_exec":
            self.add_obs("dyn_exec", "", rel, number, source=ctx, confidence=confidence)
            if not in_tests:
                self.add_finding("SR-CD-003", rel, number, line, confidence)


RISKY_PY = re.compile(r"\b(?:exec|eval|compile|__import__)\s*\(|\bsubprocess\b|\bos\.(?:system|popen|exec)"
                      r"|\burllib2?\b|\brequests\b|\bhttpx\b|\bsocket\b|\.ssh\b|\.aws\b"
                      r"|\.gnupg\b|\.netrc\b|\.claude\b|keychain", re.I)


class PyScan(ast.NodeVisitor):
    """Walk one Python file and record what it does."""

    def __init__(self, rel, col, auto=False):
        self.rel, self.col, self.auto = rel, col, auto
        self.aliases, self.strs, self.taint = {}, {}, {}
        self.net_objs, self.imports, self.requests = set(), set(), set()
        self.envall = set()
        self.net_files = set()
        self.in_tests = col.tests(rel)
        self.net_seen = False

    # ---- name and string resolution -------------------------------------
    def cname(self, node, depth=0):
        if depth > 8 or node is None:
            return ""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.cname(node.value, depth + 1)
            return (base + "." + node.attr) if base else node.attr
        if isinstance(node, ast.Call):
            func = self.cname(node.func, depth + 1)
            if func in ("__import__", "importlib.import_module") and node.args:
                return self.sval(node.args[0]) or ""
            if func == "getattr" and len(node.args) >= 2:
                attr, base = self.sval(node.args[1]), self.cname(node.args[0], depth + 1)
                return (base + "." + attr) if attr and base else ""
            return func
        if isinstance(node, ast.Subscript):
            base = self.cname(node.value, depth + 1)
            key = self.sval(node.slice)
            if base in ("globals", "vars", "locals", "__builtins__", "builtins.__dict__") and key:
                return self.aliases.get(key, key)
            return base
        return ""

    def sval(self, node, depth=0):
        if depth > 8 or node is None:
            return None
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            if isinstance(node.value, bytes):
                return node.value.decode("utf-8", "replace")
            return None
        if isinstance(node, ast.JoinedStr):
            out = ""
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    out += part.value
                else:
                    inner = self.sval(getattr(part, "value", None), depth + 1)
                    out += inner if inner is not None else "{}"
            return out
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Div)):
                left, right = self.sval(node.left, depth + 1), self.sval(node.right, depth + 1)
                if left is None and right is None:
                    return None
                sep = "/" if isinstance(node.op, ast.Div) else ""
                return (left if left is not None else "{}") + sep + (
                    right if right is not None else "{}")
            if isinstance(node.op, ast.Mod):
                return self.sval(node.left, depth + 1)
            return None
        if isinstance(node, ast.Name):
            return self.strs.get(node.id)
        if isinstance(node, ast.Subscript):
            if self.cname(node.value) == "os.environ" and self.sval(node.slice) in (
                    "HOME", "USERPROFILE"):
                return "~"
            return None
        if isinstance(node, ast.Attribute):
            if node.attr in ("parent", "name", "stem"):
                return self.sval(node.value, depth + 1)
            return None
        if isinstance(node, ast.Call):
            name = self.cname(node.func)
            if name in ("pathlib.Path.home", "Path.home"):
                return "~"
            if name in ("os.getenv", "os.environ.get") and node.args and self.sval(
                    node.args[0]) in ("HOME", "USERPROFILE"):
                return "~"
            if name == "os.path.join" or name in PATH_WRAPPERS:
                parts = [self.sval(arg, depth + 1) for arg in node.args]
                if not parts or all(part is None for part in parts):
                    return None
                return "/".join(part if part is not None else "{}" for part in parts)
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "joinpath":
                    parts = [self.sval(node.func.value, depth + 1)] + [
                        self.sval(arg, depth + 1) for arg in node.args]
                    return "/".join(part if part is not None else "{}" for part in parts)
                if node.func.attr == "join" and node.args and isinstance(
                        node.args[0], (ast.List, ast.Tuple)):
                    sep = self.sval(node.func.value, depth + 1) or ""
                    parts = [self.sval(e, depth + 1) for e in node.args[0].elts]
                    return sep.join(part if part is not None else "{}" for part in parts)
                if node.func.attr in PASS_METHODS:
                    return self.sval(node.func.value, depth + 1)
        return None

    def taint_of(self, node):
        found = None
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.taint:
                kind = self.taint[sub.id]
            elif isinstance(sub, ast.Call):
                name = self.cname(sub.func)
                if self.is_net(name, sub):
                    kind = "net"
                elif name in DECODERS:
                    kind = "decoded"
                elif name in ("open", "io.open") or name.endswith((".read_text", ".read_bytes")):
                    kind = "file"
                else:
                    continue
            else:
                continue
            if kind == "net":
                return "net"
            if kind == "decoded" or found is None:
                found = kind
        return found

    def is_net(self, name, node):
        if name in NET_CALLS:
            return True
        if "." in name:
            base, method = name.rsplit(".", 1)
            if method in NET_METHODS and (base in self.net_objs or base in NET_OBJECTS
                                          or base.endswith(NET_OBJECTS)):
                return True
        return False

    # ---- visitors --------------------------------------------------------
    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name)
            self.aliases[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        module = node.module or ""
        self.imports.add(module)
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = (module + "." + alias.name).strip(".")

    def _bind(self, target, value):
        if not isinstance(target, ast.Name):
            return
        text = self.sval(value)
        if text is not None:
            self.strs[target.id] = text
        kind = self.taint_of(value)
        if kind:
            self.taint[target.id] = kind
        if self.whole_env(value) and not isinstance(value, (ast.Name, ast.Attribute)):
            self.envall.add(target.id)
        indirect = isinstance(value, ast.Call) and self.cname(value.func) in (
            "getattr", "__import__", "importlib.import_module")
        if indirect or isinstance(value, (ast.Name, ast.Attribute)):
            name = self.cname(value)
            if name and name != target.id:
                self.aliases[target.id] = name
        if isinstance(value, ast.Call) and self.cname(value.func) in NET_OBJECTS:
            self.net_objs.add(target.id)
        if isinstance(value, ast.Call) and self.cname(value.func).rsplit(".", 1)[-1] == "Request":
            self.requests.add(target.id)

    def visit_Assign(self, node):
        self.generic_visit(node)
        for target in node.targets:
            self._bind(target, node.value)

    def visit_AnnAssign(self, node):
        self.generic_visit(node)
        if node.value is not None:
            self._bind(node.target, node.value)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None:
                self._bind(item.optional_vars, item.context_expr)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    # ---- the whole environment: copying it for a child process is routine,
    # ---- printing it or sending it is not
    def whole_env(self, node):
        """True when the expression holds every environment variable.

        The environment that is handed to a child process (`env=`) stays with
        the child: what the call returns is the child's output, not the
        environment. Following it there made a version stamp read from
        `git rev-parse` look like a dump of the environment."""
        stack = [node]
        while stack:
            sub = stack.pop()
            if isinstance(sub, ast.Name) and sub.id in self.envall:
                return True
            if isinstance(sub, ast.Call):
                func = self.cname(sub.func)
                if func in ("os.environ.items", "os.environ.copy", "os.environ.values"):
                    return True
                if func == "dict" and sub.args and self.cname(sub.args[0]) == "os.environ":
                    return True
                stack.append(sub.func)
                stack.extend(sub.args)
                stack.extend(k.value for k in sub.keywords if k.arg != "env")
                continue
            if isinstance(sub, ast.Dict):
                for key, value in zip(sub.keys, sub.values):
                    if key is None and self.cname(value) == "os.environ":
                        return True
            stack.extend(ast.iter_child_nodes(sub))
        return isinstance(node, (ast.Name, ast.Attribute)) and self.cname(node) == "os.environ"

    def _env_sink(self, node, name, short):
        if self.in_tests:
            return
        printing = short in ("print", "json.dumps", "json.dump", "pprint.pprint", "pprint",
                             "logging.info", "logging.debug", "logging.warning", "sys.stdout.write")
        sending = self.is_net(name, node)
        if not (printing or sending):
            return
        values = list(node.args) + [k.value for k in node.keywords if k.arg != "env"]
        if any(self.whole_env(value) for value in values):
            self.col.add_obs("env_all", "", self.rel, node.lineno,
                             sink="net" if sending else "print")

    def visit_For(self, node):
        if self.whole_env(node.iter) and not self.in_tests:
            body = ast.Module(body=node.body, type_ignores=[])
            calls = [self.cname(c.func) for c in ast.walk(body) if isinstance(c, ast.Call)]
            shown = any(c in ("print", "sys.stdout.write", "logging.info") or c.endswith(
                (".write", ".post", ".send", ".sendall", ".put")) for c in calls)
            self.col.add_obs("env_all", "", self.rel, node.lineno,
                             sink="print" if shown else "loop")
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if self.cname(node.value) == "os.environ":
            key = self.sval(node.slice)
            if key:
                self.col.add_obs("env", key, self.rel, node.lineno)
        self.generic_visit(node)

    def _file(self, path, op, node):
        line = node.lineno
        if path is None:
            if op != "r":
                self.col.add_obs("write", "?", self.rel, line, op=op)
            return
        norm = path.replace("\\", "/").rstrip("/")
        base = norm.rsplit("/", 1)[-1]
        if (CRED_PY.search(norm) or self.col.stores.search(norm)) and not norm.endswith(".pub"):
            self.col.add_obs("cred_read", norm, self.rel, line)
            if not self.in_tests:
                self.col.add_finding("SR-RL-01", self.rel, line, norm, sub="read" if op == "r" else "write")
            return
        if base.startswith(".env") and op == "r":
            self.col.add_obs("dotenv", base, self.rel, line)
        if op == "r":
            return
        home = norm.startswith(("~", "/")) and not norm.startswith("/{}")
        hit = "settings_write" if SETTINGS_PY.search(norm) else (
            "otherskill_write" if OTHERSKILL_PY.search(norm) else "")
        if hit:
            self.col.add_obs(hit, norm, self.rel, line)
            if not self.in_tests:
                if self.auto and (home or hit == "settings_write"):
                    rule = "SR-RL-05"
                elif home or self.auto:
                    rule = "SR-SF-007"
                else:
                    rule = "SR-SF-010"
                self.col.add_finding(rule, self.rel, line, norm, sub=hit)
        elif home and not norm.startswith(("/tmp", "/var/tmp", "/dev/", "/proc/", "/sys/",
                                           "/mnt/user-data/", "/mnt/outputs")):
            self.col.add_obs("write_out", norm, self.rel, line, op=op)
        else:
            self.col.add_obs("write", norm, self.rel, line, op=op)

    def _command(self, node):
        arg = node.args[0] if node.args else None
        if arg is None:
            for keyword in node.keywords:
                if keyword.arg in ("args", "cmd"):
                    arg = keyword.value
        if isinstance(arg, (ast.List, ast.Tuple)):
            parts = ["python3" if self.cname(e) == "sys.executable" else self.sval(e)
                     for e in arg.elts]
            if any(part is not None for part in parts):
                return " ".join(part if part is not None else "{}" for part in parts)
            return None
        return self.sval(arg)

    def visit_Call(self, node):
        name = self.cname(node.func)
        short = name[9:] if name.startswith("builtins.") else name
        line = node.lineno
        src = short
        if short in ("exec", "eval") and node.args:
            arg = node.args[0]
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    and len(arg.value) < 200):
                kind = self.taint_of(arg)
                literal = max((n.value for n in ast.walk(arg) if isinstance(n, ast.Constant)
                               and isinstance(n.value, str)), key=len, default="")
                if self.in_tests:
                    pass
                elif kind == "net":
                    self.col.add_finding("SR-RL-02", self.rel, line, src + "(network content)",
                                         sub="exec-network")
                elif kind == "decoded":
                    decoded = decode_blob(repr(literal)) if len(literal) >= 24 else ""
                    self.col.add_finding("SR-RL-02", self.rel, line, src + "(decoded content)",
                                         sub="exec-decoded", decoded=clean_snippet(decoded, 110) or None)
                    if decoded:
                        self.col.scan_text(decoded, self.rel, "shell",
                                           "auto" if self.auto else "code", line - 1, "high")
                elif len(literal) >= 120 and entropy(literal) > 4.3:
                    self.col.add_finding("SR-RL-03", self.rel, line, src + "(long opaque string)")
                else:
                    self.col.add_finding("SR-CD-003", self.rel, line, src + "(...)")
                self.col.add_obs("dyn_exec", kind or "", self.rel, line)
        if self.is_net(name, node):
            self.net_seen = True
            target = node.args[0] if node.args else None
            for keyword in node.keywords:
                if keyword.arg in ("url", "host", "address"):
                    target = keyword.value
            if name.rsplit(".", 1)[-1] == "request" and len(node.args) > 1:
                target = node.args[1]
            if isinstance(target, (ast.Tuple, ast.List)) and target.elts:
                target = target.elts[0]
            url = self.sval(target)
            host = host_of(url) if url else ""
            if url and not host and "://" not in url and "." in url and " " not in url:
                host = url.split("/")[0].lower() if "{" not in url.split("/")[0] else ""
            method = name.rsplit(".", 1)[-1]
            send = method in SEND_METHODS or any(
                k.arg in ("data", "json", "files", "content") for k in node.keywords) or (
                method == "Request" and len(node.args) > 1)
            if host and is_local_host(host):
                pass
            elif host and not self.col.is_placeholder(host):
                self.col.add_obs("network", host, self.rel, line, send=send)
            elif host and send and not self.in_tests:
                self.col.add_obs("network", host, self.rel, line, send=send, placeholder=True)
            elif isinstance(target, ast.Name) and target.id in self.requests:
                pass
            elif host:
                pass
            elif not host and method not in ("socket", "Session", "Client", "AsyncClient"):
                self.col.add_obs("network_dyn", "", self.rel, line, send=send)
        if short == "compile" and len(node.args) >= 3 and self.sval(node.args[2]) in (
                "exec", "eval", "single") and not isinstance(node.args[0], ast.Constant):
            if not self.in_tests:
                self.col.add_finding("SR-CD-003", self.rel, line, "compile(...)")
            self.col.add_obs("dyn_exec", "", self.rel, line)
        self._env_sink(node, name, short)
        if name in ("urllib.request.urlretrieve", "urllib.urlretrieve") and len(node.args) >= 2:
            dest = node.args[1]
            self.net_files.add(dest.id if isinstance(dest, ast.Name) else (self.sval(dest) or ""))
        if (name in EXEC_CALLS or name == "os.chmod") and self.net_files and not self.in_tests:
            names = {sub.id for sub in ast.walk(node) if isinstance(sub, ast.Name)}
            texts = {self.sval(arg) or "" for arg in node.args}
            if (names | texts) & (self.net_files - {""}):
                self.col.add_finding("SR-RL-02", self.rel, line, short + "(downloaded file)",
                                     sub="download-then-run")
        if name in EXEC_CALLS:
            command = self._command(node)
            word = (command or "?").strip().split(" ")[0].rsplit("/", 1)[-1][:30] or "?"
            self.col.add_obs("exec", word, self.rel, line)
            if command:
                self.col.scan_text(command, self.rel, "shell", "auto" if self.auto else "code",
                                   line - 1, "high")
        if short in ("open", "io.open", "codecs.open") and node.args:
            mode = self.sval(node.args[1]) if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode = self.sval(keyword.value)
            mode = mode or "r"
            self._file(self.sval(node.args[0]), "w" if any(c in mode for c in "wax+") else "r", node)
        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in ("read_text", "read_bytes", "iterdir", "glob", "rglob"):
                self._file(self.sval(node.func.value), "r", node)
            elif attr in ("write_text", "write_bytes", "touch", "mkdir"):
                self._file(self.sval(node.func.value), "w", node)
            elif attr in ("unlink", "rmdir") and not name.startswith("os."):
                self._file(self.sval(node.func.value), "d", node)
        if name in READ_CALLS and node.args:
            self._file(self.sval(node.args[0]), "r", node)
            if name.startswith("shutil.copy") and len(node.args) > 1:
                self._file(self.sval(node.args[1]), "w", node)
        if name in DELETE_CALLS and node.args:
            self._file(self.sval(node.args[0]), "d", node)
        if name in ("os.getenv", "os.environ.get") and node.args:
            key = self.sval(node.args[0])
            if key:
                self.col.add_obs("env", key, self.rel, line)
        if short in STDIN_CALLS:
            self.col.add_obs("stdin", "", self.rel, line)
        if name.endswith(("load_dotenv", "dotenv_values")):
            self.col.add_obs("dotenv", ".env", self.rel, line)
        if name in ("pip.main", "pip._internal.main", "ensurepip.bootstrap"):
            self.col.add_obs("install", "pip", self.rel, line)
        self.generic_visit(node)

    def finish(self):
        hosts = self.col.known.get("sdk_hosts", {})
        for module in self.imports:
            for sdk, host in hosts.items():
                if module == sdk or module.startswith(sdk + "."):
                    self.col.add_obs("network", host, self.rel, 1, sdk=sdk)
                    self.net_seen = True
        if not self.net_seen:
            libs = set(self.col.known.get("net_libs", []))
            hit = sorted(m for m in self.imports if m.split(".")[0] in libs)
            if hit:
                self.col.add_obs("network_dyn", "", self.rel, 1, confidence="low", lib=hit[0],
                                 guess=True)


def scan_python(col, root, rel, text, auto=False):
    scan = PyScan(rel, col, auto)
    try:
        tree = ast.parse(text, filename="<skill>")
        scan.visit(tree)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
        deep = isinstance(error, (RecursionError, MemoryError))
        risky = RISKY_PY.search(text) if not col.tests(rel) else None
        if deep or risky:
            col.add_finding("SR-FAIL-CLOSED", rel, line_of(text, risky.start()) if risky else 1,
                            "python file could not be analysed: " + type(error).__name__,
                            kind="input")
        elif not col.tests(rel):
            col.add_finding("SR-CD-002", rel, 1, type(error).__name__, "low")
        col.scan_text(text, rel, "shell", "auto" if auto else "code", whole_file=True)
        return None
    scan.finish()
    return scan.imports


DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-w",
                      "--workdir", "--network", "--mount", "-u", "--user", "--entrypoint", "-l",
                      "--label", "--platform", "--env-file", "-h", "--hostname", "--add-host",
                      "--cpus", "-m", "--memory", "--pull"}


def _unpinned(command, known):
    """The first package or image that is fetched and started without a
    version, as "runner name". Empty when every one is pinned."""
    tokens = []
    for token in command.split():
        # --flag=value is a flag and its value. KEY=value after -e is one value.
        if token.startswith("-") and "=" in token:
            flag, value = token.split("=", 1)
            tokens += [flag, value] if value else [flag]
        else:
            tokens.append(token)
    for index, token in enumerate(tokens):
        base = token.rsplit("/", 1)[-1]
        two = (base + " " + tokens[index + 1]) if index + 1 < len(tokens) else ""
        runner = base if base in known["unpinned_runners"] else (
            two if two in known["unpinned_runners"] else "")
        if not runner:
            continue
        rest = tokens[index + (2 if " " in runner else 1):]
        spec = ""
        skip = False
        docker = runner.startswith("docker")
        for item in rest:
            if skip:
                skip = False
                if not docker and (item.startswith(("git+", "http")) or "/" in item or "@" in item):
                    spec = item
                    break
                continue
            if item in (DOCKER_VALUE_FLAGS if docker else ("--from", "-p", "--package", "--with")):
                skip = True
                continue
            if item.startswith("-") or item in ("run", "exec", "--"):
                continue
            spec = item
            break
        if not spec or spec.startswith(("./", "/", "$", ".")):
            continue
        if runner.startswith("docker"):
            image = spec
            pinned = "@sha256:" in image or bool(re.search(r":[\w.-]*\d[\w.-]*$", image))
            pinned = pinned and not image.endswith(":latest")
        elif spec.startswith(("git+", "http")):
            pinned = bool(re.search(r"@(?:v?\d[\w.]*|[0-9a-f]{7,40})$", spec))
        else:
            pinned = bool(PKG_PINNED.search(spec)) and not spec.endswith("@latest")
        if not pinned:
            return runner + " " + spec
    return ""


def _surface_command(col, rel, kind, event, command, timing):
    if not isinstance(command, str) or not command.strip():
        return
    known = col.known
    col.surfaces.append({"kind": kind, "event": event, "timing": timing, "file": rel,
                         "command": command[:300]})
    col.scan_text(command, rel, "shell", "auto", 0, "high")
    if kind == "hook" and AUTO_APPROVE.search(command):
        col.add_finding("SR-SF-011", rel, 1, command)
    loose = _unpinned(command, known)
    if loose:
        col.add_finding("SR-SF-006", rel, 1, loose, sub=kind)
        col.add_obs("install", loose, rel, 1, source="auto")
    if kind == "hook":
        for token in re.findall(r"(?:^|[\s\"'=])((?:~|\$HOME|\$\{HOME\}|/)[\w./${}-]+)", command):
            if token.startswith(("/usr/", "/bin/", "/dev/", "/tmp/", "/opt/homebrew/", "/etc/"))\
                    or token in ("/", "~") or "CLAUDE_PLUGIN_ROOT" in token or len(token) < 4:
                continue
            col.surfaces[-1]["outside"] = token
            break


def _walk_config(col, rel, obj, base_kind, path=(), depth=0):
    if depth > 12:
        return
    known = col.known
    events = known["hook_events"]
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, str) and path and path[-1] in ("modules", "mods"):
                col.surfaces.append({"kind": "module", "event": "", "timing": "in_process",
                                     "file": rel, "command": item[:300]})
            _walk_config(col, rel, item, base_kind, path, depth + 1)
        return
    if not isinstance(obj, dict):
        return
    kind = base_kind
    for key in path:
        if key == "mcpServers":
            kind = "mcp"
        elif key in ("lspServers",):
            kind = "lsp"
        elif key == "monitors":
            kind = "monitor"
        elif key in ("modules", "mods"):
            kind = "module"
        elif key == "hooks" and kind not in ("mcp", "lsp", "monitor", "module"):
            kind = "hook"
    event = next((key for key in reversed(path) if key in events), "")
    if not event and kind == "hook":
        # An event this version does not know still runs on its own.
        event = next((key for key in reversed(path) if re.match(r"^[A-Z][A-Za-z]+$", key)), "")
    timing = events.get(event, "background") if kind == "hook" else {
        "mcp": "session_start", "lsp": "on_file", "monitor": "background",
        "module": "in_process"}.get(kind, "")
    command = obj.get("command")
    url = obj.get("url") or obj.get("serverUrl")
    hook_type = obj.get("type")
    if kind == "module" and (isinstance(command, str) or obj.get("path") or obj.get("module")):
        col.surfaces.append({"kind": "module", "event": event, "timing": "in_process",
                             "file": rel, "command": str(command or obj.get("path")
                                                         or obj.get("module"))[:300]})
    elif isinstance(command, str) and kind in ("hook", "mcp", "lsp", "monitor", "config"):
        args = obj.get("args")
        full = command + (" " + " ".join(str(a) for a in args) if isinstance(args, list) else "")
        _surface_command(col, rel, kind if kind != "config" else "hook", event, full, timing)
    elif isinstance(url, str) and kind == "mcp":
        host = host_of(url)
        col.surfaces.append({"kind": "mcp", "event": "", "timing": "session_start",
                             "file": rel, "url": url[:200], "remote": True})
        if host and not is_local_host(host):
            col.add_obs("network", host, rel, 1, source="auto", send=True, via="mcp")
    elif isinstance(url, str) and kind == "hook" and hook_type == "http":
        host = host_of(url)
        col.surfaces.append({"kind": "hook", "event": event, "timing": timing, "file": rel,
                             "url": url[:200], "type": "http"})
        if host and not is_local_host(host):
            col.add_obs("network", host, rel, 1, source="auto", send=True)
    elif kind == "hook" and isinstance(hook_type, str) and hook_type not in known[
            "hook_types_command"] and event:
        col.surfaces.append({"kind": "hook", "event": event, "timing": timing, "file": rel,
                             "command": "", "type": hook_type})
        col.add_finding("SR-SF-001", rel, 1, "%s hook of type %s" % (event, hook_type))
    for key, value in obj.items():
        if isinstance(value, (dict, list)):
            _walk_config(col, rel, value, base_kind, path + (str(key),), depth + 1)
        elif key in ("modules", "mods") and isinstance(value, str):
            col.surfaces.append({"kind": "module", "event": "", "timing": "in_process",
                                 "file": rel, "command": value[:300]})


def _pointed_configs(root, intake):
    """Config files that a plugin manifest names with a custom path."""
    present = {entry["p"] for entry in intake["files"]}
    out = {}
    for entry in intake["files"]:
        rel = entry["p"]
        if not rel.endswith(".claude-plugin/plugin.json") or is_test_path(rel):
            continue
        try:
            data = json.loads(read_text(os.path.join(root, rel))[0])
        except (ValueError, OSError, RecursionError):
            continue
        base = os.path.dirname(os.path.dirname(rel))
        for key, kind in (("hooks", "hook"), ("mcpServers", "mcp"), ("lspServers", "lsp")):
            value = data.get(key) if isinstance(data, dict) else None
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str):
                    path = os.path.normpath(os.path.join(base, item)).replace("\\", "/")
                    if path in present:
                        out[path] = kind
    return out


_JS_LOCAL = re.compile(r"""(?:require\(|from\s+|import\s+|import\()\s*['"](\.{1,2}/[^'"]+)['"]""")
_RUNNERS = r"(?:python3?|node|bash|sh|zsh|source|bun|deno|tsx|ruby|perl|php|pwsh|powershell)"
# A file handed to an interpreter, in a shell line or inside a string of any language.
_RUN_SHELL = re.compile(r"""(?:^|[\s;&|(`'"$])(?:exec\s+)?%s\s+(?:-[\w-]+\s+)*\\?["']?([^\s"';|&)<>\\]+)"""
                        % _RUNNERS, re.M)
# The same, written as a list: ["python3", "tool.py"].
_RUN_LIST = re.compile(r"""["']%s["']\s*,\s*(?:["']-[\w-]+["']\s*,\s*)*["']([^"']+)["']""" % _RUNNERS)
# A script started by its own path at the head of a command.
_RUN_PATH = re.compile(r"""(?:^|[;&|]\s*|\bexec\s+|\bthen\s+|\bdo\s+)\\?["']?"""
                       r"""((?:\$\{?\w+\}?|\.{1,2}|~)?/?[\w./${}-]+\.(?:sh|bash|py|js|mjs|cjs|ts|rb|pl))""", re.M)


def _local_imports(text):
    """Module names a Python file imports, as written (a.b and a for "import a.b")."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if base:
                names.add(base)
            for alias in node.names:
                names.add((base + "." if base else "") + alias.name)
    return names


def reach(root, started, intake, limit=300):
    """Everything an auto-started file pulls in: the scripts it hands to an
    interpreter or starts by path, and the local modules it imports, and
    theirs in turn. A file that is only mentioned is not followed.

    WHY: a hook that runs a harmless-looking launcher is still running
    whatever the launcher runs. Without this, a skill moves its payload one
    file away from the hook and is judged as code that only runs on request."""
    code = {entry["p"]: entry.get("lang", "") for entry in intake["files"]
            if entry["kind"] == "code"}
    paths = list(code)
    seen, queue = set(started), sorted(started)
    while queue and len(seen) < limit:
        rel = queue.pop()
        if rel not in code:
            continue
        try:
            text, _ = read_text(os.path.join(root, rel), 400000)
        except OSError:
            continue
        folder = os.path.dirname(rel)
        prefix = folder + "/" if folder else ""
        found = set()
        for pattern in (_RUN_SHELL, _RUN_LIST, _RUN_PATH):
            for match in pattern.finditer(text):
                found |= path_matches(match.group(1), folder, paths)
        if code[rel] == "python":
            for name in _local_imports(text):
                stem = prefix + name.replace(".", "/")
                found.update(c for c in (stem + ".py", stem + "/__init__.py") if c in code)
        elif code[rel] == "js":
            for match in _JS_LOCAL.finditer(text):
                stem = os.path.normpath(prefix + match.group(1)).replace("\\", "/")
                found.update(c for c in (stem, stem + ".js", stem + ".mjs", stem + ".cjs",
                                         stem + ".ts", stem + "/index.js") if c in code)
        for item in sorted(found - seen):
            seen.add(item)
            queue.append(item)
    return seen


def scan_configs(col, root, intake, structure):
    pointed = _pointed_configs(root, intake)
    for entry in intake["files"]:
        rel = entry["p"]
        base = os.path.basename(rel)
        if is_test_path(rel) and rel not in pointed:
            continue
        kind = pointed.get(rel)
        if kind:
            col.live.add(rel)
        if kind:
            pass
        elif base == "hooks.json":
            kind = "hook"
        elif base == ".mcp.json" or base == "mcp.json":
            kind = "mcp"
        elif base == ".lsp.json":
            kind = "lsp"
        elif rel.endswith(".claude-plugin/plugin.json") or rel.endswith(
                ".claude-plugin/marketplace.json"):
            kind = "config"
        elif base == "package.json":
            kind = "package"
        if not kind:
            continue
        try:
            data = json.loads(read_text(os.path.join(root, rel))[0])
        except (ValueError, OSError, RecursionError):
            col.add_finding("SR-ST-006", rel, 1, "not valid JSON", kind="input")
            continue
        if kind == "package":
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if isinstance(scripts, dict):
                for name in ("preinstall", "install", "postinstall", "prepare"):
                    if isinstance(scripts.get(name), str):
                        col.add_finding("SR-SF-005", rel, 1, name + ": " + scripts[name])
                        _surface_command(col, rel, "package", name, scripts[name], "install")
            continue
        if kind == "mcp" and isinstance(data, dict) and "mcpServers" not in data:
            data = {"mcpServers": data}
        if kind == "lsp" and isinstance(data, dict) and "lspServers" not in data:
            data = {"lspServers": data}
        if kind == "hook" and isinstance(data, dict) and "hooks" not in data:
            data = {"hooks": data}
        _walk_config(col, rel, data, kind)
    for group in ("skills", "agents", "commands"):
        for item in structure.get(group, []):
            if item.get("fm_raw"):
                col.add_finding("SR-SF-001", item["file"], 1, "hooks in frontmatter that could not be parsed")
                col.surfaces.append({"kind": "hook", "event": "", "timing": "every_tool",
                                     "file": item["file"], "command": ""})
                col.scan_text(item["fm_raw"], item["file"], "shell", "auto", 0, "high")
            hooks = (item.get("fm") or {}).get("hooks")
            if hooks:
                col.add_finding("SR-SF-003", item["file"], 1, "hooks in frontmatter")
                _walk_config(col, item["file"], {"hooks": hooks}, "hook")
            for tool in item.get("allowed_tools", []):
                bare = tool.strip().strip("\"'")
                if bare in ("Bash", "Bash(*)", "*", "Bash(*:*)"):
                    col.add_finding("SR-SF-004", item["file"], 1, bare, tool=bare)


def auto_started(col, intake):
    """Files of the skill that a hook, a server entry or an install script starts."""
    paths = [entry["p"] for entry in intake["files"] if entry["kind"] == "code"]
    started = set()
    for surface in col.surfaces:
        if surface["kind"] not in ("hook", "mcp", "lsp", "monitor", "package", "module"):
            continue
        hits = path_matches(surface.get("command") or "", os.path.dirname(surface["file"]), paths)
        started |= hits
        outside = surface.pop("outside", None)
        if outside and not path_matches(outside, "", paths):
            col.add_finding("SR-SF-002", surface["file"], 1, outside)
    return started


def scan_bin_and_shadow(col, intake, imports_by_file):
    known = col.known
    commands, core = set(known["bin_commands"]), set(known["stdlib_core"])
    risky = set(known["stdlib_core"][:24])
    by_dir = {}
    for entry in intake["files"]:
        by_dir.setdefault(os.path.dirname(entry["p"]), []).append(entry)
    for entry in intake["files"]:
        rel = entry["p"]
        parts = rel.split("/")
        base = parts[-1]
        stem = base.split(".")[0]
        if len(parts) >= 2 and parts[-2] == "bin" and not col.tests(rel):
            col.surfaces.append({"kind": "bin", "event": "", "timing": "on_command",
                                 "file": rel, "command": base})
            if stem in commands and "node_modules" not in parts:
                col.add_finding("SR-RL-14", rel, 0, base)
        if base in known["auto_exec_py"]:
            col.add_finding("SR-RL-10", rel, 0, base, sub="auto-exec")
        elif base.endswith(".pth") and entry["kind"] in ("data", "code"):
            col.add_finding("SR-RL-10", rel, 0, base, sub="pth")
        elif base.endswith(".py") and stem in core and not col.tests(rel):
            siblings = [e["p"] for e in by_dir.get(os.path.dirname(rel), [])
                        if e["p"] != rel and e["p"].endswith(".py")]
            used = any(stem in {m.split(".")[0] for m in imports_by_file.get(s, ())}
                       for s in siblings)
            if used or (stem in risky and siblings):
                col.add_finding("SR-RL-10", rel, 0, base, sub="shadow")
        elif base == "__init__.py" and len(parts) >= 2 and parts[-2] in risky and not col.tests(rel):
            col.add_finding("SR-RL-10", rel, 0, parts[-2] + "/", sub="shadow")


REGISTRY_FILES = {".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".pypirc", "uv.toml",
                  "bunfig.toml"}
CONFIG_EXT = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties",
              ".xml", ".txt", ".plist")


def scan_data(col, rel, text):
    """Addresses inside config and data files. Nothing here runs; it shows
    where the skill is set up to send things."""
    base = rel.rsplit("/", 1)[-1].lower()
    if base in REGISTRY_FILES and not col.tests(rel):
        col.scan_text(text, rel, "shell", "code", 0, "high")
    if not base.endswith(CONFIG_EXT) and not base.startswith(".env"):
        return
    if base in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "uv.lock",
                "poetry.lock", "cargo.lock") or base.endswith((".min.json", ".map")):
        return
    seen = 0
    for match in URL_ANY.finditer(text[:400000]):
        host = host_of(match.group(0))
        if not host or col.is_placeholder(host) or is_local_host(host):
            continue
        col.add_obs("config_url", host, rel, line_of(text, match.start()), source="config",
                    confidence="low")
        seen += 1
        if seen >= 60:
            break


def scan_prose(col, root, rel, text):
    known = col.known
    hosts = {}
    for match in URL_ANY.finditer(text):
        host = host_of(match.group(0))
        if host and not col.is_placeholder(host) and host not in hosts:
            hosts[host] = line_of(text, match.start())
    for host, line in list(hosts.items())[:40]:
        col.add_obs("mention", host, rel, line, source="prose", confidence="low")
    if col.tests(rel):
        return
    for lang, start, body in code_blocks(text):
        if lang in ("", "sh", "bash", "shell", "zsh", "console", "terminal", "fish", "powershell",
                    "python", "py", "python3", "javascript", "js", "ts", "typescript", "ini",
                    "toml", "dockerfile"):
            col.scan_text(body, rel, "shell", "prose", start - 1, "low")
    verbs = re.compile(known["connector_verbs_re"], re.I)
    reads = re.compile(known["connector_reads_re"], re.I)
    if os.path.basename(rel) == "SKILL.md":
        low = text.lower()
        for name in known["connectors"]:
            found = {}
            for match in list(re.finditer(r"\b%s\b" % re.escape(name), low))[:20]:
                line = line_text(text, match.start())
                mode = "write" if verbs.search(line) else ("read" if reads.search(line) else "")
                if mode and mode not in found:
                    found[mode] = line_of(text, match.start())
            mode = "write" if "write" in found else ("read" if "read" in found else "")
            if mode:
                col.add_obs("connector", name, rel, found[mode], source="prose",
                            confidence="low", mode=mode)


def scan_code_hosts(col, rel, text, ctx):
    """Servers that the code names in a string, whether or not a call to
    them was found.

    WHY: only Python is read as a syntax tree. In the other languages a call
    is tied to its address when both sit in one file. An address that is held
    in one place and used in another, or handed to a helper, would otherwise
    appear nowhere in the report. Naming it costs little; hiding it is how a
    reader gets "an address decided at run time" for a tool that phones one
    fixed server."""
    count = 0
    for regex in (CODE_URL, CODE_HOST_KEY):
        for match in regex.finditer(text):
            line = line_text(text, match.start())
            stripped = line.lstrip()
            if stripped.startswith(("//", "* ", "/*", "<!--")) or (
                    stripped.startswith("#") and not stripped.startswith("#!")):
                continue
            value = match.group(1)
            host = host_of(value) if "://" in value else value.lower()
            if (not host or "." not in host or col.is_placeholder(host) or is_local_host(host)
                    or col.name_only(host) or host.endswith((".sock", ".socket"))):
                continue
            col.add_obs("code_host", host, rel, line_of(text, match.start()), source=ctx,
                        confidence="low")
            count += 1
            if count >= 60:
                return


def run(root, work, opts):
    intake = load_json(os.path.join(work, "intake.json"))
    structure = load_json(os.path.join(work, "structure.json"))
    col = Collector()
    imports_by_file, stats = {}, {"python_ast": 0, "patterns": 0, "not_analysed": 0}
    other = []
    scan_configs(col, root, intake, structure)
    started = reach(root, auto_started(col, intake), intake)
    code_paths = [entry["p"] for entry in intake["files"] if entry["kind"] == "code"]
    started_hooks = set()
    for surface in col.surfaces:
        if surface["kind"] == "hook":
            started_hooks |= path_matches(surface.get("command") or "",
                                          os.path.dirname(surface["file"]), code_paths)
    col.live |= set(started) | referenced_files(root, intake, structure)
    for entry in intake["files"]:
        rel, kind, lang = entry["p"], entry["kind"], entry.get("lang", "")
        ctx = "auto" if rel in started else "code"
        if rel in started_hooks and kind == "code":
            try:
                approve = AUTO_APPROVE.search(read_text(os.path.join(root, rel))[0])
            except OSError:
                approve = None
            if approve:
                col.add_finding("SR-SF-011", rel, 1, approve.group(0))
        if kind not in ("code", "doc", "data"):
            continue
        progress(work, "surfaces", rel)
        try:
            text, _ = read_text(os.path.join(root, rel))
        except OSError:
            continue
        if kind == "code" and lang == "python":
            imports = scan_python(col, root, rel, text, ctx == "auto")
            if imports is not None:
                imports_by_file[rel] = imports
                stats["python_ast"] += 1
        elif kind == "code" and lang in ("shell", "winshell"):
            col.scan_text(text, rel, "shell", ctx, whole_file=True)
            stats["patterns"] += 1
        elif kind == "code" and rel.endswith((".d.ts", ".d.mts", ".d.cts")):
            pass
        elif kind == "code" and lang == "js":
            if any(len(line) > 5000 for line in text.split("\n")[:50]) and not col.tests(rel):
                col.add_finding("SR-CD-005", rel, 1, "bundled or minified", "low")
            col.scan_text(text, rel, "js", ctx, whole_file=True)
            stats["patterns"] += 1
        elif kind == "code":
            if not col.tests(rel):
                other.append(rel)
            col.scan_text(text, rel, "shell", "code")
            col.scan_text(text, rel, "js", "code")
            stats["not_analysed"] += 1
        elif entry.get("lang") == "markup":
            col.scan_text(text, rel, "js", "code")
        elif kind == "data":
            scan_data(col, rel, text)
        if kind == "code" and not rel.endswith((".d.ts", ".d.mts", ".d.cts")):
            scan_code_hosts(col, rel, text, ctx)
        if kind == "doc" or is_doc_path(rel):
            scan_prose(col, root, rel, text)
    if other:
        col.add_finding("SR-CD-001", other[0], 0, "%d files" % len(other), count=len(other),
                        files=other[:8])
    scan_bin_and_shadow(col, intake, imports_by_file)
    return {"observations": col.obs, "surfaces": col.surfaces, "findings": col.findings,
            "analysis": stats, "auto_started": sorted(started)}
