"""Loaded inside the sandbox as Python's start-up module. Records what a
Python script of the skill tries to do. It only appends lines to a trace
file; it blocks nothing, because the sandbox has no network and holds no
real files.

Settings come from the environment: SR_TRACE (file to append to) and
SR_WATCH (folders whose files are worth recording, separated by os.pathsep).
"""
import json
import os
import sys

_TRACE = os.environ.get("SR_TRACE", "")
_WATCH = tuple(p for p in os.environ.get("SR_WATCH", "").split(os.pathsep) if p)
_busy = False
_fd = -1


def _write(kind, **fields):
    global _busy, _fd
    if _busy or not _TRACE:
        return
    _busy = True
    try:
        if _fd < 0:
            _fd = os.open(_TRACE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
        fields["kind"] = kind
        fields["pid"] = os.getpid()
        os.write(_fd, (json.dumps(fields, default=str)[:1200] + "\n").encode("utf-8", "replace"))
    except Exception:
        pass
    finally:
        _busy = False


def _hook(event, args):
    try:
        if event == "open":
            path = args[0]
            if isinstance(path, bytes):
                path = path.decode("utf-8", "replace")
            if isinstance(path, str) and path != _TRACE:
                full = os.path.abspath(path)
                if full.startswith(_WATCH):
                    _write("open", path=full, mode=str(args[1]))
        elif event in ("socket.connect", "socket.sendto"):
            _write("net", address=str(args[1]))
        elif event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"):
            _write("dns", host=str(args[0]))
        elif event == "urllib.Request":
            _write("url", url=str(args[0]))
        elif event == "subprocess.Popen":
            argv = args[1] if isinstance(args[1], (list, tuple)) else [args[1]]
            _write("exec", argv=[str(a)[:200] for a in argv][:20])
        elif event in ("os.system", "os.exec", "os.posix_spawn", "os.spawn"):
            _write("exec", argv=[str(a)[:200] for a in args][:6])
        elif event in ("os.remove", "os.rename", "os.chmod", "shutil.rmtree"):
            _write("change", op=event, path=str(args[0]))
    except Exception:
        pass


if _TRACE:
    sys.addaudithook(_hook)
