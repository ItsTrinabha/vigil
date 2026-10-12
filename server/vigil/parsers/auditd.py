"""Linux audit (auditd) log parsing.

Each audit record line becomes an event (Sigma auditd rules match single
records such as `type: EXECVE` with `a0`, `a1` ...). Records that share an
audit serial are also assembled, and an execve SYSCALL + EXECVE (+ CWD,
PROCTITLE) group is emitted as a process_creation event so the SigmaHQ
process_creation rules work on hosts running auditd.
"""
from __future__ import annotations

import re
import threading
import time

_HEADER = re.compile(r"^(?:node=(?P<node>\S+) )?type=(?P<type>\S+) msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\):\s?(?P<body>.*)$")
_KV = re.compile(r"""(\w[\w-]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)""")


def _decode(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    # Unquoted values of argument fields are hex-encoded when they contain spaces/specials.
    if len(v) >= 2 and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-F]+", v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace").replace("\x00", " ")
        except ValueError:
            return v
    return v


HEXABLE = re.compile(r"^(a\d+|proctitle|name|cwd|exe|comm|data|cmd)$")


def parse_audit_line(line: str) -> tuple[float, int, str, dict] | None:
    m = _HEADER.match(line.replace("\x1d", " ").strip())
    if not m:
        return None
    body = m["body"]
    # USER_* records carry a nested msg='...' with more key=value pairs.
    nested = re.search(r"msg='(.*)'$", body)
    kv = {}
    rtype = m["type"]
    for k, v in _KV.findall(body if not nested else body[: nested.start()]):
        hexable = HEXABLE.match(k) and not (rtype == "SYSCALL" and re.fullmatch(r"a\d+", k))
        kv[k] = _decode(v) if hexable or v[:1] in "\"'" else v
    if nested:
        for k, v in _KV.findall(nested.group(1)):
            kv[k] = _decode(v) if v[:1] in "\"'" or HEXABLE.match(k) else v
    kv["type"] = m["type"]
    if m["node"]:
        kv["node"] = m["node"]
    return float(m["ts"]), int(m["serial"]), m["type"], kv


def record_fields(rtype: str, kv: dict) -> dict:
    """Normalised fields for a single audit record."""
    f: dict = {"auditd.type": rtype}
    for k, v in kv.items():
        f[k] = v  # raw names for Sigma auditd rules (type, a0, key, exe, comm, ...)
    if rtype.startswith("USER_") or rtype in ("CRED_ACQ", "CRED_DISP", "LOGIN"):
        f["event.category"] = "authentication"
        f["event.action"] = f"audit_{rtype.lower()}"
        res = kv.get("res")
        if res:
            f["event.outcome"] = "success" if res in ("success", "yes", "1") else "failure"
        if kv.get("acct"):
            f["user.name"] = kv["acct"]
        if kv.get("addr") and kv["addr"] not in ("?", "-"):
            f["source.ip"] = kv["addr"]
    elif rtype == "ADD_USER":
        f.update({"event.category": "iam", "event.action": "user_created", "user.target.name": kv.get("acct") or kv.get("id")})
    elif rtype == "ADD_GROUP":
        f.update({"event.category": "iam", "event.action": "group_created", "group.name": kv.get("acct") or kv.get("id")})
    else:
        f["event.category"] = "audit"
        f["event.action"] = f"audit_{rtype.lower()}"
    return f


class AuditAssembler:
    """Groups audit records by (host, serial) to build process_creation events."""

    def __init__(self, max_age: float = 3.0):
        self.max_age = max_age
        self._pending: dict[tuple[str, int], dict] = {}
        self._lock = threading.Lock()

    def add(self, host: str, ts: float, serial: int, rtype: str, kv: dict) -> list[dict]:
        key = (host, serial)
        out: list[dict] = []
        with self._lock:
            grp = self._pending.setdefault(key, {"ts": ts, "host": host, "records": {}, "seen": time.monotonic()})
            if rtype == "EOE":
                out.extend(self._finish(key))
            else:
                grp["records"].setdefault(rtype, kv)
                if rtype == "PROCTITLE" and "EXECVE" in grp["records"]:
                    out.extend(self._finish(key))
            out.extend(self._expire())
        return out

    def flush(self) -> list[dict]:
        with self._lock:
            return [e for k in list(self._pending) for e in self._finish(k)]

    def _expire(self) -> list[dict]:
        now = time.monotonic()
        out = []
        for k in [k for k, g in self._pending.items() if now - g["seen"] > self.max_age]:
            out.extend(self._finish(k))
        return out

    def _finish(self, key) -> list[dict]:
        grp = self._pending.pop(key, None)
        if not grp:
            return []
        recs = grp["records"]
        sc, ex = recs.get("SYSCALL"), recs.get("EXECVE")
        if not ex:
            return []
        argc = int(ex.get("argc", "0") or 0)
        args = [ex.get(f"a{i}", "") for i in range(argc)] if argc else []
        cmdline = " ".join(args) if args else (recs.get("PROCTITLE", {}).get("proctitle") or "")
        sc = sc or {}
        exe = sc.get("exe") or (args[0] if args else None)
        f = {
            "event.category": "process_creation", "event.action": "process_started", "event.outcome": "success",
            "process.executable": exe, "process.command_line": cmdline,
            "process.name": (exe or "").rsplit("/", 1)[-1] or None,
            "process.pid": int(sc["pid"]) if sc.get("pid", "").isdigit() else None,
            "process.parent.pid": int(sc["ppid"]) if sc.get("ppid", "").isdigit() else None,
            "process.working_directory": recs.get("CWD", {}).get("cwd"),
            "user.id": sc.get("uid"), "user.effective_id": sc.get("euid"), "audit.auid": sc.get("auid"),
            "user.name": sc.get("UID") or sc.get("uid"), "audit.key": sc.get("key"),
            "process.tty": sc.get("tty"), "audit.serial": key[1],
        }
        return [{"ts": grp["ts"], "host": grp["host"], "fields": {k: v for k, v in f.items() if v not in (None, "", "(null)")}}]
