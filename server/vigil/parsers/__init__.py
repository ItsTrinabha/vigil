"""Turn raw records from agents and syslog senders into normalised events.

A normalised event is a flat dict with ECS-style dotted keys. A few keys are
always present:

    @timestamp     epoch seconds (float)
    host.name      originating host
    message        the raw log line (used by Sigma keyword rules and FTS)
    log.product    Sigma logsource product   (linux, windows, ...)
    log.services   Sigma logsource services  (["sshd", "auth"], ...)
    log.category   Sigma logsource category  (process_creation, webserver, ...)
    event.category / event.action / event.outcome
"""
from __future__ import annotations

import json
import time
from typing import Any

from .auditd import AuditAssembler, parse_audit_line, record_fields
from .linux import parse_program
from .syslog import parse_syslog
from .web import parse_access_line
from .windows import parse_windows, xml_to_record

Event = dict[str, Any]

WEB_HINTS = ("access.log", "access_log", "/nginx/", "/apache2/", "/httpd/", "/caddy/")
AUDIT_HINTS = ("audit.log", "/audit/")


def guess_sourcetype(path: str) -> str:
    p = path.lower()
    if any(h in p for h in AUDIT_HINTS):
        return "auditd"
    if any(h in p for h in WEB_HINTS) and "error" not in p:
        return "web"
    return "syslog"


class Normalizer:
    def __init__(self) -> None:
        self.audit = AuditAssembler()

    # ------------------------------------------------------------------
    def parse(self, record: dict, host: str | None = None, agent_id: str | None = None,
              tz_offset: int = 0) -> list[Event]:
        rtype = record.get("type", "file")
        try:
            if rtype == "journald":
                events = self._journald(record.get("entry") or {}, host, tz_offset)
            elif rtype == "process":
                events = [self._process(record.get("data") or {}, host)]
            elif rtype == "wineventlog":
                events = self._windows(record, host)
            elif rtype == "event":  # already-normalised (e.g. Vigil's own audit events)
                events = [dict(record.get("fields") or {})]
            else:
                events = self._line(record, host, tz_offset)
        except Exception as exc:  # never drop a record because a parser failed
            events = [self._raw(str(record.get("line") or record)[:8192], host, error=repr(exc))]
        now = time.time()
        out = []
        for ev in events:
            if ev is None:
                continue
            ev.setdefault("@timestamp", record.get("ts") or now)
            if host and not ev.get("host.name"):
                ev["host.name"] = host
            if agent_id:
                ev["agent.id"] = agent_id
            if record.get("path"):
                ev.setdefault("log.file.path", record["path"])
            ev.setdefault("log.source", rtype if rtype != "file" else "file")
            ev.setdefault("log.services", [])
            ev.setdefault("event.category", "other")
            ev.setdefault("event.action", "log")
            out.append({k: v for k, v in ev.items() if v is not None})
        return out

    def flush(self) -> list[Event]:
        return [self._audit_process(e) for e in self.audit.flush()]

    # ------------------------------------------------------------------
    def _raw(self, line: str, host: str | None, error: str | None = None) -> Event:
        ev: Event = {"message": line, "host.name": host, "log.product": "linux", "log.services": []}
        if error:
            ev["vigil.parse_error"] = error
        return ev

    def _line(self, record: dict, host: str | None, tz_offset: int) -> list[Event]:
        line = (record.get("line") or "").rstrip("\r\n")
        if not line.strip():
            return []
        st = record.get("sourcetype") or "auto"
        if st == "auto":
            st = guess_sourcetype(record.get("path") or "") if record.get("type") != "syslog" else "syslog"
            if st == "syslog" and line.lstrip().startswith("type=") and "msg=audit(" in line:
                st = "auditd"
        if st == "web":
            parsed = parse_access_line(line)
            if parsed:
                ts, f = parsed
                ev = {"message": line, "@timestamp": ts, "log.product": "linux", "log.services": ["webserver"],
                      "log.category": "webserver", **f}
                return [ev]
            return [self._raw(line, host)]
        if st == "auditd":
            return self._auditd(line, host)
        if st == "json":
            try:
                d = json.loads(line)
                return [{"message": line, **{str(k): v for k, v in d.items() if isinstance(v, (str, int, float, bool))}}]
            except ValueError:
                return [self._raw(line, host)]
        return [self._syslog_line(line, host, tz_offset, record.get("type") == "syslog")]

    def _syslog_line(self, line: str, host: str | None, tz_offset: int, network: bool = False) -> Event:
        hdr = parse_syslog(line, tz_offset)
        if hdr is None:
            # Not syslog framed: maybe an access log or audit line sent over syslog.
            web = parse_access_line(line)
            if web:
                ts, f = web
                return {"message": line, "@timestamp": ts, "log.product": "linux", "log.services": ["webserver"],
                        "log.category": "webserver", **f}
            return self._raw(line, host)
        ev = self._program_event(hdr.program, hdr.pid, hdr.message, hdr.ts)
        # Over the network the header host is authoritative; from a local file the agent's hostname is.
        ev["host.name"] = (hdr.host if network and hdr.host else None) or host or hdr.host
        if hdr.facility:
            ev["log.syslog.facility"] = hdr.facility
        if hdr.severity is not None:
            ev["log.syslog.severity"] = hdr.severity
        if hdr.structured:
            for sd_id, params in hdr.structured.items():
                for k, v in params.items():
                    ev[f"syslog.sd.{sd_id}.{k}"] = v
        return ev

    def _program_event(self, program: str | None, pid: int | None, msg: str, ts: float | None) -> Event:
        ev: Event = {"message": msg, "@timestamp": ts, "log.product": "linux", "process.name": program,
                     "process.pid": pid, "log.services": ["syslog"]}
        if program == "audit" or (msg.startswith("type=") and "msg=audit(" in msg):
            pass
        fields, services = parse_program(program, msg)
        if services:
            ev["log.services"] = list(dict.fromkeys([*list(services), "syslog"]))
        if fields:
            # A sudo/cron "process.name" means the command run, keep the logger under log.program.
            ev["log.program"] = program
            ev.update(fields)
        else:
            ev["log.program"] = program
        return ev

    def _auditd(self, line: str, host: str | None) -> list[Event]:
        parsed = parse_audit_line(line)
        if not parsed:
            return [self._raw(line, host)]
        ts, serial, rtype, kv = parsed
        ev: Event = {"message": line, "@timestamp": ts, "log.product": "linux", "log.services": ["auditd"],
                     **record_fields(rtype, kv)}
        out = [ev]
        for proc in self.audit.add(host or kv.get("node") or "", ts, serial, rtype, kv):
            out.append(self._audit_process(proc))
        return out

    def _audit_process(self, p: dict) -> Event:
        f = p["fields"]
        ev: Event = {"@timestamp": p["ts"], "host.name": p["host"] or None, "log.product": "linux",
                     "log.category": "process_creation", "log.services": ["auditd"],
                     "message": f"execve: {f.get('process.command_line', '')}", **f}
        return _sigma_process_aliases(ev)

    def _journald(self, e: dict, host: str | None, tz_offset: int) -> list[Event]:
        msg = e.get("MESSAGE")
        if isinstance(msg, list):  # journald encodes non-UTF8 as byte arrays
            msg = bytes(msg).decode("utf-8", "replace")
        msg = msg or ""
        program = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM")
        pid = e.get("_PID") or e.get("SYSLOG_PID")
        ts = None
        if e.get("__REALTIME_TIMESTAMP"):
            ts = int(e["__REALTIME_TIMESTAMP"]) / 1e6
        if program == "audit" or (e.get("_TRANSPORT") == "audit"):
            line = msg if msg.startswith("type=") else f"type={e.get('_AUDIT_TYPE_NAME', 'UNKNOWN')} msg=audit({ts or time.time():.3f}:{e.get('_AUDIT_ID', 0)}): {msg}"
            return self._auditd(line, host or e.get("_HOSTNAME"))
        ev = self._program_event(program, int(pid) if str(pid or "").isdigit() else None, msg, ts)
        ev["host.name"] = host or e.get("_HOSTNAME")
        if e.get("_SYSTEMD_UNIT"):
            ev["systemd.unit"] = e["_SYSTEMD_UNIT"]
        if e.get("PRIORITY") is not None and str(e.get("PRIORITY")).isdigit():
            ev["log.syslog.severity"] = int(e["PRIORITY"])
        return [ev]

    def _process(self, d: dict, host: str | None) -> Event:
        cmd = d.get("cmdline") or ""
        ev: Event = {
            "@timestamp": d.get("start_ts"), "log.product": "linux", "log.category": "process_creation",
            "log.services": ["proc"], "event.category": "process_creation", "event.action": "process_started",
            "event.outcome": "success", "process.pid": d.get("pid"), "process.parent.pid": d.get("ppid"),
            "process.executable": d.get("exe"), "process.name": d.get("name") or (d.get("exe") or "").rsplit("/", 1)[-1],
            "process.command_line": cmd, "process.working_directory": d.get("cwd"),
            "process.parent.executable": d.get("parent_exe"), "process.parent.command_line": d.get("parent_cmdline"),
            "process.parent.name": d.get("parent_name"), "user.name": d.get("user"), "user.id": d.get("uid"),
            "message": f"process started: {cmd}" if cmd else f"process started: {d.get('exe')}",
        }
        return _sigma_process_aliases(ev)

    def _windows(self, record: dict, host: str | None) -> list[Event]:
        rec = record.get("data")
        if rec is None and record.get("xml"):
            rec = xml_to_record(record["xml"])
        if not rec:
            return [self._raw(str(record.get("xml") or "")[:4096], host)]
        ts, computer, f, ls = parse_windows(rec)
        ev: Event = {"@timestamp": ts, "host.name": computer or host, "log.product": "windows",
                     "log.services": [ls["service"]] if ls["service"] else [], "log.category": ls["category"],
                     "message": record.get("message") or _win_message(f), **f}
        return [ev]


def _win_message(f: dict) -> str:
    keys = [k for k in f if "." not in k and k not in ("Channel", "Provider_Name", "Computer")]
    return " ".join(f"{k}={f[k]}" for k in keys[:24])


def _sigma_process_aliases(ev: Event) -> Event:
    """Expose Sigma process_creation taxonomy names next to the normalised ones."""
    ev["Image"] = ev.get("process.executable")
    ev["CommandLine"] = ev.get("process.command_line")
    ev["ParentImage"] = ev.get("process.parent.executable")
    ev["ParentCommandLine"] = ev.get("process.parent.command_line")
    ev["User"] = ev.get("user.name")
    ev["CurrentDirectory"] = ev.get("process.working_directory")
    ev["ProcessId"] = ev.get("process.pid")
    ev["ParentProcessId"] = ev.get("process.parent.pid")
    return ev
