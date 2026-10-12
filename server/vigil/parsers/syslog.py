"""Syslog header parsing: RFC 3164 (BSD), RFC 5424 and rsyslog's ISO-8601 format.

Returns a SyslogHeader with the timestamp resolved to epoch seconds. BSD
syslog has no year or timezone, so the caller passes the sender's UTC offset
(the agent reports it) and a reference time used to infer the year.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
              "authpriv", "ftp", "ntp", "security", "console", "solaris-cron"] + [f"local{i}" for i in range(8)]

_PRI = re.compile(r"^<(\d{1,3})>")
_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?:(?P<host>[^\s:]+)\s+)?(?P<rest>.*)$", re.S)
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$", re.S)
_5424 = re.compile(
    r"^1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)\s?(?P<msg>.*)$", re.S)
_TAG = re.compile(r"^(?P<prog>[\w./@-]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$", re.S)
_SD_ELEM = re.compile(r"\[(\S+?)((?:\s+[^=\s]+=\"(?:[^\"\\]|\\.)*\")*)\]")
_SD_PARAM = re.compile(r"([^=\s]+)=\"((?:[^\"\\]|\\.)*)\"")


@dataclass
class SyslogHeader:
    ts: float | None
    host: str | None
    program: str | None
    pid: int | None
    message: str
    facility: str | None = None
    severity: int | None = None
    structured: dict | None = None


def parse_iso(ts: str, default_offset: int = 0) -> float | None:
    s = ts.replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    m = re.match(r"^(.*[+-]\d{2})(\d{2})$", s)  # +0000 -> +00:00
    if m and "T" in s and ":" not in s[-5:]:
        s = f"{m.group(1)}:{m.group(2)}"
    if "." in s:  # trim fractional seconds beyond microseconds
        head, _, tail = s.partition(".")
        frac = re.match(r"\d+", tail).group(0)
        s = f"{head}.{frac[:6]}{tail[len(frac):]}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(seconds=default_offset)))
    return dt.timestamp()


def parse_bsd_time(mon: str, day: str, hms: str, tz_offset: int = 0, now: float | None = None) -> float | None:
    if mon not in MONTHS:
        return None
    now = now or time.time()
    tz = timezone(timedelta(seconds=tz_offset))
    year = datetime.fromtimestamp(now, tz).year
    h, m, s = (int(x) for x in hms.split(":"))
    try:
        dt = datetime(year, MONTHS[mon], int(day), h, m, s, tzinfo=tz)
    except ValueError:
        return None
    # A December line read in January belongs to last year.
    if dt.timestamp() - now > 2 * 86400:
        dt = dt.replace(year=year - 1)
    return dt.timestamp()


def _split_tag(rest: str) -> tuple[str | None, int | None, str]:
    m = _TAG.match(rest)
    if not m:
        return None, None, rest
    pid = int(m.group("pid")) if m.group("pid") else None
    return m.group("prog"), pid, m.group("msg")


def parse_syslog(line: str, tz_offset: int = 0, now: float | None = None) -> SyslogHeader | None:
    line = line.rstrip("\r\n")
    facility = severity = None
    m = _PRI.match(line)
    if m:
        pri = int(m.group(1))
        fac_num, severity = divmod(pri, 8)
        facility = FACILITIES[fac_num] if fac_num < len(FACILITIES) else str(fac_num)
        line = line[m.end():]

    m = _5424.match(line)
    if m:
        sd = None
        if m.group("sd") != "-":
            sd = {}
            for sd_id, params in _SD_ELEM.findall(m.group("sd")):
                sd[sd_id] = {k: v.replace('\\"', '"') for k, v in _SD_PARAM.findall(params)}
        msg = m.group("msg")
        if msg.startswith("﻿"):
            msg = msg[1:]
        dash = lambda v: None if v == "-" else v  # noqa: E731
        pid = dash(m.group("procid"))
        return SyslogHeader(
            ts=parse_iso(m.group("ts"), tz_offset) if m.group("ts") != "-" else None,
            host=dash(m.group("host")), program=dash(m.group("app")),
            pid=int(pid) if pid and pid.isdigit() else None, message=msg,
            facility=facility, severity=severity, structured=sd)

    m = _ISO.match(line)
    if m:
        ts = parse_iso(m.group("ts"), tz_offset)
        if ts is not None:
            prog, pid, msg = _split_tag(m.group("rest"))
            return SyslogHeader(ts, m.group("host"), prog, pid, msg, facility, severity)

    m = _BSD.match(line)
    if m:
        ts = parse_bsd_time(m.group("mon"), m.group("day"), m.group("time"), tz_offset, now)
        host, rest = m.group("host"), m.group("rest")
        # "host" may actually be the tag when the sender omitted the hostname.
        if host and _TAG.match(host + " ") and host.endswith(":"):
            rest, host = f"{host} {rest}", None
        prog, pid, msg = _split_tag(rest)
        if prog is None and host and re.match(r"^[\w./@-]+(\[\d+\])?:$", host):
            prog, pid, msg = _split_tag(f"{host} {rest}")
            host = None
        return SyslogHeader(ts, host, prog, pid, msg, facility, severity)
    return None
