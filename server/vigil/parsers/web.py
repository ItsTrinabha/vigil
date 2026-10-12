"""Web server access logs: NCSA common/combined (nginx, Apache, Caddy-compatible)
and JSON access logs."""
from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import unquote_plus

_COMBINED = re.compile(
    r'^(?:(?P<vhost>\S+)\s+)??(?P<ip>[0-9a-fA-F:.]+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?(?P<extra>.*)$')


def _ts(s: str) -> float | None:
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


def _split_request(req: str) -> tuple[str | None, str, str | None]:
    parts = req.split(" ")
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], None
    return None, req, None


def _http_fields(ip, method, target, proto, status, size, referer, ua, user=None) -> dict:
    path, _, query = (target or "").partition("?")
    f = {
        "event.category": "webserver", "event.action": "http_request",
        "event.outcome": "failure" if status and int(status) >= 400 else "success",
        "source.ip": ip, "http.request.method": method, "url.original": target, "url.path": path,
        "url.query": query or None, "url.decoded": unquote_plus(target or ""),
        "http.response.status_code": int(status) if status else None,
        "http.response.body.bytes": int(size) if size and str(size).isdigit() else None,
        "http.version": proto.split("/", 1)[1] if proto and "/" in proto else None,
        "http.request.referrer": referer if referer not in (None, "-", "") else None,
        "user_agent.original": ua if ua not in (None, "-", "") else None,
    }
    if user and user != "-":
        f["user.name"] = user
    return {k: v for k, v in f.items() if v is not None}


def parse_access_line(line: str) -> tuple[float | None, dict] | None:
    line = line.strip()
    if line.startswith("{"):
        return _parse_json(line)
    m = _COMBINED.match(line)
    if not m:
        return None
    method, target, proto = _split_request(m["request"])
    f = _http_fields(m["ip"], method, target, proto, m["status"], m["size"], m["referer"], m["ua"], m["user"])
    if m["vhost"]:
        f["url.domain"] = m["vhost"].split(":")[0]
    return _ts(m["time"]), f


def _parse_json(line: str) -> tuple[float | None, dict] | None:
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    pick = lambda *ks: next((d[k] for k in ks if d.get(k) not in (None, "")), None)  # noqa: E731
    ip = pick("remote_addr", "client_ip", "remote_ip", "ip", "clientip")
    req = pick("request")
    method, target, proto = _split_request(req) if req else (pick("method", "request_method"), pick("uri", "request_uri", "path"), pick("protocol", "server_protocol"))
    status = pick("status", "response_status")
    if ip is None or status is None:
        return None
    f = _http_fields(ip, method, target, proto, status, pick("body_bytes_sent", "bytes", "size"),
                     pick("http_referer", "referer"), pick("http_user_agent", "user_agent"), pick("remote_user"))
    ts = None
    t = pick("time_local", "time", "timestamp", "time_iso8601")
    if isinstance(t, (int, float)):
        ts = float(t)
    elif isinstance(t, str):
        ts = _ts(t)
        if ts is None:
            from .syslog import parse_iso
            ts = parse_iso(t)
    return ts, f
