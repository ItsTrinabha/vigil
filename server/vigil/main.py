"""HTTP API and web UI."""

import asyncio
import gzip
import ipaddress
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import search as vql
from .app import VERSION, Vigil, start_syslog
from .config import Settings, get_settings
from .db import loads
from .detection.correlation import compile_correlation
from .detection.sigma import compile_rule
from .enrich import attack
from .pipeline import Batch

log = logging.getLogger("vigil.api")
STATIC = Path(__file__).parent / "static"
COOKIE = "vigil_session"
RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
MAX_INGEST_BYTES = 10 * 1024 * 1024


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    vigil = Vigil(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        vigil.broadcaster.loop = asyncio.get_running_loop()
        vigil.start()
        servers = None
        if settings.syslog_enabled:
            try:
                servers = await start_syslog(vigil, settings.host, settings.syslog_port)
            except OSError as exc:
                log.warning("syslog listener disabled: %s", exc)
        yield
        if servers:
            servers[0].close()
            servers[1].close()
        vigil.stop()

    app = FastAPI(title="Vigil SIEM", version=VERSION, lifespan=lifespan, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.vigil = vigil
    db = vigil.db

    # ------------------------------------------------------------ middleware
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api/") \
                and not request.url.path.startswith("/api/v1/") and request.url.path != "/api/auth/login" \
                and request.headers.get("x-vigil-request") != "1":
            return JSONResponse({"detail": "missing X-Vigil-Request header"}, status_code=403)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith("/api/docs"):
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if settings.tls:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    # ------------------------------------------------------------ auth deps
    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def current_user(request: Request) -> dict:
        user = vigil.auth.session_user(request.cookies.get(COOKIE))
        if not user:
            raise HTTPException(401, "not authenticated")
        return user

    def analyst(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in ("admin", "analyst"):
            raise HTTPException(403, "analyst role required")
        return user

    def admin(user: dict = Depends(current_user)) -> dict:
        if user["role"] != "admin":
            raise HTTPException(403, "admin role required")
        return user

    def agent(request: Request) -> dict:
        h = request.headers.get("authorization", "")
        a = vigil.auth.agent_for_token(h[7:] if h.lower().startswith("bearer ") else None)
        if not a:
            raise HTTPException(401, "invalid agent token")
        return a

    def time_range(range: str = "24h", start: float | None = None, end: float | None = None) -> tuple[float, float]:
        now = time.time()
        if start is not None:
            return float(start), float(end or now)
        return now - RANGES.get(range, 86400), now

    # ------------------------------------------------------------ public
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": VERSION, "uptime_s": int(time.time() - vigil.started)}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        p = vigil.pipeline
        lines = [
            "# TYPE vigil_events_processed_total counter", f"vigil_events_processed_total {p.processed}",
            "# TYPE vigil_detections_total counter", f"vigil_detections_total {p.detections}",
            "# TYPE vigil_pipeline_errors_total counter", f"vigil_pipeline_errors_total {p.errors}",
            "# TYPE vigil_pipeline_queue_depth gauge", f"vigil_pipeline_queue_depth {p.q.qsize()}",
            "# TYPE vigil_events_per_second gauge", f"vigil_events_per_second {p.eps()}",
            "# TYPE vigil_rules_loaded gauge", f"vigil_rules_loaded {vigil.engine.report.rules + vigil.engine.report.correlations}",
        ]
        return "\n".join(lines) + "\n"

    class LoginBody(BaseModel):
        username: str = Field(max_length=64)
        password: str = Field(max_length=256)

    @app.post("/api/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        ip = client_ip(request)
        token, reason = vigil.auth.authenticate(body.username, body.password, ip)
        if not token:
            vigil.self_event("vigil_login_failed", "failure", body.username, ip, **{"vigil.reason": reason})
            if reason == "throttled":
                raise HTTPException(429, "too many failed attempts, try again in a few minutes")
            raise HTTPException(401, "invalid username or password")
        vigil.self_event("vigil_login_success", "success", body.username, ip)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=settings.tls,
                            max_age=settings.session_hours * 3600, path="/")
        return vigil.auth.session_user(token)

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        vigil.auth.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(user: dict = Depends(current_user)):
        return user

    class PasswordBody(BaseModel):
        current: str
        new: str = Field(min_length=10, max_length=256)

    @app.post("/api/auth/password")
    def change_password(body: PasswordBody, request: Request, user: dict = Depends(current_user)):
        row = db.query_one("SELECT password_hash FROM users WHERE username=?", (user["username"],))
        from .auth import verify_password
        if not row or not verify_password(body.current, row["password_hash"]):
            raise HTTPException(400, "current password is wrong")
        vigil.auth.set_password(user["username"], body.new)
        db.audit(user["username"], "password_changed", user["username"])
        vigil.self_event("vigil_password_changed", "success", user["username"], client_ip(request))
        return {"ok": True}

    # ------------------------------------------------------------ users
    class UserBody(BaseModel):
        username: str
        password: str
        role: str = "analyst"

    @app.get("/api/users")
    def users(user: dict = Depends(admin)):
        return db.query("SELECT username, role, created_ts, disabled FROM users ORDER BY username")

    @app.post("/api/users")
    def create_user(body: UserBody, request: Request, user: dict = Depends(admin)):
        try:
            u = vigil.auth.create_user(body.username, body.password, body.role)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        except Exception:
            raise HTTPException(409, "user already exists") from None
        db.audit(user["username"], "user_created", body.username, {"role": body.role})
        vigil.self_event("vigil_user_created", "success", user["username"], client_ip(request),
                         **{"user.target.name": body.username, "vigil.role": body.role})
        return u

    @app.delete("/api/users/{username}")
    def delete_user(username: str, user: dict = Depends(admin)):
        if username == user["username"]:
            raise HTTPException(400, "cannot delete yourself")
        db.execute("UPDATE users SET disabled=1 WHERE username=?", (username,))
        db.execute("DELETE FROM sessions WHERE username=?", (username,))
        db.audit(user["username"], "user_disabled", username)
        return {"ok": True}

    # ------------------------------------------------------------ agents API
    class EnrollBody(BaseModel):
        enrollment_token: str
        hostname: str
        os: str = ""
        version: str = ""

    @app.post("/api/v1/agents/enroll")
    def enroll(body: EnrollBody, request: Request):
        res = vigil.auth.enroll_agent(body.enrollment_token, settings.enrollment_token, body.hostname, body.os,
                                      body.version, client_ip(request))
        if not res:
            vigil.self_event("vigil_agent_enroll_failed", "failure", None, client_ip(request), **{"agent.hostname": body.hostname})
            raise HTTPException(401, "invalid enrollment token")
        db.audit("agent", "agent_enrolled", res["agent_id"], {"hostname": body.hostname, "ip": client_ip(request)})
        return res

    @app.post("/api/v1/ingest")
    async def ingest(request: Request, a: dict = Depends(agent)):
        raw = await request.body()
        if len(raw) > MAX_INGEST_BYTES:
            raise HTTPException(413, "batch too large")
        if request.headers.get("content-encoding") == "gzip":
            try:
                raw = gzip.decompress(raw)
            except OSError:
                raise HTTPException(400, "bad gzip body") from None
            if len(raw) > 8 * MAX_INGEST_BYTES:
                raise HTTPException(413, "batch too large")
        try:
            body = json.loads(raw)
            records = body["records"]
            assert isinstance(records, list)
        except Exception:
            raise HTTPException(400, "expected JSON {records: [...]}") from None
        host = str(body.get("host") or a["hostname"])[:255]
        tz = int(body.get("tz_offset") or 0)
        if not vigil.pipeline.submit(Batch(records[:20000], host, a["id"], tz)):
            raise HTTPException(429, "pipeline busy, retry later")
        db.execute("UPDATE agents SET last_seen=?, events_received=events_received+?, hostname=?, ip=? WHERE id=?",
                   (time.time(), len(records), host, client_ip(request), a["id"]))
        return {"accepted": len(records)}

    @app.post("/api/v1/heartbeat")
    async def heartbeat(request: Request, a: dict = Depends(agent)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        db.execute("UPDATE agents SET last_seen=?, inputs=?, version=COALESCE(?, version), os=COALESCE(?, os) WHERE id=?",
                   (time.time(), json.dumps(body.get("inputs") or [])[:20000], body.get("version"), body.get("os"), a["id"]))
        return {"ok": True, "server_time": time.time()}

    @app.get("/api/agents")
    def agents(user: dict = Depends(current_user)):
        rows = db.query("SELECT id, hostname, os, version, ip, enrolled_ts, last_seen, events_received, inputs, status "
                        "FROM agents ORDER BY hostname")
        silence = settings.agent_silence_minutes * 60
        for r in rows:
            r["inputs"] = json.loads(r["inputs"])
            r["health"] = "revoked" if r["status"] != "active" else (
                "healthy" if r["last_seen"] and time.time() - r["last_seen"] < silence else "silent")
        return rows

    @app.post("/api/agents/{agent_id}/revoke")
    def revoke_agent(agent_id: str, user: dict = Depends(admin)):
        db.execute("UPDATE agents SET status='revoked' WHERE id=?", (agent_id,))
        db.audit(user["username"], "agent_revoked", agent_id)
        return {"ok": True}

    def ca_cert_path() -> Path | None:
        if not settings.tls:
            return None
        p = Path(settings.tls_cert) if settings.tls_cert else settings.data_dir / "tls" / "vigil.crt"
        return p if p.exists() else None

    @app.get("/api/agents/enrollment")
    def enrollment(request: Request, user: dict = Depends(admin)):
        base = settings.public_url or str(request.base_url).rstrip("/")
        ca = ca_cert_path()
        fp = None
        if ca:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            fp = x509.load_pem_x509_certificate(ca.read_bytes()).fingerprint(hashes.SHA256()).hex()
        pin = f"VIGIL_CA_SHA256={fp} " if fp else ""
        return {"enrollment_token": settings.enrollment_token, "server_url": base, "ca_sha256": fp,
                "install_command": f"curl -fsSLk {base}/agent/install.sh | sudo VIGIL_SERVER={base} "
                                   f"VIGIL_ENROLL_TOKEN={settings.enrollment_token} {pin}bash"}

    # ------------------------------------------------------------ overview
    @app.get("/api/overview")
    def overview(tr: tuple = Depends(time_range), user: dict = Depends(current_user)):
        start, end = tr
        span = end - start
        bucket = max(60, int(span / 48))
        events_total = db.query_one("SELECT COALESCE(SUM(events),0) AS n FROM stats_minute WHERE minute >= ? AND minute <= ?",
                                    (int(start // 60), int(end // 60)))["n"]
        timeline = db.query(
            "SELECT (minute*60 - ?) / ? AS b, SUM(events) AS n FROM stats_minute WHERE minute >= ? AND minute <= ? GROUP BY b",
            (int(start), bucket, int(start // 60), int(end // 60)))
        nb = int(span // bucket) + 1
        ev_series = [0] * nb
        for r in timeline:
            if 0 <= int(r["b"]) < nb:
                ev_series[int(r["b"])] += r["n"]
        al_series = {s: [0] * nb for s in ("low", "medium", "high", "critical")}
        for r in db.query("SELECT CAST((created_ts - ?) / ? AS INTEGER) AS b, severity, COUNT(*) AS n FROM alerts "
                          "WHERE created_ts >= ? AND created_ts <= ? GROUP BY b, severity", (start, bucket, start, end)):
            if r["severity"] in al_series and 0 <= r["b"] < nb:
                al_series[r["severity"]][r["b"]] += r["n"]
        sev = {r["severity"]: r["n"] for r in db.query(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE created_ts >= ? GROUP BY severity", (start,))}
        open_alerts = db.query_one("SELECT COUNT(*) AS n FROM alerts WHERE status != 'closed'")["n"]
        open_inc = db.query("SELECT * FROM incidents WHERE status != 'closed' ORDER BY risk DESC, last_ts DESC LIMIT 6")
        for i in open_inc:
            loads(i, "entities", "tactics", "techniques")
        top_src = db.query(
            "SELECT src_ip AS ip, src_country AS country, COUNT(*) AS n, SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END) AS failures "
            "FROM events WHERE ts >= ? AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT 8", (start,))
        for s in top_src:
            s["intel"] = [h["feed"] for h in vigil.intel.lookup(s["ip"])]
        countries = db.query("SELECT src_country AS country, COUNT(*) AS n FROM events WHERE ts >= ? AND src_country IS NOT NULL "
                             "GROUP BY src_country ORDER BY n DESC LIMIT 10", (start,))
        top_rules = db.query("SELECT rule_title, severity, COUNT(*) AS alerts, SUM(count) AS hits FROM alerts WHERE created_ts >= ? "
                             "GROUP BY rule_id ORDER BY alerts DESC, hits DESC LIMIT 8", (start,))
        tactic_counts: dict[str, int] = {}
        for r in db.query("SELECT tactics FROM alerts WHERE created_ts >= ?", (start,)):
            for t in json.loads(r["tactics"]):
                tactic_counts[t] = tactic_counts.get(t, 0) + 1
        auth_stats = db.query_one(
            "SELECT SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END) AS failed, SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS ok "
            "FROM events WHERE ts >= ? AND category IN ('authentication')", (start,))
        agents = db.query("SELECT last_seen, status FROM agents")
        silence = settings.agent_silence_minutes * 60
        return {
            "range": {"start": start, "end": end, "bucket": bucket},
            "events_total": events_total, "eps": vigil.pipeline.eps(), "queue": vigil.pipeline.q.qsize(),
            "alerts_by_severity": sev, "open_alerts": open_alerts,
            "open_incidents": db.query_one("SELECT COUNT(*) AS n FROM incidents WHERE status != 'closed'")["n"],
            "incidents": open_inc, "events_series": ev_series, "alerts_series": al_series,
            "top_sources": top_src, "countries": countries, "top_rules": top_rules,
            "tactics": [{"short": t["short"], "name": t["name"], "count": tactic_counts.get(t["short"], 0)} for t in attack.tactics()],
            "auth": {"failed": auth_stats["failed"] or 0, "success": auth_stats["ok"] or 0},
            "agents": {"total": len(agents), "healthy": sum(1 for a in agents if a["status"] == "active" and a["last_seen"]
                                                            and time.time() - a["last_seen"] < silence)},
            "rules": {"sigma": vigil.engine.report.rules, "correlation": vigil.engine.report.correlations},
            "intel_ranges": vigil.intel.summary()["total_ranges"],
        }

    # ------------------------------------------------------------ alerts
    @app.get("/api/alerts")
    def list_alerts(status: str = "", severity: str = "", q: str = "", rule_type: str = "", incident_id: int | None = None,
                    limit: int = 50, offset: int = 0, tr: tuple = Depends(time_range), user: dict = Depends(current_user)):
        where, params = ["created_ts >= ?"], [tr[0]]
        if status == "open":
            where.append("status != 'closed'")
        elif status:
            where.append("status = ?")
            params.append(status)
        if severity:
            sevs = [s for s in severity.split(",") if s]
            where.append(f"severity IN ({','.join('?' * len(sevs))})")
            params += sevs
        if rule_type:
            where.append("rule_type = ?")
            params.append(rule_type)
        if incident_id is not None:
            where = ["incident_id = ?"]
            params = [incident_id]
        if q:
            where.append("(rule_title LIKE ? OR host LIKE ? OR user_name LIKE ? OR src_ip LIKE ?)")
            params += [f"%{q}%"] * 4
        w = " AND ".join(where)
        total = db.query_one(f"SELECT COUNT(*) AS n FROM alerts WHERE {w}", params)["n"]
        rows = db.query(f"SELECT id, rule_id, rule_title, rule_type, severity, risk, first_ts, last_ts, created_ts, count, "
                        f"host, user_name, src_ip, tactics, techniques, status, resolution, assignee, incident_id "
                        f"FROM alerts WHERE {w} ORDER BY created_ts DESC LIMIT ? OFFSET ?", [*params, min(limit, 500), offset])
        for r in rows:
            loads(r, "tactics", "techniques")
        return {"total": total, "items": rows}

    def _events(ids: list[int], limit: int = 200) -> list[dict]:
        ids = ids[-limit:]
        if not ids:
            return []
        rows = db.query(f"SELECT id, ts, host, message, fields FROM events WHERE id IN ({','.join('?' * len(ids))}) ORDER BY ts",
                        ids)
        for r in rows:
            r["fields"] = json.loads(r["fields"])
        return rows

    def _comments(kind: str, target: int) -> list[dict]:
        return db.query("SELECT * FROM comments WHERE target_type=? AND target_id=? ORDER BY ts", (kind, target))

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: int, user: dict = Depends(current_user)):
        a = vigil.alerts.get(alert_id)
        if not a:
            raise HTTPException(404, "alert not found")
        a["events"] = _events(a["event_ids"])
        a["comments"] = _comments("alert", alert_id)
        a["incident"] = vigil.alerts.get_incident(a["incident_id"]) if a["incident_id"] else None
        rule = vigil.engine.get_rule(a["rule_id"])
        a["rule"] = rule.summary() if rule else None
        a["history"] = db.query("SELECT * FROM audit_log WHERE target=? ORDER BY ts", (f"alert:{alert_id}",))
        return a

    class TriageBody(BaseModel):
        status: str | None = None
        resolution: str | None = None
        assignee: str | None = None

    def _triage(kind: str, obj_id: int, body: TriageBody, user: dict) -> None:
        table = "alerts" if kind == "alert" else "incidents"
        sets, params = [], []
        if body.status is not None:
            if body.status not in ("new", "in_progress", "closed"):
                raise HTTPException(400, "status must be new, in_progress or closed")
            sets.append("status=?")
            params.append(body.status)
        if body.resolution is not None:
            if body.resolution not in ("", "true_positive", "false_positive", "benign"):
                raise HTTPException(400, "invalid resolution")
            sets.append("resolution=?")
            params.append(body.resolution or None)
        if body.assignee is not None:
            if body.assignee and not db.query_one("SELECT 1 FROM users WHERE username=?", (body.assignee,)):
                raise HTTPException(400, "unknown user")
            sets.append("assignee=?")
            params.append(body.assignee or None)
        if not sets:
            raise HTTPException(400, "nothing to update")
        cur = db.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE id=?", [*params, obj_id])
        if cur.rowcount == 0:
            raise HTTPException(404, f"{kind} not found")
        db.audit(user["username"], f"{kind}_updated", f"{kind}:{obj_id}", body.model_dump(exclude_none=True))

    @app.patch("/api/alerts/{alert_id}")
    def update_alert(alert_id: int, body: TriageBody, user: dict = Depends(analyst)):
        _triage("alert", alert_id, body, user)
        return vigil.alerts.get(alert_id)

    class BulkBody(TriageBody):
        ids: list[int]

    @app.post("/api/alerts/bulk")
    def bulk_alerts(body: BulkBody, user: dict = Depends(analyst)):
        for i in body.ids[:1000]:
            _triage("alert", i, body, user)
        return {"updated": len(body.ids[:1000])}

    class CommentBody(BaseModel):
        body: str = Field(min_length=1, max_length=10000)

    @app.post("/api/{kind}/{obj_id}/comments")
    def add_comment(kind: str, obj_id: int, body: CommentBody, user: dict = Depends(analyst)):
        if kind not in ("alerts", "incidents"):
            raise HTTPException(404, "not found")
        k = kind[:-1]
        if not db.query_one(f"SELECT 1 FROM {kind} WHERE id=?", (obj_id,)):
            raise HTTPException(404, f"{k} not found")
        db.execute("INSERT INTO comments(target_type, target_id, author, ts, body) VALUES(?,?,?,?,?)",
                   (k, obj_id, user["username"], time.time(), body.body))
        db.audit(user["username"], "comment_added", f"{k}:{obj_id}")
        return _comments(k, obj_id)

    # ------------------------------------------------------------ incidents
    @app.get("/api/incidents")
    def list_incidents(status: str = "", limit: int = 50, offset: int = 0, tr: tuple = Depends(time_range),
                       user: dict = Depends(current_user)):
        where, params = ["last_ts >= ?"], [tr[0]]
        if status == "open":
            where.append("status != 'closed'")
        elif status:
            where.append("status = ?")
            params.append(status)
        w = " AND ".join(where)
        total = db.query_one(f"SELECT COUNT(*) AS n FROM incidents WHERE {w}", params)["n"]
        rows = db.query(f"SELECT * FROM incidents WHERE {w} ORDER BY last_ts DESC LIMIT ? OFFSET ?",
                        [*params, min(limit, 500), offset])
        for r in rows:
            loads(r, "entities", "tactics", "techniques")
        return {"total": total, "items": rows}

    @app.get("/api/incidents/{inc_id}")
    def get_incident(inc_id: int, user: dict = Depends(current_user)):
        inc = vigil.alerts.get_incident(inc_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        alerts = db.query("SELECT * FROM alerts WHERE incident_id=? ORDER BY first_ts", (inc_id,))
        ids: list[int] = []
        for a in alerts:
            loads(a, "tactics", "techniques", "event_ids", "details")
            ids.extend(a["event_ids"][-50:])
        inc["alerts"] = alerts
        inc["events"] = _events(sorted(set(ids)), 300)
        inc["comments"] = _comments("incident", inc_id)
        inc["ip_context"] = {ip: ip_context(ip) for ip in inc["entities"].get("ip", [])[:10]}
        inc["technique_details"] = [t for t in (attack.technique(x) for x in inc["techniques"]) if t]
        inc["tactic_names"] = attack.tactic_names()
        return inc

    @app.patch("/api/incidents/{inc_id}")
    def update_incident(inc_id: int, body: TriageBody, user: dict = Depends(analyst)):
        _triage("incident", inc_id, body, user)
        if body.status == "closed":  # closing an incident closes its alerts
            db.execute("UPDATE alerts SET status='closed', resolution=COALESCE(resolution, ?) WHERE incident_id=?",
                       (body.resolution, inc_id))
        return vigil.alerts.get_incident(inc_id)

    # ------------------------------------------------------------ search
    @app.get("/api/search")
    def search(q: str = "", limit: int = 100, offset: int = 0, tr: tuple = Depends(time_range),
               user: dict = Depends(current_user)):
        try:
            res = vql.run_search(db.reader, q, tr[0], tr[1], min(limit, 1000), offset)
        except vql.SearchError as exc:
            raise HTTPException(400, str(exc)) from None
        if res["type"] == "events":
            for e in res["events"]:
                e["fields"] = json.loads(e["fields"])
        return res

    @app.get("/api/search/field")
    def field_values(field: str, q: str = "", tr: tuple = Depends(time_range), user: dict = Depends(current_user)):
        try:
            res = vql.run_search(db.reader, f"{q} | top {field}" if q.strip() else f"| top {field}", tr[0], tr[1])
        except vql.SearchError as exc:
            raise HTTPException(400, str(exc)) from None
        return res

    @app.get("/api/events/{event_id}")
    def get_event(event_id: int, user: dict = Depends(current_user)):
        r = db.query_one("SELECT * FROM events WHERE id=?", (event_id,))
        if not r:
            raise HTTPException(404, "event not found")
        r["fields"] = json.loads(r["fields"])
        return r

    # ------------------------------------------------------------ IP / entities
    def ip_context(ip: str) -> dict:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(400, "invalid IP") from None
        stats = db.query_one("SELECT COUNT(*) AS events, MIN(ts) AS first_seen, MAX(ts) AS last_seen, "
                             "SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END) AS failures, "
                             "SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS successes FROM events WHERE src_ip=?", (ip,))
        users = db.query("SELECT user_name, COUNT(*) AS n FROM events WHERE src_ip=? AND user_name IS NOT NULL "
                         "GROUP BY user_name ORDER BY n DESC LIMIT 15", (ip,))
        hosts = db.query("SELECT host, COUNT(*) AS n FROM events WHERE src_ip=? GROUP BY host ORDER BY n DESC LIMIT 10", (ip,))
        return {"ip": ip, "geo": vigil.geoip.lookup(ip), "intel": vigil.intel.lookup(ip), **stats,
                "users": users, "hosts": hosts,
                "alerts": db.query_one("SELECT COUNT(*) AS n FROM alerts WHERE src_ip=?", (ip,))["n"]}

    @app.get("/api/ip/{ip}")
    def ip_info(ip: str, user: dict = Depends(current_user)):
        return ip_context(ip)

    @app.get("/api/entities")
    def entities(user: dict = Depends(current_user)):
        if not vigil.ueba:
            return {"enabled": False, "items": []}
        return {"enabled": True, "min_observations": vigil.ueba.min_obs, "threshold": vigil.ueba.threshold,
                "items": vigil.ueba.list_profiles()}

    @app.get("/api/entities/{entity:path}")
    def entity(entity: str, user: dict = Depends(current_user)):
        p = vigil.ueba.get_profile(entity) if vigil.ueba else None
        if not p:
            raise HTTPException(404, "entity not found")
        name = p["name"]
        col = "user_name" if p["kind"] == "user" else "host"
        p["recent_alerts"] = db.query(f"SELECT id, rule_title, severity, risk, created_ts, status FROM alerts WHERE {col}=? "
                                      f"ORDER BY created_ts DESC LIMIT 20", (name,))
        return p

    # ------------------------------------------------------------ rules
    @app.get("/api/rules")
    def rules(q: str = "", user: dict = Depends(current_user)):
        items = vigil.engine.all_rules()
        stats = vigil.engine.stats
        for r in items:
            r["hits"] = stats.get(r["id"], 0)
            r["source"] = "vigil" if "/rules/vigil/" in r["path"] else (
                "custom" if str(vigil.custom_rules_dir) in r["path"] else "sigmahq")
            r["path"] = Path(r["path"]).name
        if q:
            ql = q.lower()
            items = [r for r in items if ql in r["title"].lower() or ql in r["id"].lower()
                     or any(ql in t.lower() for t in r["tags"])]
        rep = vigil.engine.report
        return {"items": items, "report": {"files": rep.files, "rules": rep.rules, "correlations": rep.correlations,
                                           "errors": rep.errors[:200], "error_count": len(rep.errors), "seconds": rep.seconds}}

    @app.get("/api/rules/{rule_id}")
    def rule_detail(rule_id: str, user: dict = Depends(current_user)):
        r = vigil.engine.get_rule(rule_id)
        if not r:
            raise HTTPException(404, "rule not found")
        d = r.summary()
        try:
            text = Path(r.path).read_text()
            docs = text.split("\n---")
            d["yaml"] = next((doc.strip() for doc in docs if rule_id in doc), text)
        except OSError:
            d["yaml"] = ""
        d["technique_details"] = [t for t in (attack.technique(x) for x in d["techniques"]) if t]
        d["hits"] = vigil.engine.stats.get(rule_id, 0)
        return d

    class EnableBody(BaseModel):
        enabled: bool

    @app.patch("/api/rules/{rule_id}")
    def toggle_rule(rule_id: str, body: EnableBody, request: Request, user: dict = Depends(admin)):
        if not vigil.engine.set_enabled(rule_id, body.enabled):
            raise HTTPException(404, "rule not found")
        db.execute("INSERT INTO rule_state(rule_id, enabled) VALUES(?,?) ON CONFLICT(rule_id) DO UPDATE SET enabled=excluded.enabled",
                   (rule_id, int(body.enabled)))
        db.audit(user["username"], "rule_enabled" if body.enabled else "rule_disabled", f"rule:{rule_id}")
        if not body.enabled:
            vigil.self_event("vigil_rule_disabled", "success", user["username"], client_ip(request), **{"rule.id": rule_id})
        return {"ok": True}

    @app.post("/api/rules/reload")
    def reload_rules(user: dict = Depends(admin)):
        rep = vigil.load_rules()
        db.audit(user["username"], "rules_reloaded", "", {"rules": rep.rules})
        return {"rules": rep.rules, "correlations": rep.correlations, "errors": len(rep.errors), "seconds": rep.seconds}

    class RuleBody(BaseModel):
        yaml: str = Field(max_length=200_000)
        hours: int = 24

    def _parse_rule_yaml(text: str):
        try:
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except yaml.YAMLError as exc:
            raise HTTPException(400, f"YAML error: {exc}") from None
        if not docs:
            raise HTTPException(400, "no rule found")
        out = []
        for d in docs:
            r = compile_correlation(d) if "correlation" in d else compile_rule(d)
            if r.error:
                raise HTTPException(400, f"{r.title}: {r.error}")
            out.append(r)
        return out

    @app.post("/api/rules/test")
    def test_rule(body: RuleBody, user: dict = Depends(analyst)):
        """Back-test a Sigma rule against stored events (no alerts are created)."""
        rules_ = [r for r in _parse_rule_yaml(body.yaml) if hasattr(r, "predicate")]
        if not rules_:
            raise HTTPException(400, "back-testing supports detection rules (not correlations)")
        since = time.time() - min(max(body.hours, 1), 24 * 30) * 3600
        matched, scanned, samples = 0, 0, []
        t0 = time.time()
        for row in db.reader.execute("SELECT id, ts, fields FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT 200000", (since,)):
            scanned += 1
            ev = json.loads(row["fields"])
            if any(r.match(ev) for r in rules_):
                matched += 1
                if len(samples) < 20:
                    samples.append({"id": row["id"], "ts": row["ts"], "host": ev.get("host.name"), "message": ev.get("message")})
        return {"scanned": scanned, "matched": matched, "samples": samples, "seconds": round(time.time() - t0, 2)}

    @app.post("/api/rules/custom")
    def add_custom_rule(body: RuleBody, user: dict = Depends(admin)):
        rules_ = _parse_rule_yaml(body.yaml)
        name = re.sub(r"[^a-z0-9]+", "_", rules_[0].title.lower()).strip("_")[:60] or "rule"
        path = vigil.custom_rules_dir / f"{name}.yml"
        path.write_text(body.yaml)
        rep = vigil.load_rules()
        db.audit(user["username"], "custom_rule_added", path.name)
        return {"file": path.name, "rules": rep.rules, "correlations": rep.correlations}

    # ------------------------------------------------------------ ATT&CK
    @app.get("/api/attack")
    def attack_matrix(tr: tuple = Depends(time_range), user: dict = Depends(current_user)):
        coverage: dict[str, int] = {}
        for r in vigil.engine.rules + vigil.engine.correlations:
            if r.enabled and not r.error:
                for t in r.techniques:
                    coverage[t] = coverage.get(t, 0) + 1
                    if "." in t:
                        coverage[t.split(".")[0]] = coverage.get(t.split(".")[0], 0) + 1
        detected: dict[str, dict] = {}
        for row in db.query("SELECT techniques, severity, COUNT(*) AS n FROM alerts WHERE created_ts >= ? GROUP BY techniques, severity",
                            (tr[0],)):
            for t in json.loads(row["techniques"]):
                for tid in {t, t.split(".")[0]}:
                    d = detected.setdefault(tid, {"alerts": 0, "max_severity": "informational"})
                    d["alerts"] += row["n"]
                    order = ["informational", "low", "medium", "high", "critical"]
                    if order.index(row["severity"]) > order.index(d["max_severity"]):
                        d["max_severity"] = row["severity"]
        data = attack.data()
        matrix = []
        for tac in attack.tactics():
            techs = []
            for tid, t in data["techniques"].items():
                if "." in tid or t.get("inactive") or tac["short"] not in t["tactics"]:
                    continue
                techs.append({"id": tid, "name": t["name"], "rules": coverage.get(tid, 0), **detected.get(tid, {"alerts": 0})})
            techs.sort(key=lambda x: (-x.get("alerts", 0), -x["rules"], x["name"]))
            matrix.append({**tac, "techniques": techs})
        covered = sum(1 for tid, t in data["techniques"].items() if "." not in tid and not t.get("inactive") and coverage.get(tid))
        total = sum(1 for tid, t in data["techniques"].items() if "." not in tid and not t.get("inactive"))
        return {"matrix": matrix, "covered": covered, "total": total, "source": data.get("source")}

    # ------------------------------------------------------------ threat intel
    @app.get("/api/intel")
    def intel(user: dict = Depends(current_user)):
        s = vigil.intel.summary()
        s["geoip"] = vigil.geoip.sources
        return s

    @app.post("/api/intel/refresh")
    def intel_refresh(user: dict = Depends(admin)):
        import threading
        threading.Thread(target=vigil.intel.refresh, daemon=True).start()
        return {"ok": True}

    class IndicatorBody(BaseModel):
        indicator: str
        note: str = ""

    @app.post("/api/intel/indicators")
    def add_indicator(body: IndicatorBody, user: dict = Depends(analyst)):
        try:
            item = vigil.intel.add_custom(body.indicator, body.note, user["username"])
        except ValueError:
            raise HTTPException(400, "indicator must be an IP address or CIDR network") from None
        db.audit(user["username"], "indicator_added", body.indicator)
        return item

    @app.delete("/api/intel/indicators/{indicator:path}")
    def remove_indicator(indicator: str, user: dict = Depends(analyst)):
        if not vigil.intel.remove_custom(indicator):
            raise HTTPException(404, "indicator not found")
        db.audit(user["username"], "indicator_removed", indicator)
        return {"ok": True}

    # ------------------------------------------------------------ settings
    @app.get("/api/settings/notifications")
    def get_notifications(user: dict = Depends(admin)):
        return {"config": vigil.notifier.redacted_config(), "history": list(vigil.notifier.history)[::-1]}

    @app.put("/api/settings/notifications")
    async def put_notifications(request: Request, user: dict = Depends(admin)):
        body = await request.json()
        cfg = vigil.notifier.update_config(body if isinstance(body, dict) else {})
        db.audit(user["username"], "notifications_updated", "")
        return cfg

    @app.post("/api/settings/notifications/test/{channel}")
    def test_notification(channel: str, user: dict = Depends(admin)):
        if channel not in ("slack", "telegram", "email", "webhook"):
            raise HTTPException(404, "unknown channel")
        return vigil.notifier.test(channel)

    @app.get("/api/audit")
    def audit_log(limit: int = 200, user: dict = Depends(admin)):
        return db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 1000),))

    @app.get("/api/system")
    def system(user: dict = Depends(current_user)):
        p = vigil.pipeline
        db_size = settings.db_path.stat().st_size if settings.db_path.exists() else 0
        return {"version": VERSION, "uptime_s": int(time.time() - vigil.started), "events_processed": p.processed,
                "detections": p.detections, "errors": p.errors, "last_error": p.last_error, "eps": p.eps(),
                "queue": p.q.qsize(), "db_bytes": db_size, "retention_days": settings.retention_days,
                "geoip": vigil.geoip.sources, "ueba": bool(vigil.ueba), "syslog_port": settings.syslog_port if settings.syslog_enabled else None,
                "events_stored": db.query_one("SELECT COUNT(*) AS n FROM events")["n"]}

    # ------------------------------------------------------------ live stream
    @app.get("/api/stream")
    async def stream(request: Request, user: dict = Depends(current_user)):
        q: asyncio.Queue = asyncio.Queue()
        vigil.broadcaster.queues.add(q)

        async def gen():
            try:
                yield "retry: 3000\n\n"
                while not await request.is_disconnected():
                    try:
                        msg = await asyncio.wait_for(q.get(), timeout=10)
                        yield f"data: {msg}\n\n"
                    except TimeoutError:
                        yield f"data: {json.dumps({'kind': 'stats', 'data': {'eps': vigil.pipeline.eps(), 'processed': vigil.pipeline.processed}})}\n\n"
            finally:
                vigil.broadcaster.queues.discard(q)
        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------ agent download + UI
    agent_dir = Path(__file__).resolve().parents[2] / "agent"
    if not agent_dir.exists():
        agent_dir = Path("/opt/vigil/agent")

    @app.get("/agent/{name}")
    def agent_file(name: str):
        if name == "ca.crt":
            ca = ca_cert_path()
            if not ca:
                raise HTTPException(404, "server is not using TLS")
            return FileResponse(ca, media_type="application/x-pem-file")
        if name not in ("vigil_agent.py", "install.sh", "vigil-agent.service"):
            raise HTTPException(404, "not found")
        path = agent_dir / name
        if not path.exists():
            raise HTTPException(404, "agent files not bundled")
        return FileResponse(path, media_type="text/plain")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    return app
