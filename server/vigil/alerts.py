"""Alert lifecycle: de-duplication, risk scoring, ATT&CK context, incident
grouping and notification fan-out."""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable

from .db import Database
from .detection.engine import Detection
from .enrich import attack

log = logging.getLogger("vigil.alerts")

LEVEL_RISK = {"informational": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}
LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]
KEY_FIELDS = ("host.name", "user.name", "user.target.name", "source.ip", "source.geo.country_iso_code",
              "source.as.organization.name", "event.action", "event.outcome", "process.executable",
              "process.command_line", "process.parent.executable", "url.original", "http.response.status_code",
              "user_agent.original", "destination.port", "threat.indicator.feeds", "log.file.path", "message")


def max_level(a: str, b: str) -> str:
    return a if LEVEL_ORDER.index(a) >= LEVEL_ORDER.index(b) else b


def _entity(ev: dict, group: dict, key: str) -> str | None:
    v = group.get(key) or ev.get(key)
    return str(v) if v not in (None, "") else None


class AlertManager:
    def __init__(self, db: Database, dedup_minutes: int = 30, incident_window_minutes: int = 60):
        self.db = db
        self.dedup_s = dedup_minutes * 60
        self.incident_window_s = incident_window_minutes * 60
        self.listeners: list[Callable[[str, dict], None]] = []

    def _emit(self, kind: str, payload: dict) -> None:
        for fn in self.listeners:
            try:
                fn(kind, payload)
            except Exception:
                log.exception("listener failed")

    # ------------------------------------------------------------------
    def handle(self, det: Detection) -> dict | None:
        ev = det.event
        host = _entity(ev, det.group, "host.name")
        user = _entity(ev, det.group, "user.name")
        src = _entity(ev, det.group, "source.ip") or _entity(ev, det.group, "IpAddress")
        if det.details.get("correlation_type") in ("event_count", "value_count"):
            # Aggregations span many events: only the grouped fields describe the alert.
            user = _entity({}, det.group, "user.name")
            src = _entity({}, det.group, "source.ip") or _entity({}, det.group, "IpAddress")
        group_part = "|".join(f"{k}={v}" for k, v in sorted(det.group.items())) if det.group else f"{host}|{user}|{src}"
        dedup_key = f"{det.rule_id}|{group_part}"
        now = time.time()

        tactics, techniques = attack.resolve(det.techniques, det.tactics)
        risk = LEVEL_RISK.get(det.severity, 50)
        if det.rule_type == "ueba":
            risk = int(det.details.get("risk", risk))
        if ev.get("threat.indicator.matched"):
            risk = min(100, risk + 10)

        with self.db.tx() as c:
            row = c.execute(
                "SELECT id, count, event_ids, last_ts, incident_id FROM alerts WHERE dedup_key=? AND status != 'closed' "
                "AND last_ts >= ? ORDER BY id DESC LIMIT 1", (dedup_key, det.last_ts - self.dedup_s)).fetchone()
            if row:
                ids = json.loads(row["event_ids"])
                for i in det.event_ids:
                    if i not in ids:
                        ids.append(i)
                ids = ids[-500:]
                c.execute("UPDATE alerts SET count=count+1, last_ts=MAX(last_ts, ?), event_ids=? WHERE id=?",
                          (det.last_ts, json.dumps(ids), row["id"]))
                if row["incident_id"]:
                    c.execute("UPDATE incidents SET last_ts=MAX(last_ts, ?) WHERE id=?", (det.last_ts, row["incident_id"]))
                alert_id, created = row["id"], False
            else:
                details = {
                    "description": det.description,
                    "event": {k: ev[k] for k in KEY_FIELDS if k in ev},
                    "group": det.group,
                    "technique_details": techniques,
                    **det.details,
                }
                cur = c.execute(
                    "INSERT INTO alerts(rule_id, rule_title, rule_type, severity, risk, first_ts, last_ts, created_ts, "
                    "host, user_name, src_ip, dedup_key, tactics, techniques, event_ids, details) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (det.rule_id, det.rule_title, det.rule_type, det.severity, risk, det.first_ts, det.last_ts, now,
                     host, user, src, dedup_key, json.dumps(tactics), json.dumps([t["id"] for t in techniques]),
                     json.dumps(det.event_ids[-500:]), json.dumps(details, default=str)))
                alert_id, created = cur.lastrowid, True
        if not created:
            return None
        alert = self.get(alert_id)
        incident = self._attach_incident(alert)
        alert["incident_id"] = incident["id"] if incident else None
        self._emit("alert", alert)
        return alert

    def get(self, alert_id: int) -> dict:
        row = self.db.query_one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if row:
            for k in ("tactics", "techniques", "event_ids", "details"):
                row[k] = json.loads(row[k])
        return row

    # --------------------------------------------------------- incidents
    def _attach_incident(self, alert: dict) -> dict | None:
        if alert["severity"] == "informational":
            return None
        ip, user, host = alert.get("src_ip"), alert.get("user_name"), alert.get("host")
        since = alert["first_ts"] - self.incident_window_s
        candidates = self.db.query(
            "SELECT * FROM incidents WHERE status != 'closed' AND last_ts >= ? ORDER BY last_ts DESC LIMIT 200", (since,))
        # Match on the strongest shared entity: attacker IP, then user on the same host, then
        # (for alerts with no source IP, e.g. a backdoor account being created) the same host
        # with recent activity.
        target = None
        for inc in candidates:
            ents = json.loads(inc["entities"])
            if ip and ip in ents.get("ip", []):
                target = inc
                break
        if target is None and user and host:
            target = next((inc for inc in candidates if user in json.loads(inc["entities"]).get("user", [])
                           and host in json.loads(inc["entities"]).get("host", [])), None)
        if target is None and not ip and host:
            # Closest in time wins, so unrelated noise on a busy host does not absorb a chain.
            near = [inc for inc in candidates if abs(inc["last_ts"] - alert["first_ts"]) <= min(self.incident_window_s, 1800)
                    and host in json.loads(inc["entities"]).get("host", [])]
            target = min(near, key=lambda inc: abs(inc["last_ts"] - alert["first_ts"]), default=None)
        now = time.time()
        with self.db.tx() as c:
            if target is None:
                ents = {"ip": [ip] if ip else [], "user": [user] if user else [], "host": [host] if host else []}
                where = f" on {host}" if host else (f" from {ip}" if ip else "")
                cur = c.execute(
                    "INSERT INTO incidents(title, severity, risk, first_ts, last_ts, created_ts, alert_count, entities, "
                    "tactics, techniques) VALUES(?,?,?,?,?,?,1,?,?,?)",
                    (f"{alert['rule_title']}{where}", alert["severity"], alert["risk"], alert["first_ts"], alert["last_ts"],
                     now, json.dumps(ents), json.dumps(alert["tactics"]), json.dumps(alert["techniques"])))
                inc_id = cur.lastrowid
                escalated = True
            else:
                inc_id = target["id"]
                ents = json.loads(target["entities"])
                for k, v in (("ip", ip), ("user", user), ("host", host)):
                    if v and v not in ents.setdefault(k, []):
                        ents[k].append(v)
                order = [t["short"] for t in attack.tactics()]
                tactics = sorted(set(json.loads(target["tactics"])) | set(alert["tactics"]),
                                 key=lambda t: order.index(t) if t in order else 99)
                techniques = sorted(set(json.loads(target["techniques"])) | set(alert["techniques"]))
                sev = max_level(target["severity"], alert["severity"])
                escalated = sev != target["severity"]
                # Risk grows with each distinct alert but saturates at 100.
                risk = min(100, max(target["risk"], alert["risk"]) + int(0.25 * min(target["risk"], alert["risk"])))
                # Multi-stage incidents (3+ tactics) are escalated by kill-chain progression.
                if len(tactics) >= 3:
                    risk = min(100, risk + 10)
                title = target["title"]
                if escalated:
                    host_part = f" on {host}" if host else ""
                    title = f"{alert['rule_title']}{host_part}"
                c.execute("UPDATE incidents SET severity=?, risk=?, last_ts=MAX(last_ts, ?), first_ts=MIN(first_ts, ?), "
                          "alert_count=alert_count+1, entities=?, tactics=?, techniques=?, title=? WHERE id=?",
                          (sev, risk, alert["last_ts"], alert["first_ts"], json.dumps(ents), json.dumps(tactics),
                           json.dumps(techniques), title, inc_id))
            c.execute("UPDATE alerts SET incident_id=? WHERE id=?", (inc_id, alert["id"]))
        inc = self.get_incident(inc_id)
        if escalated:
            self._emit("incident", inc)
        return inc

    def get_incident(self, inc_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if row:
            for k in ("entities", "tactics", "techniques"):
                row[k] = json.loads(row[k])
        return row
