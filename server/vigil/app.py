"""Application wiring: builds every component and owns background tasks."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from pathlib import Path

from .alerts import AlertManager
from .auth import Auth
from .config import Settings
from .db import Database
from .detection.engine import Detection, DetectionEngine
from .detection.ueba import UEBA
from .enrich.geoip import GeoIP
from .enrich.threatintel import ThreatIntel
from .notify import Notifier
from .pipeline import Batch, Pipeline

log = logging.getLogger("vigil")
VERSION = "1.0.0"


class Broadcaster:
    """Fan-out of live alert/incident events to Server-Sent-Event clients."""

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.queues: set[asyncio.Queue] = set()

    def publish(self, kind: str, obj: dict) -> None:
        if not self.loop:
            return
        payload = json.dumps({"kind": kind, "data": {k: obj.get(k) for k in (
            "id", "rule_title", "title", "severity", "risk", "host", "src_ip", "user_name", "alert_count")}}, default=str)
        for q in list(self.queues):
            self.loop.call_soon_threadsafe(self._put, q, payload)

    @staticmethod
    def _put(q: asyncio.Queue, payload: str) -> None:
        if q.qsize() < 100:
            q.put_nowait(payload)


class Vigil:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.started = time.time()
        self.db = Database(settings.db_path)
        self.auth = Auth(self.db, settings.session_hours)
        self.engine = DetectionEngine()
        self.geoip = GeoIP(settings.geoip_dir or None)
        self.intel = ThreatIntel(settings.data_dir / "intel", settings.threatintel_enabled, settings.threatintel_refresh_hours)
        self.ueba = UEBA(settings.ueba_min_observations, settings.ueba_threshold, self.db) if settings.ueba_enabled else None
        self.alerts = AlertManager(self.db, settings.alert_dedup_minutes, settings.incident_window_minutes)
        self.notifier = Notifier(self.db, settings.public_url)
        self.broadcaster = Broadcaster()
        self.alerts.listeners += [self.notifier.on_event, self.broadcaster.publish]
        self.pipeline = Pipeline(self.db, self.engine, self.alerts, self.geoip, self.intel, self.ueba)
        self._stop = threading.Event()
        self.custom_rules_dir = settings.data_dir / "rules"
        self.custom_rules_dir.mkdir(parents=True, exist_ok=True)
        self.load_rules()

    # ---------------------------------------------------------------- rules
    def rule_dirs(self) -> list[Path]:
        return [*self.settings.rules_dirs, self.custom_rules_dir]

    def load_rules(self):
        disabled = {r["rule_id"] for r in self.db.query("SELECT rule_id FROM rule_state WHERE enabled=0")}
        return self.engine.load_dirs(self.rule_dirs(), disabled)

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        generated = self.auth.ensure_admin(self.settings.admin_user, self.settings.admin_password)
        if generated:
            cred_file = self.settings.data_dir / "initial_admin_password.txt"
            cred_file.write_text(f"username: {self.settings.admin_user}\npassword: {generated}\n")
            cred_file.chmod(0o600)
            log.warning("=" * 70)
            log.warning("Created admin account  user: %s  password: %s", self.settings.admin_user, generated)
            log.warning("(also saved to %s) - change it after first login", cred_file)
            log.warning("=" * 70)
        self.pipeline.start()
        self.intel.start()
        threading.Thread(target=self._maintenance, name="maintenance", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self.pipeline.stop()
        self.intel.stop()
        self.notifier.stop()
        if self.ueba:
            self.ueba.save()

    def self_event(self, action: str, outcome: str, user: str | None, ip: str | None, **extra) -> None:
        """Feed Vigil's own security events (console logins, admin changes) through the pipeline."""
        fields = {"@timestamp": time.time(), "host.name": "vigil", "log.product": "vigil", "log.services": ["audit"],
                  "event.category": "authentication" if "login" in action else "configuration", "event.action": action,
                  "event.outcome": outcome, "user.name": user, "source.ip": ip,
                  "message": f"vigil {action} user={user} src={ip} outcome={outcome}", **extra}
        self.pipeline.submit(Batch([{"type": "event", "fields": fields}], "vigil", None))

    # ---------------------------------------------------------- maintenance
    def _maintenance(self) -> None:
        last_retention = 0.0
        while not self._stop.wait(30):
            try:
                self._check_agents()
                if time.time() - last_retention > 3600:
                    last_retention = time.time()
                    self._retention()
            except Exception:
                log.exception("maintenance failed")

    def _check_agents(self) -> None:
        silence = self.settings.agent_silence_minutes * 60
        now = time.time()
        for a in self.db.query("SELECT * FROM agents WHERE status='active'"):
            last = a["last_seen"] or a["enrolled_ts"]
            if now - last > silence and not a["silent_alerted"]:
                self.db.execute("UPDATE agents SET silent_alerted=1 WHERE id=?", (a["id"],))
                ev = {"host.name": a["hostname"], "agent.id": a["id"], "@timestamp": now,
                      "message": f"agent {a['id']} on {a['hostname']} stopped reporting"}
                self.alerts.handle(Detection(
                    "vigil-agent-silent", "Log Source Stopped Reporting", "system", "medium", ev, [], last, now,
                    ["defense-impairment"], ["T1685"], {"agent.id": a["id"]},
                    {"last_seen": last, "silence_minutes": round((now - last) / 60)},
                    "An agent has not sent data or heartbeats within the configured window. Attackers often stop "
                    "logging agents after gaining access; it can also be a crashed host or network outage."))
            elif now - last <= silence and a["silent_alerted"]:
                self.db.execute("UPDATE agents SET silent_alerted=0 WHERE id=?", (a["id"],))

    def _retention(self) -> None:
        cutoff = time.time() - self.settings.retention_days * 86400
        while True:
            with self.db.tx() as c:
                n = c.execute("DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts < ? LIMIT 5000)",
                              (cutoff,)).rowcount
            if n < 5000:
                break
        self.db.execute("DELETE FROM stats_minute WHERE minute < ?", (int(cutoff // 60),))


# ---------------------------------------------------------------- syslog
class _SyslogUDP(asyncio.DatagramProtocol):
    def __init__(self, vigil: Vigil):
        self.vigil = vigil

    def datagram_received(self, data: bytes, addr) -> None:
        line = data.decode("utf-8", "replace")
        self.vigil.pipeline.submit(Batch([{"type": "syslog", "line": line, "path": f"syslog-udp://{addr[0]}"}], None, None))


async def start_syslog(vigil: Vigil, host: str, port: int):
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: _SyslogUDP(vigil), local_addr=(host, port))

    async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")[0]
        buf: list[dict] = []
        last = time.time()
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=2)
                except TimeoutError:
                    line = None
                if line == b"":
                    break
                if line:
                    # RFC 6587 octet counting: "<len> <msg>"
                    text = line.decode("utf-8", "replace").rstrip("\r\n")
                    if text[:1].isdigit() and " " in text and text.split(" ", 1)[1].startswith("<"):
                        text = text.split(" ", 1)[1]
                    buf.append({"type": "syslog", "line": text, "path": f"syslog-tcp://{peer}"})
                if buf and (len(buf) >= 500 or time.time() - last > 1 or line is None):
                    vigil.pipeline.submit(Batch(buf, None, None))
                    buf, last = [], time.time()
        finally:
            if buf:
                vigil.pipeline.submit(Batch(buf, None, None))
            writer.close()

    tcp = await asyncio.start_server(handle_tcp, host, port, limit=65536)
    log.info("syslog listening on udp/tcp %s:%d", host, port)
    return udp, tcp
