"""Ingestion pipeline: parse -> enrich -> store -> detect -> alert.

Batches arrive from agents (HTTPS) and the syslog listener and are queued.
A single worker thread drains the queue so database writes are batched into
one transaction per batch and detection state needs no extra locking.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass

from .alerts import AlertManager
from .db import Database
from .detection.engine import Detection, DetectionEngine
from .detection.ueba import UEBA
from .enrich.geoip import GeoIP
from .enrich.threatintel import ThreatIntel
from .parsers import Normalizer

log = logging.getLogger("vigil.pipeline")

COLUMNS = ("host.name", "agent.id", "log.source", "log.product", "log.services", "log.category", "event.action",
           "event.outcome", "user.name", "source.ip", "source.geo.country_iso_code")


@dataclass
class Batch:
    records: list[dict]
    host: str | None
    agent_id: str | None
    tz_offset: int = 0
    received: float = 0.0


class Pipeline:
    def __init__(self, db: Database, engine: DetectionEngine, alerts: AlertManager, geoip: GeoIP,
                 intel: ThreatIntel, ueba: UEBA | None, max_queue: int = 2000):
        self.db = db
        self.engine = engine
        self.alerts = alerts
        self.geoip = geoip
        self.intel = intel
        self.ueba = ueba
        self.normalizer = Normalizer()
        self.q: queue.Queue[Batch | None] = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.processed = 0
        self.detections = 0
        self.errors = 0
        self.rate: deque = deque(maxlen=120)  # (ts, events) per batch for EPS
        self.last_error: str | None = None

    # ------------------------------------------------------------ control
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="pipeline", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass
        if self._thread:
            self._thread.join(timeout=10)

    def submit(self, batch: Batch) -> bool:
        batch.received = time.time()
        try:
            self.q.put_nowait(batch)
            return True
        except queue.Full:
            return False

    def eps(self) -> float:
        now = time.time()
        recent = [n for ts, n in self.rate if ts >= now - 60]
        return round(sum(recent) / 60.0, 2)

    # ------------------------------------------------------------ worker
    def _run(self) -> None:
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                batch = self.q.get(timeout=1.0)
            except queue.Empty:
                batch = None
            if batch is not None:
                try:
                    self.process(batch)
                except Exception as exc:
                    self.errors += 1
                    self.last_error = repr(exc)
                    log.exception("pipeline batch failed")
            if time.time() - last_flush > 5:
                last_flush = time.time()
                leftovers = self.normalizer.flush() if self.normalizer.audit._pending else []
                if leftovers:
                    self.process_events(leftovers)
                if self.ueba:
                    try:
                        self.ueba.save()
                    except Exception:
                        log.exception("ueba save failed")
                self.engine.corr_engine.gc(time.time())

    def process(self, batch: Batch) -> int:
        events: list[dict] = []
        for rec in batch.records:
            if not isinstance(rec, dict):
                continue
            events.extend(self.normalizer.parse(rec, batch.host, batch.agent_id, batch.tz_offset))
        return self.process_events(events)

    def process_events(self, events: list[dict]) -> int:
        if not events:
            return 0
        now = time.time()
        intel_hits: dict[int, list[dict]] = {}
        for i, ev in enumerate(events):
            if not ev.get("@timestamp") or abs(float(ev["@timestamp"]) - now) > 400 * 86400:
                ev["@timestamp"] = now
            self.geoip.enrich(ev)
            hits = self.intel.enrich(ev)
            if hits:
                intel_hits[i] = hits
        ids = self._store(events, now)
        dets: list[Detection] = []
        for i, (ev, eid) in enumerate(zip(events, ids, strict=True)):
            dets.extend(self.engine.evaluate(ev, eid))
            if i in intel_hits:
                d = self._intel_detection(ev, eid, intel_hits[i])
                if d:
                    dets.append(d)
            if self.ueba:
                for a in self.ueba.observe(ev):
                    dets.append(Detection(
                        f"ueba-{a.model}", a.title if a.model != "login_anomaly" else "Anomalous Login (UEBA)",
                        "ueba", a.severity, a.event, [eid], float(ev["@timestamp"]), float(ev["@timestamp"]),
                        a.tactics, a.techniques, {"entity": a.entity},
                        {"risk": a.risk, "factors": a.factors, "model": a.model, "entity": a.entity},
                        "Behavioural anomaly: this activity deviates from the baseline Vigil learned for the entity."))
        for d in dets:
            try:
                self.alerts.handle(d)
            except Exception:
                log.exception("alert handling failed for %s", d.rule_id)
        self.processed += len(events)
        self.detections += len(dets)
        self.rate.append((time.time(), len(events)))
        return len(events)

    def _intel_detection(self, ev: dict, eid: int, hits: list[dict]) -> Detection:
        ip = str(ev.get("source.ip"))
        ts = float(ev["@timestamp"])
        # Repeat sightings of the same IP on the same host merge into one alert (AlertManager dedup).
        feeds = [h["feed"] for h in hits]
        high = any(h.get("confidence") == "high" for h in hits)
        success = ev.get("event.outcome") == "success" and ev.get("event.category") in ("authentication", "webserver")
        sev = "high" if success else ("medium" if high else "low")
        cats = sorted({h.get("category") or "" for h in hits} - {""})
        title = "Successful Activity From Threat-Intel Listed IP" if success else "Activity From Threat-Intel Listed IP"
        return Detection("vigil-threatintel-ip", title, "threatintel", sev, ev, [eid], ts, ts,
                         ["initial-access"] if success else ["reconnaissance"], [],
                         {"source.ip": ip, "host.name": ev.get("host.name")},
                         {"feeds": feeds, "categories": cats, "intel_hits": hits},
                         f"{ip} appears on threat-intelligence feeds ({', '.join(feeds)}).")

    def _store(self, events: list[dict], now: float) -> list[int]:
        ids: list[int] = []
        minute_counts: dict[int, int] = {}
        with self.db.tx() as c:
            for ev in events:
                services = ev.get("log.services") or []
                cur = c.execute(
                    "INSERT INTO events(ts, ingest_ts, host, agent_id, source, product, service, category, action, outcome, "
                    "user_name, src_ip, src_country, message, fields) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (float(ev["@timestamp"]), now, ev.get("host.name"), ev.get("agent.id"),
                     ev.get("log.file.path") or ev.get("log.source"), ev.get("log.product"),
                     ",".join(services), ev.get("log.category") or ev.get("event.category"), ev.get("event.action"),
                     ev.get("event.outcome"), _s(ev.get("user.name")), _s(ev.get("source.ip")),
                     ev.get("source.geo.country_iso_code"), (ev.get("message") or "")[:16384],
                     json.dumps(ev, default=str)))
                ids.append(cur.lastrowid)
                m = int(float(ev["@timestamp"]) // 60)
                minute_counts[m] = minute_counts.get(m, 0) + 1
            c.executemany("INSERT INTO stats_minute(minute, events) VALUES(?, ?) ON CONFLICT(minute) DO UPDATE SET "
                          "events = events + excluded.events", list(minute_counts.items()))
        return ids


def _s(v):
    return None if v is None else str(v)
