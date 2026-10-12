"""Alert notifications: Slack, Telegram, email (SMTP) and generic webhooks.

Sending happens on a background thread so a slow webhook never stalls
detection. Each channel is rate limited and every alert is sent at most once.
"""
from __future__ import annotations

import json
import logging
import queue
import smtplib
import threading
import time
import urllib.request
from collections import deque
from email.message import EmailMessage

from .db import Database

log = logging.getLogger("vigil.notify")

SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}
DEFAULT = {
    "min_severity": "high",
    "notify_incidents": True,
    "max_per_hour": 30,
    "slack": {"enabled": False, "webhook_url": ""},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    "email": {"enabled": False, "host": "", "port": 587, "username": "", "password": "", "from": "", "to": "",
              "starttls": True},
    "webhook": {"enabled": False, "url": "", "headers": {}},
}
SECRET_KEYS = {("slack", "webhook_url"), ("telegram", "bot_token"), ("email", "password"), ("webhook", "headers")}


def _post_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 10) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "Vigil-SIEM/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if r.status >= 300:
            raise RuntimeError(f"HTTP {r.status}")


class Notifier:
    def __init__(self, db: Database, public_url: str = ""):
        self.db = db
        self.public_url = public_url.rstrip("/")
        self._q: queue.Queue = queue.Queue(maxsize=1000)
        self._sent: dict[str, deque] = {}
        self.history: deque = deque(maxlen=100)
        self._stop = threading.Event()
        threading.Thread(target=self._run, name="notifier", daemon=True).start()

    # ------------------------------------------------------------ config
    def config(self) -> dict:
        cfg = json.loads(json.dumps(DEFAULT))
        stored = self.db.get_setting("notifications", {}) or {}
        for k, v in stored.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
        return cfg

    def redacted_config(self) -> dict:
        cfg = self.config()
        for ch, key in SECRET_KEYS:
            if cfg.get(ch, {}).get(key):
                cfg[ch][key] = "********"
        return cfg

    def update_config(self, new: dict) -> dict:
        cur = self.config()
        for k, v in new.items():
            if k not in DEFAULT:
                continue
            if isinstance(v, dict) and isinstance(cur.get(k), dict):
                for kk, vv in v.items():
                    if (k, kk) in SECRET_KEYS and vv == "********":
                        continue  # unchanged secret
                    cur[k][kk] = vv
            else:
                cur[k] = v
        if cur.get("min_severity") not in SEV_ORDER:
            cur["min_severity"] = "high"
        self.db.set_setting("notifications", cur)
        return self.redacted_config()

    # ------------------------------------------------------------ public
    def on_event(self, kind: str, obj: dict) -> None:
        cfg = self.config()
        if kind == "alert":
            if SEV_ORDER.index(obj["severity"]) < SEV_ORDER.index(cfg["min_severity"]):
                return
        elif kind == "incident":
            if not cfg.get("notify_incidents") or SEV_ORDER.index(obj["severity"]) < SEV_ORDER.index(cfg["min_severity"]):
                return
        else:
            return
        try:
            self._q.put_nowait((kind, obj, cfg))
        except queue.Full:
            log.warning("notification queue full, dropping %s %s", kind, obj.get("id"))

    def test(self, channel: str) -> dict:
        cfg = self.config()
        sample = {"id": 0, "rule_title": "Vigil test notification", "severity": "high", "risk": 75, "host": "vigil",
                  "user_name": None, "src_ip": "203.0.113.10", "tactics": ["credential-access"], "techniques": ["T1110"],
                  "details": {"description": "This is a test message from Vigil. Notifications are working."}}
        try:
            self._send(channel, cfg, self._format("alert", sample))
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:300]}

    # ------------------------------------------------------------ internals
    def _format(self, kind: str, o: dict) -> dict:
        sev = o["severity"]
        if kind == "alert":
            title = f"{SEV_EMOJI.get(sev, '')} [{sev.upper()}] {o['rule_title']}"
            link = f"{self.public_url}/#/alerts/{o['id']}" if self.public_url else ""
            lines = [f"Risk: {o['risk']}/100"]
            for label, key in (("Host", "host"), ("User", "user_name"), ("Source IP", "src_ip")):
                if o.get(key):
                    lines.append(f"{label}: {o[key]}")
            if o.get("techniques"):
                lines.append("ATT&CK: " + ", ".join(o["techniques"]))
            desc = (o.get("details") or {}).get("description") or ""
            if desc:
                lines.append(desc.strip().split("\n")[0][:300])
        else:
            title = f"{SEV_EMOJI.get(sev, '')} Incident #{o['id']} [{sev.upper()}]: {o['title']}"
            link = f"{self.public_url}/#/incidents/{o['id']}" if self.public_url else ""
            ents = o.get("entities") or {}
            lines = [f"Risk: {o['risk']}/100 · {o['alert_count']} alert(s)",
                     "Kill chain: " + " → ".join(o.get("tactics") or []) if o.get("tactics") else "",
                     "Entities: " + ", ".join(v for vs in ents.values() for v in vs)[:300]]
        if link:
            lines.append(link)
        return {"title": title, "text": "\n".join(l for l in lines if l), "kind": kind, "object": o}  # noqa: E741

    def _allowed(self, channel: str, limit: int) -> bool:
        dq = self._sent.setdefault(channel, deque())
        now = time.time()
        while dq and dq[0] < now - 3600:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True

    def _send(self, channel: str, cfg: dict, msg: dict) -> None:
        c = cfg[channel]
        if channel == "slack":
            _post_json(c["webhook_url"], {"text": f"*{msg['title']}*\n{msg['text']}"})
        elif channel == "telegram":
            url = f"https://api.telegram.org/bot{c['bot_token']}/sendMessage"
            _post_json(url, {"chat_id": c["chat_id"], "text": f"{msg['title']}\n{msg['text']}", "disable_web_page_preview": True})
        elif channel == "webhook":
            _post_json(c["url"], {"source": "vigil", "kind": msg["kind"], "title": msg["title"], "text": msg["text"],
                                  "data": msg["object"]}, headers=c.get("headers") or {})
        elif channel == "email":
            em = EmailMessage()
            em["Subject"] = msg["title"]
            em["From"] = c["from"] or c["username"]
            em["To"] = c["to"]
            em.set_content(msg["text"])
            with smtplib.SMTP(c["host"], int(c.get("port") or 587), timeout=15) as s:
                if c.get("starttls", True):
                    s.starttls()
                if c.get("username"):
                    s.login(c["username"], c["password"])
                s.send_message(em)
        else:
            raise ValueError(f"unknown channel {channel}")

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                kind, obj, cfg = self._q.get(timeout=1)
            except queue.Empty:
                continue
            msg = self._format(kind, obj)
            for ch in ("slack", "telegram", "email", "webhook"):
                if not cfg.get(ch, {}).get("enabled"):
                    continue
                if not self._allowed(ch, int(cfg.get("max_per_hour") or 30)):
                    self.history.append({"ts": time.time(), "channel": ch, "title": msg["title"], "ok": False,
                                         "error": "rate limited"})
                    continue
                try:
                    self._send(ch, cfg, msg)
                    self.history.append({"ts": time.time(), "channel": ch, "title": msg["title"], "ok": True})
                except Exception as exc:
                    log.warning("notification via %s failed: %s", ch, exc)
                    self.history.append({"ts": time.time(), "channel": ch, "title": msg["title"], "ok": False,
                                         "error": str(exc)[:200]})

    def stop(self) -> None:
        self._stop.set()
