"""Threat-intelligence IP reputation from free, keyless public feeds.

Feeds are downloaded in the background, cached on disk, and compiled into
sorted integer ranges so a lookup is a binary search. With no network the
last cached copy is used; with no cache the feature simply reports itself as
unavailable and the pipeline carries on.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import re
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("vigil.threatintel")


@dataclass
class Feed:
    name: str
    url: str
    category: str
    description: str
    confidence: str = "medium"


FEEDS = [
    Feed("blocklist.de-ssh", "https://lists.blocklist.de/lists/ssh.txt", "bruteforce",
         "IPs reported for SSH brute force in the last 48h (blocklist.de)", "high"),
    Feed("blocklist.de-all", "https://lists.blocklist.de/lists/all.txt", "attacker",
         "All IPs reported to blocklist.de for attacks on mail, web, FTP, SSH ...", "medium"),
    Feed("feodo-c2", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "c2",
         "Botnet command-and-control servers (abuse.ch Feodo Tracker)", "high"),
    Feed("cinsscore", "https://cinsscore.com/list/ci-badguys.txt", "attacker",
         "CINS Army list of IPs with poor reputation", "medium"),
    Feed("firehol-level1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
         "malicious-network", "FireHOL level 1: networks that should never be reachable (attacks, hijacked ranges)", "medium"),
    Feed("spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt", "hijacked-network",
         "Spamhaus DROP: hijacked netblocks operated by criminals", "high"),
    Feed("et-compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "compromised",
         "Emerging Threats known compromised hosts", "medium"),
]

_LINE = re.compile(r"^\s*([0-9a-fA-F:.]+(?:/\d{1,3})?)")


def parse_feed(text: str) -> list[tuple[int, int]]:
    ranges = []
    for line in text.splitlines():
        if not line or line.lstrip().startswith(("#", ";", "//")):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        try:
            net = ipaddress.ip_network(m.group(1), strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.is_private:
            continue
        ranges.append((int(net.network_address), int(net.broadcast_address)))
    return ranges


class _RangeSet:
    def __init__(self, ranges: list[tuple[int, int]]):
        ranges.sort()
        merged: list[list[int]] = []
        for lo, hi in ranges:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self.starts = [r[0] for r in merged]
        self.ends = [r[1] for r in merged]
        self.size = sum(h - l + 1 for l, h in merged)  # noqa: E741
        self.entries = len(ranges)

    def __contains__(self, ip: int) -> bool:
        i = bisect.bisect_right(self.starts, ip) - 1
        return i >= 0 and ip <= self.ends[i]


class ThreatIntel:
    def __init__(self, cache_dir: Path, enabled: bool = True, refresh_hours: int = 6, feeds: list[Feed] | None = None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.enabled = enabled
        self.refresh_s = refresh_hours * 3600
        self.feeds = feeds if feeds is not None else FEEDS
        self._sets: dict[str, _RangeSet] = {}
        self.status: dict[str, dict] = {}
        self.custom: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._load_cache()
        self._load_custom()

    # ---------------------------------------------------------------- cache
    def _path(self, feed: Feed) -> Path:
        return self.cache_dir / f"{feed.name}.txt"

    def _load_cache(self) -> None:
        for f in self.feeds:
            p = self._path(f)
            if p.exists():
                self._install(f, p.read_text(errors="replace"), p.stat().st_mtime, "cache")

    def _install(self, feed: Feed, text: str, ts: float, origin: str) -> None:
        rs = _RangeSet(parse_feed(text))
        with self._lock:
            self._sets[feed.name] = rs
            self.status[feed.name] = {"name": feed.name, "category": feed.category, "description": feed.description,
                                      "url": feed.url, "entries": rs.entries, "updated": ts, "origin": origin,
                                      "error": None, "confidence": feed.confidence}

    def refresh(self) -> None:
        for f in self.feeds:
            p = self._path(f)
            if p.exists() and time.time() - p.stat().st_mtime < self.refresh_s * 0.9:
                continue
            try:
                req = urllib.request.Request(f.url, headers={"User-Agent": "Vigil-SIEM/1.0 (+threat-intel feed fetch)"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    text = r.read(50_000_000).decode("utf-8", "replace")
                if not parse_feed(text):
                    raise ValueError("feed returned no IPs")
                p.write_text(text)
                self._install(f, text, time.time(), "download")
                log.info("threat intel feed %s: %d entries", f.name, self.status[f.name]["entries"])
            except Exception as exc:
                st = self.status.setdefault(f.name, {"name": f.name, "category": f.category, "description": f.description,
                                                     "url": f.url, "entries": 0, "updated": None, "origin": None,
                                                     "confidence": f.confidence})
                st["error"] = str(exc)[:200]
                log.warning("threat intel feed %s unavailable: %s", f.name, exc)

    def start(self) -> None:
        if not self.enabled:
            return

        def loop():
            while not self._stop.is_set():
                self.refresh()
                self._stop.wait(min(self.refresh_s, 3600))
        threading.Thread(target=loop, name="threatintel", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    # --------------------------------------------------------------- custom
    def _custom_path(self) -> Path:
        return self.cache_dir / "custom_indicators.json"

    def _load_custom(self) -> None:
        p = self._custom_path()
        if p.exists():
            try:
                self.custom = json.loads(p.read_text())
            except ValueError:
                self.custom = {}

    def add_custom(self, indicator: str, note: str, author: str) -> dict:
        net = ipaddress.ip_network(indicator.strip(), strict=False)
        key = str(net) if net.num_addresses > 1 else str(net.network_address)
        self.custom[key] = {"indicator": key, "note": note[:500], "author": author, "added": time.time()}
        self._custom_path().write_text(json.dumps(self.custom))
        return self.custom[key]

    def remove_custom(self, indicator: str) -> bool:
        if self.custom.pop(indicator, None) is None:
            return False
        self._custom_path().write_text(json.dumps(self.custom))
        return True

    # --------------------------------------------------------------- lookup
    def lookup(self, ip: str) -> list[dict]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        hits = []
        for key, c in self.custom.items():
            try:
                if addr in ipaddress.ip_network(key, strict=False):
                    hits.append({"feed": "custom-watchlist", "category": "watchlist", "confidence": "high", "note": c.get("note")})
            except ValueError:
                continue
        if addr.version == 4:
            n = int(addr)
            with self._lock:
                for name, rs in self._sets.items():
                    if n in rs:
                        st = self.status.get(name, {})
                        hits.append({"feed": name, "category": st.get("category"), "confidence": st.get("confidence")})
        return hits

    def enrich(self, ev: dict) -> list[dict]:
        ip = ev.get("source.ip")
        if not ip:
            return []
        hits = self.lookup(str(ip))
        if hits:
            ev["threat.indicator.matched"] = True
            ev["threat.indicator.feeds"] = [h["feed"] for h in hits]
            ev["threat.indicator.category"] = sorted({h["category"] for h in hits if h.get("category")})
        return hits

    def summary(self) -> dict:
        with self._lock:
            return {"enabled": self.enabled, "feeds": list(self.status.values()),
                    "total_ranges": sum(rs.entries for rs in self._sets.values()),
                    "custom": list(self.custom.values())}
