"""UEBA: unsupervised behavioural baselining that learns from the operator's
own logs. There is no pre-trained model and no training dataset; every
profile starts empty and learns online, one event at a time.

Models
------
Login model (per user)
    * hour-of-day distribution, kernel-smoothed on a circle, with a uniform
      Dirichlet prior so a young profile is not over-confident
    * categorical novelty for source country, ASN, /24 network, IP, host and
      auth method. The probability of seeing a never-seen value is estimated
      with a Good-Turing style estimator  P(new) = (distinct + 1) / (n + 2)
    * impossible travel: geodesic speed between consecutive logins
Process model (per host)
    * executable novelty and parent -> child pair novelty, weighted by how
      rare the executable is across all hosts (global prevalence)
Volume model (per host and event category)
    * exponentially weighted mean / variance of event counts per 5-minute
      bucket; a bucket far above the learned level is a spike

Each anomaly is scored in bits of surprise (-log2 p). Bits from the
individual features are summed and mapped to a 0-100 risk score, and every
alert lists the features that contributed so an analyst can see *why*.
Counts decay with a 30-day half-life so profiles follow behaviour changes.
"""
from __future__ import annotations

import json
import logging
import math
import threading
import time
from dataclasses import dataclass

log = logging.getLogger("vigil.ueba")

HALF_LIFE_S = 30 * 86400
BUCKET_S = 300
LOGIN_ACTIONS = {"ssh_login_success", "logon_success", "su_success"}
RISKY_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")


def _decay(state: dict, now: float) -> None:
    last = state.get("updated") or now
    dt = max(0.0, now - last)
    if dt < 3600:
        return
    f = 0.5 ** (dt / HALF_LIFE_S)
    state["hours"] = [h * f for h in state.get("hours", [])]
    for key in ("countries", "asns", "nets", "ips", "hosts", "methods", "exes", "pairs"):
        if key in state:
            state[key] = {k: v * f for k, v in state[key].items() if v * f >= 0.05}
    state["updated"] = now


def _novelty_bits(counts: dict, value, n: float) -> float:
    """Surprise of value given categorical counts (0 if seen before)."""
    if value is None or value in counts:
        return 0.0
    distinct = len(counts)
    p_new = (distinct + 1) / (n + 2)
    return -math.log2(p_new)


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def risk_from_bits(bits: float) -> int:
    """Map summed surprise to 0-100. ~8 bits -> 70, ~13 bits -> 90."""
    return round(100 * (1 - math.exp(-bits / 6.6)))


@dataclass
class Anomaly:
    model: str
    entity: str
    risk: int
    title: str
    factors: list[dict]
    event: dict
    severity: str
    techniques: list[str]
    tactics: list[str]


class UEBA:
    def __init__(self, min_observations: int = 20, threshold: int = 70, store=None):
        self.min_obs = min_observations
        self.threshold = threshold
        self.store = store  # Database or None
        self.profiles: dict[str, dict] = {}
        self.global_exes: dict[str, list[str]] = {}
        self._dirty: set[str] = set()
        self._lock = threading.RLock()
        self._volume: dict[str, dict] = {}
        if store is not None:
            self._load()

    # ------------------------------------------------------------ persistence
    def _load(self) -> None:
        for row in self.store.query("SELECT entity, state FROM ueba_models"):
            st = json.loads(row["state"])
            if row["entity"] == "__global_exes__":
                self.global_exes = st
            elif row["entity"].startswith("vol:"):
                self._volume[row["entity"]] = st
            else:
                self.profiles[row["entity"]] = st
        log.info("UEBA loaded %d profiles", len(self.profiles))

    def save(self) -> None:
        if self.store is None:
            return
        with self._lock:
            dirty = list(self._dirty)
            self._dirty.clear()
            rows = []
            for e in dirty:
                if e == "__global_exes__":
                    rows.append((e, "global", json.dumps(self.global_exes)))
                elif e.startswith("vol:"):
                    rows.append((e, "volume", json.dumps(self._volume[e])))
                elif e in self.profiles:
                    rows.append((e, self.profiles[e]["kind"], json.dumps(self.profiles[e])))
        if rows:
            now = time.time()
            with self.store.tx() as c:
                c.executemany("INSERT INTO ueba_models(entity, kind, updated_ts, state) VALUES(?,?,?,?) "
                              "ON CONFLICT(entity) DO UPDATE SET kind=excluded.kind, updated_ts=excluded.updated_ts, "
                              "state=excluded.state", [(e, k, now, s) for e, k, s in rows])

    # ---------------------------------------------------------------- public
    def observe(self, ev: dict) -> list[Anomaly]:
        out: list[Anomaly] = []
        action = ev.get("event.action")
        with self._lock:
            if action in LOGIN_ACTIONS and ev.get("user.name"):
                a = self._login(ev)
                out.extend(a)
            if ev.get("log.category") == "process_creation" and ev.get("host.name") and ev.get("process.executable"):
                out.extend(self._process(ev))
            cat = ev.get("event.category")
            if cat in ("authentication", "webserver", "network", "process_creation", "iam") and ev.get("host.name"):
                a = self._volume_tick(ev, cat)
                if a:
                    out.append(a)
        return out

    # ---------------------------------------------------------------- logins
    def _login(self, ev: dict) -> list[Anomaly]:
        user = str(ev["user.name"])
        entity = f"user:{user}"
        now = float(ev.get("@timestamp") or time.time())
        p = self.profiles.get(entity)
        if p is None:
            p = self.profiles[entity] = {"kind": "user", "entity": entity, "name": user, "n": 0.0, "hours": [0.0] * 24,
                                         "countries": {}, "asns": {}, "nets": {}, "ips": {}, "hosts": {}, "methods": {},
                                         "first_seen": now, "updated": now, "last": None, "alerts": 0}
        _decay(p, now)
        hour = time.gmtime(now).tm_hour
        ip = ev.get("source.ip")
        cc = ev.get("source.geo.country_iso_code")
        asn = ev.get("source.as.number")
        net = ".".join(str(ip).split(".")[:3]) + ".0/24" if ip and "." in str(ip) else None
        host = ev.get("host.name")
        method = ev.get("auth.method") or ev.get("winlog.logon.type")
        internal = ev.get("source.network.type") == "internal"
        factors: list[dict] = []
        out: list[Anomaly] = []
        mature = p["n"] >= self.min_obs

        if mature:
            # hour of day: circular kernel smoothing + uniform Dirichlet prior (alpha = 4 pseudo-counts)
            hours = p["hours"]
            sm = [0.5 * hours[h] + 0.25 * hours[(h - 1) % 24] + 0.25 * hours[(h + 1) % 24] for h in range(24)]
            tot = sum(sm)
            alpha = 4.0
            prob = (sm[hour] + alpha / 24) / (tot + alpha)
            bits = max(0.0, -math.log2(prob * 24))
            if bits >= 1.5:
                usual = sorted(range(24), key=lambda h: -hours[h])[:3]
                factors.append({"feature": "login_hour", "bits": round(bits, 2),
                                "detail": f"login at {hour:02d}:00 UTC; this user usually logs in around "
                                          f"{', '.join(f'{h:02d}:00' for h in sorted(usual))}"})
            if not internal:
                for key, val, label, weight in (("countries", cc, "country", 1.0), ("asns", str(asn) if asn else None, "network provider (ASN)", 0.6)):
                    b = _novelty_bits(p[key], val, p["n"]) * weight
                    if b > 0:
                        seen = ", ".join(sorted(p[key], key=lambda k: -p[key][k])[:4]) or "none"
                        extra = f" ({ev.get('source.as.organization.name')})" if key == "asns" and ev.get("source.as.organization.name") else ""
                        factors.append({"feature": f"new_{label.split()[0].lower()}", "bits": round(b, 2),
                                        "detail": f"first login from {label} {val}{extra}; previously seen: {seen}"})
            b = _novelty_bits(p["nets"], net, p["n"]) * 0.5
            if b > 0:
                seen = ", ".join(sorted(p["nets"], key=lambda k: -p["nets"][k])[:4])
                factors.append({"feature": "new_network", "bits": round(b, 2),
                                "detail": f"first login from network {net}; previously seen: {seen}"})
            b = _novelty_bits(p["hosts"], host, p["n"]) * 0.5
            if b > 0:
                factors.append({"feature": "new_host", "bits": round(b, 2), "detail": f"first login to host {host}"})
            b = _novelty_bits(p["methods"], method, p["n"])
            if b > 0 and method:
                factors.append({"feature": "new_auth_method", "bits": round(b, 2),
                                "detail": f"auth method '{method}' never used by this account (usual: {', '.join(p['methods'])})"})
        # impossible travel works from the 2nd login on, but only alerts on a mature profile
        last = p.get("last")
        lat, lon = ev.get("source.geo.location.lat"), ev.get("source.geo.location.lon")
        if last and lat is not None and last.get("lat") is not None and not internal and last.get("cc") is not None and cc != last.get("cc"):
            km = _haversine_km(last["lat"], last["lon"], lat, lon)
            hours_between = max((now - last["ts"]) / 3600, 1 / 60)
            speed = km / hours_between
            if km > 500 and speed > 900:
                travel = {"feature": "impossible_travel", "bits": 10.0,
                          "detail": f"{last.get('cc')} -> {cc}: {km:,.0f} km in {hours_between*60:,.0f} min "
                                    f"({speed:,.0f} km/h); previous login from {last.get('ip')}"}
                out.append(Anomaly("impossible_travel", entity, 90, f"Impossible travel for {user}", [travel], ev,
                                   "high", ["T1078"], ["initial-access"]))

        bits = sum(f["bits"] for f in factors)
        risk = risk_from_bits(bits)
        if mature and risk >= self.threshold:
            p["alerts"] = p.get("alerts", 0) + 1
            out.append(Anomaly("login_anomaly", entity, risk, f"Anomalous login for {user}",
                               sorted(factors, key=lambda f: -f["bits"]), ev,
                               "high" if risk >= 90 else "medium", ["T1078"], ["initial-access"]))

        # learn
        p["n"] += 1
        p["hours"][hour] += 1
        for key, val in (("countries", cc), ("asns", str(asn) if asn else None), ("nets", net), ("ips", ip),
                         ("hosts", host), ("methods", method)):
            if val is not None:
                p[key][str(val)] = p[key].get(str(val), 0) + 1
        if len(p["ips"]) > 500:  # bound memory
            p["ips"] = dict(sorted(p["ips"].items(), key=lambda kv: -kv[1])[:250])
        p["last"] = {"ts": now, "ip": ip, "cc": cc, "lat": lat, "lon": lon}
        p["last_risk"] = risk if mature else None
        p["updated"] = now
        self._dirty.add(entity)
        return out

    # -------------------------------------------------------------- processes
    def _process(self, ev: dict) -> list[Anomaly]:
        host = str(ev["host.name"])
        entity = f"host:{host}"
        now = float(ev.get("@timestamp") or time.time())
        p = self.profiles.get(entity)
        if p is None:
            p = self.profiles[entity] = {"kind": "host", "entity": entity, "name": host, "n": 0.0, "exes": {},
                                         "pairs": {}, "first_seen": now, "updated": now, "alerts": 0}
        _decay(p, now)
        exe = str(ev.get("process.executable"))
        parent = ev.get("process.parent.executable")
        pair = f"{(parent or '?').rsplit('/', 1)[-1]}>{exe.rsplit('/', 1)[-1]}"
        mature = p["n"] >= max(self.min_obs * 10, 200) and now - p["first_seen"] > 3600
        out = []
        if mature:
            factors = []
            b_exe = _novelty_bits(p["exes"], exe, p["n"])
            if b_exe > 0:
                hosts_with = len(self.global_exes.get(exe, []))
                n_hosts = max(1, sum(1 for e in self.profiles.values() if e["kind"] == "host"))
                prevalence = hosts_with / n_hosts
                factors.append({"feature": "new_executable", "bits": round(b_exe * (1 - 0.7 * prevalence), 2),
                                "detail": f"{exe} never ran on {host} before (seen on {hosts_with} of {n_hosts} hosts)"})
            b_pair = _novelty_bits(p["pairs"], pair, p["n"]) * 0.8
            if b_pair > 0:
                factors.append({"feature": "new_parent_child", "bits": round(b_pair, 2),
                                "detail": f"process lineage {pair.replace('>', ' -> ')} never seen on {host}"})
            if factors and exe.startswith(RISKY_DIRS):
                factors.append({"feature": "risky_location", "bits": 3.0,
                                "detail": f"executable runs from a world-writable directory ({exe.rsplit('/', 1)[0]}/)"})
            bits = sum(f["bits"] for f in factors)
            risk = risk_from_bits(bits)
            if risk >= self.threshold:
                p["alerts"] = p.get("alerts", 0) + 1
                out.append(Anomaly("rare_process", entity, risk, f"Rare process on {host}: {exe.rsplit('/', 1)[-1]}",
                                   sorted(factors, key=lambda f: -f["bits"]), ev, "high" if risk >= 90 else "medium",
                                   ["T1059"], ["execution"]))
        p["n"] += 1
        p["exes"][exe] = p["exes"].get(exe, 0) + 1
        p["pairs"][pair] = p["pairs"].get(pair, 0) + 1
        if len(p["exes"]) > 5000:
            p["exes"] = dict(sorted(p["exes"].items(), key=lambda kv: -kv[1])[:2500])
        if len(p["pairs"]) > 5000:
            p["pairs"] = dict(sorted(p["pairs"].items(), key=lambda kv: -kv[1])[:2500])
        hosts = self.global_exes.setdefault(exe, [])
        if host not in hosts and len(hosts) < 1000:
            hosts.append(host)
            self._dirty.add("__global_exes__")
        p["updated"] = now
        self._dirty.add(entity)
        return out

    # ----------------------------------------------------------------- volume
    def _volume_tick(self, ev: dict, cat: str) -> Anomaly | None:
        key = f"vol:{ev['host.name']}:{cat}"
        now = float(ev.get("@timestamp") or time.time())
        bucket = int(now // BUCKET_S)
        st = self._volume.get(key)
        if st is None:
            st = self._volume[key] = {"bucket": bucket, "count": 0, "mean": 0.0, "var": 0.0, "n": 0, "alerted": None}
        anomaly = None
        if bucket > st["bucket"]:
            self._close_bucket(st, st["count"])
            for _ in range(min(bucket - st["bucket"] - 1, 288)):  # empty buckets in between
                self._close_bucket(st, 0)
            st["bucket"], st["count"] = bucket, 0
        elif bucket < st["bucket"]:
            return None  # late event from an already-closed bucket
        st["count"] += 1
        # Alert while the bucket is still open, once per bucket.
        if st["n"] >= 24 and st["alerted"] != bucket:
            sd = math.sqrt(st["var"]) + 1.0
            z = (st["count"] - st["mean"]) / sd
            if z >= 6 and st["count"] >= max(50, 5 * st["mean"]):
                st["alerted"] = bucket
                risk = min(99, 60 + int(z))
                anomaly = Anomaly("volume_spike", key, risk, f"Spike in {cat} events on {ev['host.name']}",
                                  [{"feature": "event_rate", "bits": round(z, 1),
                                    "detail": f"{st['count']} {cat} events in the current 5 min window; learned normal "
                                              f"is {st['mean']:.1f} ± {math.sqrt(st['var']):.1f} (z = {z:.1f})"}],
                                  ev, "medium", ["T1499"] if cat == "webserver" else [], [])
        self._dirty.add(key)
        return anomaly

    @staticmethod
    def _close_bucket(st: dict, count: int) -> None:
        a = 0.1 if st["n"] >= 10 else 1.0 / (st["n"] + 1)
        diff = count - st["mean"]
        st["mean"] += a * diff
        st["var"] = (1 - a) * (st["var"] + a * diff * diff)
        st["n"] += 1

    # ------------------------------------------------------------------ views
    def list_profiles(self) -> list[dict]:
        with self._lock:
            out = []
            for e, p in self.profiles.items():
                need = self.min_obs if p["kind"] == "user" else max(self.min_obs * 10, 200)
                item = {"entity": e, "kind": p["kind"], "name": p["name"], "observations": round(p["n"]),
                        "learning_progress": min(100, int(100 * p["n"] / need)), "first_seen": p["first_seen"],
                        "updated": p["updated"], "alerts": p.get("alerts", 0)}
                if p["kind"] == "user":
                    item.update({"countries": p["countries"], "hours": p["hours"], "hosts": list(p["hosts"]),
                                 "methods": p["methods"], "last_risk": p.get("last_risk"),
                                 "asns": len(p["asns"]), "ips": len(p["ips"])})
                else:
                    item.update({"executables": len(p["exes"]), "lineages": len(p["pairs"])})
                out.append(item)
            return sorted(out, key=lambda x: (-x["alerts"], -x["observations"]))

    def get_profile(self, entity: str) -> dict | None:
        with self._lock:
            p = self.profiles.get(entity)
            if p is None:
                return None
            d = json.loads(json.dumps(p))
            if p["kind"] == "host":
                d["exes"] = dict(sorted(p["exes"].items(), key=lambda kv: -kv[1])[:200])
                d["pairs"] = dict(sorted(p["pairs"].items(), key=lambda kv: -kv[1])[:200])
            return d
