import calendar
import random

from vigil.detection.ueba import UEBA, _decay, _novelty_bits, risk_from_bits

DAY = 86400
T0 = calendar.timegm((2026, 9, 1, 0, 0, 0))


def login(ts, user="alice", ip="198.51.100.10", method="publickey", cc=None, lat=None, lon=None, host="web01", net_type="external"):
    ev = {"@timestamp": ts, "event.action": "ssh_login_success", "user.name": user, "source.ip": ip,
          "auth.method": method, "host.name": host, "source.network.type": net_type}
    if cc:
        ev.update({"source.geo.country_iso_code": cc, "source.geo.location.lat": lat, "source.geo.location.lon": lon})
    return ev


def train(u, days=14, per_day=2, **kw):
    rnd = random.Random(7)
    for d in range(days):
        for _ in range(per_day):
            u.observe(login(T0 + d * DAY + rnd.choice([9, 10, 11, 14, 15]) * 3600 + rnd.randint(0, 3599), **kw))


def test_scoring_helpers():
    assert _novelty_bits({"a": 5}, "a", 5) == 0
    assert _novelty_bits({"a": 50}, "b", 50) > _novelty_bits({"a": 2}, "b", 2)  # rarer novelty on a stable profile
    assert risk_from_bits(0) == 0 and 68 <= risk_from_bits(8) <= 72 and risk_from_bits(40) > 99


def test_no_alerts_while_learning():
    u = UEBA(min_observations=20)
    out = []
    for i in range(19):
        out += u.observe(login(T0 + i * 60, ip=f"192.0.2.{i}", method="password"))
    assert out == []


def test_routine_login_is_quiet():
    u = UEBA()
    train(u)
    assert u.observe(login(T0 + 15 * DAY + 10 * 3600)) == []
    assert u.get_profile("user:alice")["n"] >= 28


def test_unusual_login_raises_explained_anomaly():
    u = UEBA()
    train(u)
    out = u.observe(login(T0 + 15 * DAY + 3 * 3600 + 7 * 60, ip="192.0.2.50", method="password"))
    assert len(out) == 1
    a = out[0]
    assert a.model == "login_anomaly" and a.risk >= 70 and a.techniques == ["T1078"]
    features = {f["feature"] for f in a.factors}
    assert {"login_hour", "new_auth_method", "new_network"} <= features
    assert all(f["detail"] for f in a.factors)


def test_one_new_factor_alone_is_not_enough():
    u = UEBA()
    train(u)
    assert u.observe(login(T0 + 15 * DAY + 10 * 3600, ip="198.51.100.99")) == []  # same /24, usual hour and method


def test_impossible_travel_from_injected_geo():
    u = UEBA()
    t = T0 + 10 * 3600
    u.observe(login(t, ip="198.51.100.10", cc="DE", lat=51.0, lon=9.0))
    out = u.observe(login(t + 1800, ip="192.0.2.10", cc="AU", lat=-25.0, lon=134.0))
    travel = [a for a in out if a.model == "impossible_travel"]
    assert travel and travel[0].risk == 90
    assert "km/h" in travel[0].factors[0]["detail"]


def test_plausible_travel_is_quiet():
    u = UEBA()
    t = T0 + 10 * 3600
    u.observe(login(t, cc="DE", lat=51.0, lon=9.0))
    out = u.observe(login(t + 12 * 3600, ip="192.0.2.10", cc="FR", lat=46.0, lon=2.0))
    assert not [a for a in out if a.model == "impossible_travel"]


def test_internal_addresses_skip_geo_features():
    u = UEBA()
    t = T0 + 10 * 3600
    u.observe(login(t, cc="DE", lat=51.0, lon=9.0))
    out = u.observe(login(t + 60, ip="10.0.0.5", cc="AU", lat=-25.0, lon=134.0, net_type="internal"))
    assert not [a for a in out if a.model == "impossible_travel"]


def test_counts_decay_with_half_life():
    st = {"updated": 1, "hours": [8.0] * 24, "countries": {"DE": 8.0, "FR": 0.06}}
    _decay(st, 1 + 30 * DAY)
    assert abs(st["hours"][0] - 4.0) < 1e-6 and st["countries"] == {"DE": 4.0}  # FR fell below the floor


def test_rare_process_on_mature_host():
    u = UEBA()
    common = ["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/sbin/cron", "/usr/bin/python3"]
    t = T0
    for i in range(400):
        t += 30
        exe = common[i % len(common)]
        u.observe({"@timestamp": t, "log.category": "process_creation", "host.name": "web01",
                   "process.executable": exe, "process.parent.executable": "/usr/bin/bash"})
    out = u.observe({"@timestamp": t + 30, "log.category": "process_creation", "host.name": "web01",
                     "process.executable": "/tmp/.x/runner", "process.parent.executable": "/usr/sbin/nginx"})
    assert out and out[0].model == "rare_process"
    assert {"new_executable", "new_parent_child", "risky_location"} <= {f["feature"] for f in out[0].factors}
    again = u.observe({"@timestamp": t + 60, "log.category": "process_creation", "host.name": "web01",
                       "process.executable": "/usr/bin/ls", "process.parent.executable": "/usr/bin/bash"})
    assert again == []


def test_volume_spike():
    u = UEBA()
    t = T0
    for b in range(40):  # 40 five-minute buckets of ~5 web events
        for i in range(5):
            u.observe({"@timestamp": t + b * 300 + i, "event.category": "webserver", "host.name": "web01"})
    t += 40 * 300
    spikes = []
    for i in range(300):
        spikes += u.observe({"@timestamp": t + i * 0.5, "event.category": "webserver", "host.name": "web01"})
    assert len(spikes) == 1 and spikes[0].model == "volume_spike"
