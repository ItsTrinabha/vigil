import copy

from vigil.detection.correlation import CorrelationEngine, Hit, compile_correlation, parse_timespan


def corr(**kw):
    doc = {"title": "c", "id": kw.pop("id", "c1"), "level": "high",
           "correlation": {"rules": ["base"], "group-by": ["source.ip"], "timespan": "5m", **kw}}
    c = compile_correlation(doc)
    assert c.error is None, c.error
    return c


def hit(ts, ip="203.0.113.1", ref="base", **fields):
    return Hit((ref,), ts, {"source.ip": ip, **fields}, [int(ts)])


def test_timespan_parsing():
    assert parse_timespan("90s") == 90 and parse_timespan("5m") == 300 and parse_timespan("1h") == 3600


def test_event_count_fires_once_at_threshold_per_group():
    e = CorrelationEngine([corr(type="event_count", condition={"gte": 3})])
    assert not e.process(hit(0)) and not e.process(hit(1))
    assert not e.process(hit(1, ip="198.51.100.1"))          # other group does not count
    m = e.process(hit(2))
    assert len(m) == 1 and m[0].group == {"source.ip": "203.0.113.1"} and m[0].event_ids == [0, 1, 2]
    assert not e.process(hit(3))                             # window resets after firing


def test_event_count_respects_timespan():
    e = CorrelationEngine([corr(type="event_count", condition={"gte": 3})])
    e.process(hit(0))
    e.process(hit(200))
    assert not e.process(hit(400))  # first hit slid out of the 5 minute window
    assert e.process(hit(401))


def test_value_count_counts_distinct_values():
    e = CorrelationEngine([corr(type="value_count", condition={"gte": 3, "field": "user.name"})])
    for u in ["root", "root", "admin"]:
        assert not e.process(hit(1, **{"user.name": u}))
    m = e.process(hit(2, **{"user.name": "test"}))
    assert m and m[0].details["value_count"] == 3 and m[0].details["values"] == ["admin", "root", "test"]


def test_temporal_ordered_requires_order():
    c = compile_correlation({"title": "seq", "id": "s", "correlation": {
        "type": "temporal_ordered", "rules": ["a", "b"], "group-by": ["user.name"], "timespan": "10m"}})
    e = CorrelationEngine([c])
    assert not e.process(Hit(("b",), 0, {"user.name": "x"}, [1]))
    assert e.process(Hit(("a",), 1, {"user.name": "x"}, [2])) == []   # b came before a: no sequence yet
    assert e.process(Hit(("b",), 2, {"user.name": "x"}, [3]))


def test_temporal_any_order():
    c = compile_correlation({"title": "t", "id": "t", "correlation": {
        "type": "temporal", "rules": ["a", "b"], "group-by": ["host.name"], "timespan": "10m"}})
    e = CorrelationEngine([c])
    assert not e.process(Hit(("b",), 0, {"host.name": "h"}, [1]))
    assert e.process(Hit(("a",), 1, {"host.name": "h"}, [2]))


def test_aliases_join_on_differently_named_fields():
    c = compile_correlation({"title": "t", "id": "t", "correlation": {
        "type": "temporal", "rules": ["a", "b"], "group-by": ["ip"], "timespan": "10m",
        "aliases": {"ip": {"a": "source.ip", "b": "client.ip"}}}})
    e = CorrelationEngine([c])
    e.process(Hit(("a",), 0, {"source.ip": "192.0.2.1"}, [1]))
    m = e.process(Hit(("b",), 1, {"client.ip": "192.0.2.1"}, [2]))
    assert m and m[0].group == {"ip": "192.0.2.1"}


def test_missing_group_field_is_ignored():
    e = CorrelationEngine([corr(type="event_count", condition={"gte": 1})])
    assert e.process(Hit(("base",), 0, {"user.name": "x"}, [1])) == []


def test_chained_correlation():
    first = corr(id="first", type="event_count", condition={"gte": 2})
    first.name = "first"
    second = compile_correlation({"title": "chain", "id": "second", "correlation": {
        "type": "temporal_ordered", "rules": ["first", "later"], "group-by": ["source.ip"], "timespan": "10m"}})
    e = CorrelationEngine([first, second])
    e.process(hit(0))
    assert [m.rule.id for m in e.process(hit(1))] == ["first"]
    assert [m.rule.id for m in e.process(hit(2, ref="later"))] == ["second"]


def test_gc_drops_stale_groups():
    e = CorrelationEngine([corr(type="event_count", condition={"gte": 5})])
    e.process(hit(0))
    e.gc(now=10_000)
    assert e._state["c1"] == {}


# ------------------------------------------------- with the shipped rule set
def _run(engine, normalizer, lines, path="/var/log/auth.log"):
    titles = []
    for i, line in enumerate(lines):
        for ev in normalizer.parse({"type": "file", "path": path, "line": line}, host="lab-web-01"):
            titles += [d.rule_title for d in engine.evaluate(copy.deepcopy(ev), i)]
    return titles


def test_shipped_rules_detect_bruteforce_then_root(engine, normalizer):
    ip = "203.0.113.20"
    lines = [f"Oct 11 22:14:{i:02d} lab-web-01 sshd[{i}]: Failed password for deploy from {ip} port {40000 + i} ssh2"
             for i in range(12)]
    lines += [f"Oct 11 22:14:30 lab-web-01 sshd[99]: Accepted password for deploy from {ip} port 41999 ssh2",
              "Oct 11 22:15:10 lab-web-01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"]
    titles = _run(engine, normalizer, lines)
    for expected in ("SSH Brute Force", "Successful SSH Login After Brute Force",
                     "Brute-Forced Account Escalated to Root", "Root Shell Opened Through Sudo"):
        assert expected in titles, (expected, titles)
    # base rules referenced only by correlations stay silent
    assert "SSH Authentication Failure" not in titles


def test_shipped_rules_detect_password_spray(engine, normalizer):
    users = ["amy", "ben", "cara", "dan", "eve", "fay"]
    lines = [f"Oct 11 23:00:{i:02d} lab-web-01 sshd[{i}]: Failed password for invalid user {u} from 198.51.100.66 port 5{i:04d} ssh2"
             for i, u in enumerate(users)]
    assert "SSH Password Spraying" in _run(engine, normalizer, lines)


def test_normal_admin_activity_is_quiet(engine, normalizer):
    lines = [f"Oct 11 10:0{i}:00 lab-web-01 sshd[{i}]: Accepted publickey for alice from 198.51.100.10 port 5000{i} ssh2: ED25519 SHA256:k"
             for i in range(5)]
    lines.append("Oct 11 10:06:00 lab-web-01 CRON[7]: (root) CMD (/usr/local/bin/backup.sh)")
    assert _run(engine, normalizer, lines) == []


def test_portscan_value_count(engine, normalizer):
    lines = [f"Oct 11 22:16:00 lab-web-01 kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.40 DST=198.51.100.5 "
             f"LEN=44 PROTO=TCP SPT=61000 DPT={p} WINDOW=1024 SYN URGP=0" for p in range(1000, 1020)]
    titles = _run(engine, normalizer, lines, path="/var/log/syslog")
    assert titles.count("Port Scan Against Host") == 1

