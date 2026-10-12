import pytest

from vigil.detection.sigma import compile_rule

LINUX_AUTH = {"product": "linux", "service": "auth"}


def rule(detection, logsource=None, **kw):
    doc = {"title": "t", "id": "00000000-0000-0000-0000-000000000001", "level": "high",
           "logsource": logsource or LINUX_AUTH, "detection": detection, **kw}
    r = compile_rule(doc)
    assert r.error is None, r.error
    return r


def ev(**fields):
    base = {"log.product": "linux", "log.services": ["auth", "sshd"]}
    base.update({k.replace("__", "."): v for k, v in fields.items()})
    return base


def test_plain_equality_is_case_insensitive():
    r = rule({"sel": {"event.action": "SSH_Login_Failed"}, "condition": "sel"})
    assert r.match(ev(event__action="ssh_login_failed"))
    assert not r.match(ev(event__action="ssh_login_success"))


def test_list_values_are_or_and_maps_are_and():
    r = rule({"sel": {"user.name": ["root", "admin"], "event.outcome": "failure"}, "condition": "sel"})
    assert r.match(ev(user__name="admin", event__outcome="failure"))
    assert not r.match(ev(user__name="admin", event__outcome="success"))
    assert not r.match(ev(user__name="bob", event__outcome="failure"))


@pytest.mark.parametrize("mod,pattern,value,expected", [
    ("contains", "passwd", "/etc/passwd", True),
    ("startswith", "/tmp/", "/tmp/x", True),
    ("startswith", "/tmp/", "/var/tmp/x", False),
    ("endswith", ".sh", "run.sh", True),
    ("re", r"^a.c$", "abc", True),
    ("re", r"^a.c$", "abcd", False),
])
def test_string_modifiers(mod, pattern, value, expected):
    r = rule({"sel": {f"f|{mod}": pattern}, "condition": "sel"})
    assert r.match(ev(f=value)) is expected


def test_contains_all():
    r = rule({"sel": {"cmd|contains|all": ["curl", "| sh"]}, "condition": "sel"})
    assert r.match(ev(cmd="curl -s x | sh"))
    assert not r.match(ev(cmd="curl -s x"))


def test_wildcards_and_escape():
    r = rule({"sel": {"f": "a*z?"}, "condition": "sel"})
    assert r.match(ev(f="abcdzq")) and not r.match(ev(f="abcdz"))
    r = rule({"sel": {"f": r"literal\*"}, "condition": "sel"})
    assert r.match(ev(f="literal*")) and not r.match(ev(f="literalX"))


def test_cidr_and_numeric_comparisons():
    r = rule({"sel": {"source.ip|cidr": "203.0.113.0/24", "destination.port|gte": 1024}, "condition": "sel"})
    assert r.match(ev(source__ip="203.0.113.9", destination__port=8080))
    assert not r.match(ev(source__ip="198.51.100.9", destination__port=8080))
    assert not r.match(ev(source__ip="203.0.113.9", destination__port=22))


def test_null_and_exists():
    r = rule({"sel": {"user.name": None}, "condition": "sel"})
    assert r.match(ev()) and not r.match(ev(user__name="x"))
    r = rule({"sel": {"user.name|exists": True}, "condition": "sel"})
    assert r.match(ev(user__name="x")) and not r.match(ev())


def test_keywords_search_message():
    r = rule({"keywords": ["segfault", "out of memory"], "condition": "keywords"})
    assert r.match(ev(message="kernel: app[1]: segfault at 0"))
    assert not r.match(ev(message="all good"))


def test_condition_grammar():
    det = {"a": {"x": "1"}, "b": {"y": "1"}, "filter_1": {"z": "1"}, "filter_2": {"w": "1"},
           "condition": "(a or b) and not 1 of filter_*"}
    r = rule(det)
    assert r.match(ev(x="1"))
    assert not r.match(ev(x="1", w="1"))
    r = rule({**det, "condition": "all of them"})
    assert r.match(ev(x="1", y="1", z="1", w="1")) and not r.match(ev(x="1", y="1", z="1"))
    r = rule({**det, "condition": "1 of a* or b"})
    assert r.match(ev(y="1"))


def test_logsource_filtering():
    r = rule({"sel": {"x": "1"}, "condition": "sel"})
    assert r.matches_logsource(ev()) and not r.matches_logsource({"log.product": "windows", "x": "1"})
    r = rule({"sel": {"Image|endswith": "/curl"}, "condition": "sel"},
             logsource={"product": "linux", "category": "process_creation"})
    assert r.match({"log.product": "linux", "log.category": "process_creation", "Image": "/usr/bin/curl"})


def test_sigma_field_names_map_to_vigil_fields():
    r = rule({"sel": {"cs-uri-query|contains": "../"}, "condition": "sel"},
             logsource={"category": "webserver"})
    assert r.match({"log.category": "webserver", "url.decoded": "/x?f=../../etc/passwd"})


def test_tags_resolve_to_attack():
    r = rule({"sel": {"x": "1"}, "condition": "sel"}, tags=["attack.credential-access", "attack.t1110.001"])
    assert r.techniques == ["T1110.001"] and "credential-access" in r.tactics


def test_invalid_rules_report_errors_instead_of_raising():
    bad = compile_rule({"title": "bad", "logsource": LINUX_AUTH, "detection": {"sel": {"x": 1}, "condition": "sel and nope"}})
    assert bad.error
    assert compile_rule({"title": "no detection", "logsource": LINUX_AUTH}).error == "missing detection"


def test_bundled_rule_sets_compile(engine_report):
    # Every vendored SigmaHQ rule and every Vigil rule must compile.
    assert engine_report.rules > 1500 and engine_report.correlations >= 8
    assert engine_report.errors == []
