import sqlite3

import pytest

from vigil.search import SearchError, cidr_match, compile_query, field_sql


def test_basic_field_terms_compile_to_bound_parameters():
    c = compile_query("source.ip:203.0.113.5 AND event.action:ssh_login_failed")
    assert "src_ip" in c.where and "action" in c.where
    assert c.params == ["203.0.113.5", "ssh_login_failed"]


def test_operators_and_pipes():
    c = compile_query('http.response.status_code>=500 NOT host.name:web* | stats count by source.ip, user.name')
    assert 500.0 in c.params and "web%" in c.params and "NOT" in c.where
    assert ("stats", ["source.ip", "user.name"]) in c.commands
    c = compile_query('"Failed password" | top user.name | head 5')
    assert "events_fts" in c.where and ("head", ["5"]) in c.commands


def test_cidr_and_exists():
    c = compile_query("source.ip:10.0.0.0/8 user.name:*")
    assert "cidr_match" in c.where and "IS NOT NULL" in c.where
    assert cidr_match("10.1.2.3", "10.0.0.0/8") == 1 and cidr_match("11.0.0.1", "10.0.0.0/8") == 0
    assert cidr_match("not-an-ip", "10.0.0.0/8") == 0


@pytest.mark.parametrize("q", [
    "x' OR 1=1 --:a",
    "a\"b:1",
    "field);DROP TABLE events;--:1",
    "(source.ip:1",
    "status>abc",
])
def test_hostile_or_broken_queries_are_rejected(q):
    with pytest.raises(SearchError):
        compile_query(q)


def test_values_never_reach_sql_text():
    payload = "1' ; DROP TABLE events; --"
    c = compile_query(f'user.name:"{payload}"')
    assert "DROP" not in c.where and payload in c.params


def test_field_names_are_validated():
    assert field_sql("host.name") == "host"
    assert field_sql("process.parent.executable") == "json_extract(fields, '$.\"process.parent.executable\"')"
    with pytest.raises(SearchError):
        field_sql("a'b")


def test_compiled_sql_executes(client):
    from vigil.search import run_search
    conn = client.vigil.db.reader
    for q in ["user.name:u1", "source.ip:203.0.113.0/24 | stats count by source.ip", "ssh | top host.name",
              "event.action:ssh_login_failed | sort -@timestamp | table user.name", "| stats count"]:
        res = run_search(conn, q, 0, 2e10)
        assert res["type"] in ("events", "stats")
    assert isinstance(conn, sqlite3.Connection)
