import gzip
import json
import time

from fastapi.testclient import TestClient

from conftest import ENROLL, wait_for


def lines_bruteforce(ip="203.0.113.77", n=12):
    now = time.strftime("%b %e %H:%M:%S", time.localtime(time.time() - 60))
    return [f"{now} api-host sshd[{i}]: Failed password for invalid user u{i} from {ip} port {40000 + i} ssh2" for i in range(n)]


def enroll(client, hostname="api-host"):
    r = client.post("/api/v1/agents/enroll", json={"enrollment_token": ENROLL, "hostname": hostname, "os": "Linux", "version": "1.0.0"})
    assert r.status_code == 200, r.text
    return r.json()


def ingest(client, token, lines, path="/var/log/auth.log", gz=True):
    body = json.dumps({"host": "api-host", "records": [{"type": "file", "path": path, "line": x} for x in lines]}).encode()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if gz:
        body, headers["Content-Encoding"] = gzip.compress(body), "gzip"
    return client.post("/api/v1/ingest", content=body, headers=headers)


def test_health_and_security_headers(client):
    r = client.get("/api/health")
    assert r.json()["status"] == "ok"
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]


def test_unauthenticated_requests_are_rejected(client):
    anon = TestClient(client.app)
    assert anon.get("/api/alerts").status_code == 401
    assert anon.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401


def test_csrf_header_required_for_state_changes(client):
    r = client.post("/api/auth/logout", headers={"X-Vigil-Request": ""})
    assert r.status_code == 403
    assert client.get("/api/auth/me").status_code == 200  # still logged in


def test_enrollment_requires_the_token(client):
    r = client.post("/api/v1/agents/enroll", json={"enrollment_token": "nope", "hostname": "x"})
    assert r.status_code == 401
    assert client.post("/api/v1/ingest", json={"records": []}, headers={"Authorization": "Bearer bogus"}).status_code == 401


def test_ingest_detect_triage_flow(client):
    agent = enroll(client)
    r = ingest(client, agent["token"], lines_bruteforce())
    assert r.status_code == 200 and r.json()["accepted"] == 12

    def bf_alert():
        items = client.get("/api/alerts", params={"q": "Brute Force"}).json()["items"]
        return [a for a in items if a["rule_title"] == "SSH Brute Force" and a["src_ip"] == "203.0.113.77"]
    alert = wait_for(bf_alert)[0]
    assert alert["rule_type"] == "correlation" and alert["incident_id"]

    detail = client.get(f"/api/alerts/{alert['id']}").json()
    assert "T1110" in json.dumps(detail) and detail["events"]

    r = client.patch(f"/api/alerts/{alert['id']}", json={"status": "in_progress", "assignee": "admin"})
    assert r.status_code == 200 and r.json()["status"] == "in_progress" and r.json()["assignee"] == "admin"
    assert client.patch(f"/api/alerts/{alert['id']}", json={"status": "bogus"}).status_code == 400
    assert client.patch(f"/api/alerts/{alert['id']}", json={"assignee": "nobody"}).status_code == 400

    r = client.post(f"/api/alerts/{alert['id']}/comments", json={"body": "Blocked at the edge <b>firewall</b>"})
    assert r.status_code == 200
    comments = client.get(f"/api/alerts/{alert['id']}").json()["comments"]
    assert comments[-1]["body"] == "Blocked at the edge <b>firewall</b>"  # stored verbatim, escaped by the UI

    inc = client.get(f"/api/incidents/{alert['incident_id']}").json()
    assert any(a["id"] == alert["id"] for a in inc["alerts"])
    r = client.patch(f"/api/incidents/{alert['incident_id']}", json={"status": "closed", "resolution": "true_positive"})
    assert r.status_code == 200
    assert client.get(f"/api/alerts/{alert['id']}").json()["status"] == "closed"

    audit = json.dumps(client.get("/api/audit").json())
    assert "alert_updated" in audit and "incident_updated" in audit


def test_search_api(client):
    agent = enroll(client, "search-host")
    ingest(client, agent["token"], lines_bruteforce(ip="198.51.100.200", n=3), gz=False)
    res = wait_for(lambda: client.get("/api/search", params={"q": "source.ip:198.51.100.0/24 | stats count by source.ip"}).json().get("rows"))
    assert ["198.51.100.200", 3] in res
    assert client.get("/api/search", params={"q": "bad.field';--:x"}).status_code == 400


def test_rule_backtest_and_toggle(client):
    yaml = """
title: Test failed logins for u1
logsource: {product: linux, service: auth}
detection:
  sel: {user.name: u1, event.action: ssh_login_failed}
  condition: sel
level: low
"""
    r = client.post("/api/rules/test", json={"yaml": yaml, "hours": 1})
    assert r.status_code == 200 and r.json()["matched"] >= 1
    rid = "0a390073-2324-4ab4-936c-00d5a82efeed"
    assert client.patch(f"/api/rules/{rid}", json={"enabled": False}).status_code == 200
    assert client.get(f"/api/rules/{rid}").json()["enabled"] is False
    client.patch(f"/api/rules/{rid}", json={"enabled": True})


def test_viewer_role_is_read_only(client):
    assert client.post("/api/users", json={"username": "viewer1", "password": "viewer-password-1", "role": "viewer"}).status_code == 200
    v = TestClient(client.app)
    v.headers["X-Vigil-Request"] = "1"
    assert v.post("/api/auth/login", json={"username": "viewer1", "password": "viewer-password-1"}).status_code == 200
    assert v.get("/api/alerts").status_code == 200
    first = client.get("/api/alerts").json()["items"][0]["id"]
    assert v.patch(f"/api/alerts/{first}", json={"status": "closed"}).status_code == 403
    assert v.get("/api/users").status_code == 403


def test_console_login_failures_are_detected(client):
    anon = TestClient(client.app)
    for _ in range(3):
        anon.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    rows = wait_for(lambda: client.get("/api/search", params={"q": "event.action:vigil_login_failed"}).json().get("events"))
    assert len(rows) >= 3


def test_metrics_and_openapi(client):
    assert "vigil_events_processed_total" in client.get("/metrics").text
    assert client.get("/api/openapi.json").status_code == 200
