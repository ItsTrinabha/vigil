import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "agent"))
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def normalizer():
    from vigil.parsers import Normalizer
    return Normalizer()


def parse_one(normalizer, line, path="/var/log/auth.log", host="web01", **kw):
    evs = normalizer.parse({"type": "file", "path": path, "line": line, **kw}, host=host)
    assert evs, f"no event for {line!r}"
    return evs[0]


@pytest.fixture(scope="session")
def engine():
    """Detection engine loaded with the bundled Vigil + SigmaHQ rules (loaded once per run)."""
    from vigil.detection.engine import DetectionEngine
    e = DetectionEngine()
    e.report_ = e.load_dirs([ROOT / "server" / "rules"])
    return e


@pytest.fixture(scope="session")
def engine_report(engine):
    return engine.report_


ADMIN_PW = "correct-horse-battery-staple"
ENROLL = "test-enrollment-token"


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    """A running Vigil app (no TLS, no syslog listener, no internet feeds) with an admin session."""
    from fastapi.testclient import TestClient

    from vigil.config import Settings
    from vigil.main import create_app

    s = Settings(data_dir=tmp_path_factory.mktemp("vigil"), rules_dirs=[ROOT / "server" / "rules"], tls=False,
                 admin_password=ADMIN_PW, enrollment_token=ENROLL, syslog_enabled=False, threatintel_enabled=False)
    app = create_app(s)
    with TestClient(app) as c:
        c.headers["X-Vigil-Request"] = "1"
        r = c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert r.status_code == 200, r.text
        c.vigil = app.state.vigil
        yield c


def wait_for(fn, timeout=10.0):
    import time
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    raise AssertionError("condition not met in time")
