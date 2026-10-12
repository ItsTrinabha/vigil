import gzip
import json
import os
import threading
import urllib.error

import vigil_agent as va


class FakeShipper:
    def __init__(self):
        self.records = []

    def put(self, rec):
        self.records.append(rec)


def lines(shipper):
    return [r["line"] for r in shipper.records]


def make_tailer(tmp_path, log, start_at="beginning"):
    sh = FakeShipper()
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    t = va.FileTailer([f"{log}:auth"], sh, state, start_at=start_at)
    for path, stype in t._discover():
        t._open(path, stype, True)
    return t, sh


def test_tailer_reads_complete_lines_only(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("one\ntwo\npart")
    t, sh = make_tailer(tmp_path, log)
    t._read(str(log))
    assert lines(sh) == ["one", "two"]
    with log.open("a") as f:
        f.write("ial\n")
    t._read(str(log))
    assert lines(sh) == ["one", "two", "partial"]
    assert sh.records[0]["sourcetype"] == "auth"


def test_tailer_start_at_end_skips_history(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old\n")
    t, sh = make_tailer(tmp_path, log, start_at="end")
    with log.open("a") as f:
        f.write("new\n")
    t._read(str(log))
    assert lines(sh) == ["new"]


def test_checkpoint_only_advances_on_ack(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("a\nb\n")
    t, sh = make_tailer(tmp_path, log)
    t._read(str(log))
    # Nothing acknowledged yet: a restarted agent re-reads everything.
    t2, sh2 = make_tailer(tmp_path, log)
    t2._read(str(log))
    assert lines(sh2) == ["a", "b"]
    # Acknowledge the first record only.
    _kind, path, pos = sh.records[0]["_ack"]
    t.ack({path: pos})
    t3, sh3 = make_tailer(tmp_path, log)
    t3._read(str(log))
    assert lines(sh3) == ["b"]


def test_rotation_reads_old_tail_then_new_file(tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("1\n")
    t, sh = make_tailer(tmp_path, log)
    t._read(str(log))
    with log.open("a") as f:
        f.write("2\n")
    os.rename(log, tmp_path / "auth.log.1")
    log.write_text("3\n")
    stop = threading.Event()
    calls = {"n": 0}

    def wait(_):
        calls["n"] += 1
        if calls["n"] >= 2:
            stop.set()
    monkeypatch.setattr(stop, "wait", wait)
    t.run(stop)
    assert lines(sh) == ["1", "2", "3"]


def test_truncation_restarts_from_zero(tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("aaaa\nbbbb\n")
    t, sh = make_tailer(tmp_path, log)
    t._read(str(log))
    log.write_text("c\n")  # copytruncate-style: same inode, smaller size
    stop = threading.Event()
    calls = {"n": 0}

    def wait(_):
        calls["n"] += 1
        if calls["n"] >= 2:
            stop.set()
    monkeypatch.setattr(stop, "wait", wait)
    t.run(stop)
    assert lines(sh)[-1] == "c"


class _Cfg:
    def __init__(self, tmp_path):
        self.server = "http://127.0.0.1:9"
        self.state_dir = tmp_path
        self.insecure = False
        self.ca_file = ""
        self.hostname = "h"
        self.batch_size = 2
        self.flush_interval = 0
        self.spool_max_mb = 1
        self.enroll_token = "x"


def test_shipper_spools_when_server_down_and_drains_later(tmp_path):
    sh = va.Shipper(_Cfg(tmp_path))
    acked = {}

    class Input:
        def ack(self, positions):
            acked.update(positions)
    sh.inputs["files"] = Input()
    sent = []
    up = {"v": False}

    def post(payload):
        if not up["v"]:
            raise urllib.error.URLError("down")
        sent.append(json.loads(gzip.decompress(payload)))
    sh._post_batch = post
    sh._stop.wait = lambda *_: False
    sh.put({"type": "file", "line": "x", "_ack": ("files", "/var/log/auth.log", {"inode": 1, "offset": 2})})
    sh.put({"type": "file", "line": "y", "_ack": ("files", "/var/log/auth.log", {"inode": 1, "offset": 4})})
    sh._stop.set()
    sh.run()
    spooled = list((tmp_path / "spool").glob("*.json.gz"))
    assert spooled and sent == []
    assert acked == {"/var/log/auth.log": {"inode": 1, "offset": 4}}  # durable on disk, so checkpoint advanced
    up["v"] = True
    assert sh._drain_spool()
    records = [r for batch in sent for r in batch["records"]]
    assert [r["line"] for r in records] == ["x", "y"] and all("_ack" not in r for r in records)
    assert not list((tmp_path / "spool").glob("*.json.gz"))
