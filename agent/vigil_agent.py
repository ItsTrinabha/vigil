#!/usr/bin/env python3
"""Vigil agent: collects security logs on a host and ships them to a Vigil server.

Single file, Python 3.8+ standard library only, so it runs on any Linux box
(and Windows for Event Log collection) without installing packages.

Inputs
  files      tail log files (glob patterns) with rotation and truncation handling
  journald   follow the systemd journal (`journalctl -f -o json`) with a cursor
  processes  poll /proc for new processes (process_creation events, no auditd needed)
  wineventlog  poll Windows Event Log channels via wevtutil (Windows only)

Delivery
  batches are gzip-compressed JSON over HTTPS with a per-agent bearer token;
  when the server is unreachable they are spooled to disk and replayed in
  order, so nothing is lost across restarts or outages (at-least-once).
"""
from __future__ import annotations

import argparse
import configparser
import glob
import gzip
import json
import logging
import os
import platform
import queue
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"
log = logging.getLogger("vigil-agent")

DEFAULT_FILES = [
    "/var/log/auth.log", "/var/log/secure", "/var/log/syslog:syslog", "/var/log/messages:syslog",
    "/var/log/ufw.log", "/var/log/kern.log:syslog",
    "/var/log/audit/audit.log:auditd",
    "/var/log/nginx/access.log:web", "/var/log/nginx/*access*.log:web",
    "/var/log/apache2/access.log:web", "/var/log/apache2/*access*.log:web", "/var/log/httpd/access_log:web",
]
DEFAULT_WIN_CHANNELS = ["Security", "System", "Microsoft-Windows-Sysmon/Operational",
                        "Microsoft-Windows-PowerShell/Operational"]


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
class Config:
    def __init__(self, path: str | None):
        cp = configparser.ConfigParser()
        if path and os.path.exists(path):
            cp.read(path)
        g = lambda sec, key, env, default="": os.environ.get(env) or cp.get(sec, key, fallback=default)  # noqa: E731
        self.server = g("server", "url", "VIGIL_SERVER").rstrip("/")
        self.enroll_token = g("server", "enroll_token", "VIGIL_ENROLL_TOKEN")
        self.ca_file = g("server", "ca_file", "VIGIL_CA_FILE")
        self.insecure = g("server", "insecure", "VIGIL_INSECURE", "false").lower() in ("1", "true", "yes")
        default_state = (r"C:\ProgramData\VigilAgent" if os.name == "nt" else "/var/lib/vigil-agent")
        self.state_dir = Path(g("agent", "state_dir", "VIGIL_STATE_DIR", default_state))
        self.hostname = g("agent", "hostname", "VIGIL_HOSTNAME") or socket.gethostname()
        self.batch_size = int(g("agent", "batch_size", "VIGIL_BATCH_SIZE", "500"))
        self.flush_interval = float(g("agent", "flush_interval", "VIGIL_FLUSH_INTERVAL", "2"))
        self.spool_max_mb = int(g("agent", "spool_max_mb", "VIGIL_SPOOL_MAX_MB", "200"))
        self.start_at = g("agent", "start_at", "VIGIL_START_AT", "end")
        files = g("inputs", "files", "VIGIL_FILES")
        self.files = [f.strip() for f in files.split(",") if f.strip()] if files else (DEFAULT_FILES if os.name != "nt" else [])
        self.journald = g("inputs", "journald", "VIGIL_JOURNALD", "auto").lower()
        self.processes = g("inputs", "processes", "VIGIL_PROCESSES", "true").lower() in ("1", "true", "yes")
        chans = g("inputs", "windows_eventlog", "VIGIL_WIN_CHANNELS")
        self.win_channels = [c.strip() for c in chans.split(",") if c.strip()] if chans else DEFAULT_WIN_CHANNELS


# --------------------------------------------------------------------------
# shipping
# --------------------------------------------------------------------------
class Shipper:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.q: queue.Queue = queue.Queue(maxsize=50000)
        self.spool = cfg.state_dir / "spool"
        self.spool.mkdir(parents=True, exist_ok=True)
        self.token: str | None = None
        self.agent_id: str | None = None
        self.sent = 0
        self.failures = 0
        self.last_error: str | None = None
        self._ctx = self._ssl_context()
        self._stop = threading.Event()
        self.inputs: dict[str, object] = {}  # input name -> object with ack(dict)

    def _ssl_context(self):
        if not self.cfg.server.startswith("https"):
            return None
        if self.cfg.insecure:
            log.warning("TLS certificate verification is DISABLED (insecure=true)")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        ctx = ssl.create_default_context(cafile=self.cfg.ca_file or None)
        if self.cfg.ca_file:
            ctx.check_hostname = False  # pinned CA (self-signed server cert); the chain is still verified
        return ctx

    def _request(self, path: str, body: bytes, headers: dict, timeout: int = 30) -> dict:
        req = urllib.request.Request(self.cfg.server + path, data=body, method="POST", headers={
            "User-Agent": f"vigil-agent/{VERSION}", **headers})
        with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as r:
            return json.loads(r.read() or b"{}")

    # ------------------------------------------------------------ enrollment
    def enroll(self) -> None:
        cred = self.cfg.state_dir / "agent.json"
        if cred.exists():
            d = json.loads(cred.read_text())
            self.token, self.agent_id = d["token"], d["agent_id"]
            return
        if not self.cfg.enroll_token:
            raise SystemExit("no enrollment token configured (VIGIL_ENROLL_TOKEN / [server] enroll_token)")
        delay = 2
        while not self._stop.is_set():
            try:
                body = json.dumps({"enrollment_token": self.cfg.enroll_token, "hostname": self.cfg.hostname,
                                   "os": f"{platform.system()} {platform.release()}", "version": VERSION}).encode()
                d = self._request("/api/v1/agents/enroll", body, {"Content-Type": "application/json"})
                cred.write_text(json.dumps(d))
                try:
                    cred.chmod(0o600)
                except OSError:
                    pass
                self.token, self.agent_id = d["token"], d["agent_id"]
                log.info("enrolled as %s", self.agent_id)
                return
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    raise SystemExit("enrollment rejected: wrong enrollment token") from None
                log.warning("enrollment failed (%s), retrying in %ss", exc, delay)
            except Exception as exc:
                log.warning("server unreachable for enrollment (%s), retrying in %ss", exc, delay)
            self._stop.wait(delay)
            delay = min(delay * 2, 60)

    # --------------------------------------------------------------- sending
    def put(self, record: dict) -> None:
        while not self._stop.is_set():
            try:
                self.q.put(record, timeout=1)
                return
            except queue.Full:
                continue  # back-pressure: inputs block instead of dropping

    def _post_batch(self, payload: bytes) -> None:
        self._request("/api/v1/ingest", payload, {"Content-Type": "application/json", "Content-Encoding": "gzip",
                                                  "Authorization": f"Bearer {self.token}"})

    def _encode(self, records: list[dict]) -> tuple[bytes, dict]:
        """Strip the per-record checkpoint markers and return them grouped by input."""
        acks: dict[str, dict] = {}
        for r in records:
            a = r.pop("_ack", None)
            if a:
                acks.setdefault(a[0], {})[a[1]] = a[2]
        return gzip.compress(json.dumps({"host": self.cfg.hostname, "tz_offset": time.localtime().tm_gmtoff,
                                         "agent_version": VERSION, "records": records}).encode()), acks

    def _spool_write(self, payload: bytes) -> None:
        total = sum(p.stat().st_size for p in self.spool.glob("*.gz"))
        if total > self.cfg.spool_max_mb * 1024 * 1024:
            oldest = sorted(self.spool.glob("*.gz"))[0]
            log.error("spool full, dropping oldest batch %s", oldest.name)
            oldest.unlink()
        name = self.spool / f"{time.time_ns()}.json.gz"
        tmp = name.with_suffix(".tmp")
        tmp.write_bytes(payload)
        tmp.rename(name)

    def _drain_spool(self) -> bool:
        for p in sorted(self.spool.glob("*.json.gz")):
            try:
                self._post_batch(p.read_bytes())
            except urllib.error.HTTPError as exc:
                if exc.code in (400, 413):
                    log.error("server rejected spooled batch %s (%s); discarding", p.name, exc.code)
                    p.unlink()
                    continue
                return False
            except Exception:
                return False
            p.unlink()
        return True

    def run(self) -> None:
        buf: list[dict] = []
        last_flush = time.time()
        backoff = 1.0
        while not self._stop.is_set() or not self.q.empty():
            try:
                buf.append(self.q.get(timeout=0.5))
            except queue.Empty:
                pass
            if buf and (len(buf) >= self.cfg.batch_size or time.time() - last_flush >= self.cfg.flush_interval
                        or self._stop.is_set()):
                payload, acks = self._encode(buf)
                n = len(buf)
                buf = []
                last_flush = time.time()
                ok = self._drain_spool()
                if ok:
                    try:
                        self._post_batch(payload)
                        self.sent += n
                        backoff = 1.0
                        self.last_error = None
                    except urllib.error.HTTPError as exc:
                        ok = False
                        self.last_error = f"HTTP {exc.code}"
                        if exc.code == 401:
                            log.error("agent token rejected (revoked?). Delete %s/agent.json to re-enroll.", self.cfg.state_dir)
                    except Exception as exc:
                        ok = False
                        self.last_error = str(exc)
                if not ok:
                    self.failures += 1
                    self._spool_write(payload)
                    log.warning("server unavailable (%s); spooled %d records", self.last_error or "backlog", n)
                    self._stop.wait(min(backoff, 30))
                    backoff = min(backoff * 2, 30)
                # The batch is durable (sent or spooled): advance each input's checkpoint.
                for name, positions in acks.items():
                    inp = self.inputs.get(name)
                    if inp is not None:
                        inp.ack(positions)

    def heartbeat(self, inputs_status) -> None:
        while not self._stop.wait(30):
            try:
                body = json.dumps({"version": VERSION, "os": f"{platform.system()} {platform.release()}",
                                   "inputs": inputs_status(), "sent": self.sent, "spooled": len(list(self.spool.glob('*.gz')))}).encode()
                self._request("/api/v1/heartbeat", body, {"Content-Type": "application/json",
                                                          "Authorization": f"Bearer {self.token}"}, timeout=10)
            except Exception as exc:
                log.debug("heartbeat failed: %s", exc)

    def stop(self) -> None:
        self._stop.set()


# --------------------------------------------------------------------------
# inputs
# --------------------------------------------------------------------------
class FileTailer:
    """Tails files matching glob patterns, persisting (inode, offset) per path.

    Rotation (rename + new file) is detected by inode change: the remainder of
    the old file is read before switching. Truncation (copytruncate) resets
    the offset to 0.
    """

    def __init__(self, patterns: list[str], shipper: Shipper, state_dir: Path, start_at: str = "end"):
        self.specs = []
        for p in patterns:
            path, _, stype = p.partition(":") if not (len(p) > 1 and p[1] == ":") else (p, "", "")
            self.specs.append((path, stype or "auto"))
        self.shipper = shipper
        self.state_file = state_dir / "positions.json"
        self.positions: dict[str, dict] = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        self.open: dict[str, tuple] = {}  # path -> (fh, inode, sourcetype)
        self.start_at = start_at
        self.lock = threading.Lock()
        self.lines = 0

    def ack(self, positions: dict) -> None:
        with self.lock:
            self.positions.update(positions)
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.positions))
            tmp.replace(self.state_file)

    def status(self) -> list[dict]:
        return [{"type": "file", "path": path, "sourcetype": st, "active": True} for path, (_, _, st) in self.open.items()]

    def _discover(self):
        for pattern, stype in self.specs:
            for path in glob.glob(pattern):
                if os.path.isfile(path) and path not in self.open:
                    yield path, stype

    def _open(self, path: str, stype: str, initial: bool) -> None:
        try:
            fh = open(path, "rb")
        except OSError as exc:
            log.debug("cannot open %s: %s", path, exc)
            return
        st = os.fstat(fh.fileno())
        saved = self.positions.get(path)
        if saved and saved.get("inode") == st.st_ino and saved.get("offset", 0) <= st.st_size:
            fh.seek(saved["offset"])
        elif initial and self.start_at == "end" and not saved:
            fh.seek(0, os.SEEK_END)
        self.open[path] = (fh, st.st_ino, stype)
        log.info("tailing %s (%s) from offset %d", path, stype, fh.tell())

    def _read(self, path: str) -> int:
        fh, inode, stype = self.open[path]
        n = 0
        while True:
            line = fh.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                fh.seek(-len(line), os.SEEK_CUR)  # partial line: wait for the rest
                break
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if text:
                self.shipper.put({"type": "file", "path": path, "sourcetype": stype, "line": text, "ts": time.time(),
                                  "_ack": ("files", path, {"inode": inode, "offset": fh.tell()})})
                n += 1
        return n

    def run(self, stop: threading.Event) -> None:
        initial = True
        last_discover = 0.0
        while not stop.is_set():
            if time.time() - last_discover > 10 or initial:
                for path, stype in list(self._discover()):
                    self._open(path, stype, initial)
                initial = False
                last_discover = time.time()
            for path in list(self.open):
                fh, inode, stype = self.open[path]
                self.lines += self._read(path)
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    continue  # rotated away, new file not created yet
                if st.st_ino != inode:  # rotated: old fd fully read above, switch to the new file
                    fh.close()
                    del self.open[path]
                    self.positions.pop(path, None)
                    self._open(path, stype, False)
                elif st.st_size < fh.tell():  # truncated
                    log.info("%s truncated, reading from start", path)
                    fh.seek(0)
            stop.wait(0.5)


class JournaldReader:
    def __init__(self, shipper: Shipper, state_dir: Path):
        self.shipper = shipper
        self.cursor_file = state_dir / "journald.cursor"
        self.cursor: str | None = self.cursor_file.read_text().strip() if self.cursor_file.exists() else None
        self.lines = 0

    def ack(self, positions: dict) -> None:
        if positions.get("cursor"):
            self.cursor_file.write_text(positions["cursor"])

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            cmd = ["journalctl", "-f", "-o", "json", "--no-pager"]
            cmd += [f"--after-cursor={self.cursor}"] if self.cursor else ["--since", "now"]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            except OSError as exc:
                log.error("journald input failed: %s", exc)
                return
            log.info("following systemd journal")
            for raw in proc.stdout:  # type: ignore[union-attr]
                if stop.is_set():
                    break
                try:
                    entry = json.loads(raw)
                except ValueError:
                    continue
                keep = {k: v for k, v in entry.items() if k in (
                    "MESSAGE", "SYSLOG_IDENTIFIER", "_COMM", "_PID", "SYSLOG_PID", "_HOSTNAME", "__REALTIME_TIMESTAMP",
                    "PRIORITY", "_SYSTEMD_UNIT", "_TRANSPORT", "_AUDIT_TYPE_NAME", "_AUDIT_ID", "_UID")}
                self.cursor = entry.get("__CURSOR", self.cursor)
                self.shipper.put({"type": "journald", "entry": keep, "ts": time.time(),
                                  "_ack": ("journald", "cursor", self.cursor)})
                self.lines += 1
            proc.terminate()
            stop.wait(5)


class ProcessMonitor:
    """Polls /proc for new processes. Short-lived processes (<interval) can be
    missed; enable auditd execve logging for complete coverage."""

    def __init__(self, shipper: Shipper, interval: float = 1.0):
        self.shipper = shipper
        self.interval = interval
        self.seen: dict[int, float] = {}
        self.me = os.getpid()
        self.events = 0
        try:
            self.clk = os.sysconf("SC_CLK_TCK")
            with open("/proc/stat") as f:
                self.btime = next(int(l.split()[1]) for l in f if l.startswith("btime"))  # noqa: E741
        except Exception:
            self.clk, self.btime = 100, 0
        import pwd
        self._pwd = pwd

    def _info(self, pid: int) -> dict | None:
        base = f"/proc/{pid}"
        try:
            with open(f"{base}/stat", "rb") as f:
                stat = f.read().decode(errors="replace")
            rp = stat.rfind(")")
            fields = stat[rp + 2:].split()
            ppid, start_ticks = int(fields[1]), int(fields[19])
            with open(f"{base}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
            if not cmd:
                return None  # kernel thread
            uid = None
            with open(f"{base}/status") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        break
            try:
                exe = os.readlink(f"{base}/exe")
            except OSError:
                exe = cmd.split(" ", 1)[0]
            try:
                cwd = os.readlink(f"{base}/cwd")
            except OSError:
                cwd = None
            name = stat[stat.find("(") + 1:rp]
        except (OSError, ValueError, IndexError):
            return None
        try:
            user = self._pwd.getpwuid(uid).pw_name if uid is not None else None
        except KeyError:
            user = str(uid)
        return {"pid": pid, "ppid": ppid, "exe": exe.replace(" (deleted)", ""), "cmdline": cmd[:4096], "uid": uid,
                "user": user, "cwd": cwd, "name": name, "start_ts": self.btime + start_ticks / self.clk}

    def run(self, stop: threading.Event) -> None:
        first = True
        while not stop.is_set():
            current = {}
            for d in os.listdir("/proc"):
                if d.isdigit():
                    pid = int(d)
                    current[pid] = self.seen.get(pid)
            new = [p for p in current if p not in self.seen and p != self.me]
            infos = {}
            for pid in new:
                info = self._info(pid)
                if info:
                    infos[pid] = info
                    current[pid] = info["start_ts"]
            if not first:
                for info in infos.values():
                    parent = infos.get(info["ppid"]) or self._info(info["ppid"])
                    if parent:
                        info.update({"parent_exe": parent["exe"], "parent_cmdline": parent["cmdline"],
                                     "parent_name": parent["name"]})
                    self.shipper.put({"type": "process", "data": info, "ts": time.time()})
                    self.events += 1
            self.seen = {p: v for p, v in current.items()}
            first = False
            stop.wait(self.interval)


class WinEventLogReader:
    def __init__(self, channels: list[str], shipper: Shipper, state_dir: Path):
        self.channels = channels
        self.shipper = shipper
        self.state_file = state_dir / "wineventlog.json"
        self.last: dict[str, int] = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        self.saved = dict(self.last)
        self.events = 0

    def ack(self, positions: dict) -> None:
        self.saved.update(positions)
        self.state_file.write_text(json.dumps(self.saved))

    @staticmethod
    def _query(channel: str, query: str, count: int, reverse: bool) -> str:
        cmd = ["wevtutil", "qe", channel, f"/q:{query}", "/f:xml", f"/c:{count}", f"/rd:{'true' if reverse else 'false'}"]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout

    def run(self, stop: threading.Event) -> None:
        import re
        rid = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
        for ch in self.channels:
            if ch not in self.last:
                out = self._query(ch, "*", 1, True)
                m = rid.search(out)
                self.last[ch] = int(m.group(1)) if m else 0
        while not stop.is_set():
            for ch in self.channels:
                try:
                    out = self._query(ch, f"*[System[EventRecordID>{self.last.get(ch, 0)}]]", 500, False)
                except Exception as exc:
                    log.debug("wevtutil %s failed: %s", ch, exc)
                    continue
                for xml in re.findall(r"<Event .*?</Event>", out, re.S):
                    m = rid.search(xml)
                    if m:
                        self.last[ch] = max(self.last.get(ch, 0), int(m.group(1)))
                    self.shipper.put({"type": "wineventlog", "channel": ch, "xml": xml, "ts": time.time(),
                                      "_ack": ("wineventlog", ch, self.last.get(ch, 0))})
                    self.events += 1
            stop.wait(2)


# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Vigil SIEM log collection agent")
    ap.add_argument("-c", "--config", default=os.environ.get("VIGIL_AGENT_CONFIG", "/etc/vigil/agent.ini"))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    cfg = Config(args.config)
    if not cfg.server:
        print("no server configured (VIGIL_SERVER or [server] url)", file=sys.stderr)
        return 2
    cfg.state_dir.mkdir(parents=True, exist_ok=True)

    shipper = Shipper(cfg)
    stop = threading.Event()

    def _sig(*_):
        log.info("stopping")
        stop.set()
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    shipper.enroll()
    inputs = []
    threads = []
    if os.name == "nt":
        w = WinEventLogReader(cfg.win_channels, shipper, cfg.state_dir)
        inputs.append(w)
        shipper.inputs["wineventlog"] = w
        threads.append(threading.Thread(target=w.run, args=(stop,), name="wineventlog", daemon=True))
    else:
        tail = FileTailer(cfg.files, shipper, cfg.state_dir, cfg.start_at)
        inputs.append(tail)
        shipper.inputs["files"] = tail
        threads.append(threading.Thread(target=tail.run, args=(stop,), name="files", daemon=True))
        auth_file = any(os.path.exists(p) for p in ("/var/log/auth.log", "/var/log/secure"))
        use_journal = cfg.journald == "true" or (cfg.journald == "auto" and not auth_file and
                                                 subprocess.run(["which", "journalctl"], capture_output=True).returncode == 0)
        if use_journal:
            j = JournaldReader(shipper, cfg.state_dir)
            inputs.append(j)
            shipper.inputs["journald"] = j
            threads.append(threading.Thread(target=j.run, args=(stop,), name="journald", daemon=True))
        if cfg.processes and os.path.isdir("/proc"):
            pm = ProcessMonitor(shipper)
            inputs.append(pm)
            threads.append(threading.Thread(target=pm.run, args=(stop,), name="processes", daemon=True))

    def status():
        out = []
        for i in inputs:
            if isinstance(i, FileTailer):
                out.extend(i.status())
            elif isinstance(i, JournaldReader):
                out.append({"type": "journald", "active": True, "lines": i.lines})
            elif isinstance(i, ProcessMonitor):
                out.append({"type": "processes", "active": True, "events": i.events})
            elif isinstance(i, WinEventLogReader):
                out.append({"type": "wineventlog", "channels": i.channels, "events": i.events})
        return out

    ship_thread = threading.Thread(target=shipper.run, name="shipper", daemon=True)
    ship_thread.start()
    threading.Thread(target=shipper.heartbeat, args=(status,), name="heartbeat", daemon=True).start()
    for t in threads:
        t.start()
    log.info("vigil-agent %s running on %s -> %s", VERSION, cfg.hostname, cfg.server)
    while not stop.wait(1):
        pass
    shipper.stop()
    ship_thread.join(timeout=15)
    return 0


if __name__ == "__main__":
    sys.exit(main())
