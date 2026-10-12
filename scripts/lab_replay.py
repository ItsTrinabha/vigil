#!/usr/bin/env python3
"""Lab replay: append ordinary log lines to files a Vigil agent is tailing, so
the detections can be seen working on a machine that is not internet-facing.

Only standard log records are written (OpenSSH, sudo, useradd, cron, UFW,
nginx access log). Nothing is executed and no network traffic is sent.
All addresses come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), which belong to nobody.

    python3 scripts/lab_replay.py --dir lab/logs
    python3 scripts/lab_replay.py --dir lab/logs --only bruteforce
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "lab-web-01"
ADMINS = {"alice": "198.51.100.10", "bob": "198.51.100.20"}
SRC_GUESSING = "203.0.113.10"
SRC_COMPROMISE = "203.0.113.20"
SRC_WEB = "203.0.113.30"
SRC_PORTS = "203.0.113.40"
SRC_UNUSUAL = "192.0.2.50"


def bsd(ts: datetime) -> str:
    return ts.strftime("%b %e %H:%M:%S")


def clf(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


class Lab:
    def __init__(self, d: Path):
        d.mkdir(parents=True, exist_ok=True)
        self.auth, self.access, self.syslog = d / "auth.log", d / "access.log", d / "syslog"
        self.pid = 3000

    def write(self, path: Path, lines: list[str]) -> None:
        with path.open("a") as f:
            f.write("".join(line + "\n" for line in lines))

    def log(self, ts: datetime, prog: str, msg: str) -> str:
        self.pid += random.randint(1, 7)
        return f"{bsd(ts)} {HOST} {prog}[{self.pid}]: {msg}"


def baseline(lab: Lab, now: datetime) -> int:
    """14 days of routine admin logins (key-based, office hours) to train UEBA."""
    lines = []
    for day in range(14, 0, -1):
        for user, ip in ADMINS.items():
            for _ in range(2):
                ts = (now - timedelta(days=day)).replace(hour=random.choice([9, 10, 11, 14, 15, 16]),
                                                         minute=random.randint(0, 59), second=random.randint(0, 59))
                lines.append(lab.log(ts, "sshd", f"Accepted publickey for {user} from {ip} port {random.randint(40000, 60000)} ssh2: ED25519 SHA256:lab{user}key"))
    lab.write(lab.auth, lines)
    return len(lines)


def bruteforce(lab: Lab, now: datetime) -> int:
    users = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "git"]
    lines = []
    for i in range(30):
        u = users[i % len(users)]
        invalid = "" if u == "root" else "invalid user "
        lines.append(lab.log(now + timedelta(seconds=i * 3), "sshd",
                             f"Failed password for {invalid}{u} from {SRC_GUESSING} port {50000 + i} ssh2"))
    lab.write(lab.auth, lines)
    return len(lines)


def compromise(lab: Lab, now: datetime) -> int:
    t = now + timedelta(minutes=2)
    lines = [lab.log(t + timedelta(seconds=i * 2), "sshd", f"Failed password for deploy from {SRC_COMPROMISE} port {41000 + i} ssh2")
             for i in range(12)]
    t += timedelta(seconds=30)
    lines += [
        lab.log(t, "sshd", f"Accepted password for deploy from {SRC_COMPROMISE} port 41999 ssh2"),
        lab.log(t + timedelta(seconds=40), "sudo", "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"),
        lab.log(t + timedelta(seconds=70), "useradd", "new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/1"),
        lab.log(t + timedelta(seconds=95), "crontab", "(root) REPLACE (root)"),
    ]
    lab.write(lab.auth, lines)
    return len(lines)


def webscan(lab: Lab, now: datetime) -> int:
    t = now + timedelta(minutes=4)
    paths = [f"/{w}" for w in ("admin", "backup", "old", "test", "dev", "api/v1", "console", "phpmyadmin", "wp-admin",
                                 "cgi-bin", "server", "uploads", "private", "tmp", "logs", "config", "db", "staging",
                                 "portal", "manager", "login.php", "setup.php", "install", "debug", "status", "shell",
                                 "files", "data", "old-site", "beta", "secret", "internal", "assets/old")]
    ua = "gobuster/3.6"
    lines = [f'{SRC_WEB} - - [{clf(t + timedelta(seconds=i))}] "GET {p} HTTP/1.1" 404 162 "-" "{ua}"' for i, p in enumerate(paths)]
    t += timedelta(seconds=len(paths) + 5)
    lines += [
        f'{SRC_WEB} - - [{clf(t)}] "GET /.env HTTP/1.1" 200 412 "-" "{ua}"',
        f'{SRC_WEB} - - [{clf(t + timedelta(seconds=2))}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 0 "-" "Mozilla/5.0"',
        f'{SRC_WEB} - - [{clf(t + timedelta(seconds=4))}] "GET /products?id=1%27%20UNION%20SELECT%20NULL--%20 HTTP/1.1" 500 0 "-" "sqlmap/1.8"',
        f'198.51.100.77 - - [{clf(t + timedelta(seconds=6))}] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (X11; Linux x86_64)"',
    ]
    lab.write(lab.access, lines)
    return len(lines)


def portscan(lab: Lab, now: datetime) -> int:
    t = now + timedelta(minutes=6)
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432,
             5900, 6379, 8080, 8443, 9200, 27017]
    lines = [f"{bsd(t)} {HOST} kernel: [{1000 + i}.{i:03d}] [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 "
             f"SRC={SRC_PORTS} DST=198.51.100.5 LEN=44 TOS=0x00 PREC=0x00 TTL=50 ID={i} PROTO=TCP SPT=61000 DPT={p} "
             f"WINDOW=1024 RES=0x00 SYN URGP=0" for i, p in enumerate(ports)]
    lab.write(lab.syslog, lines)
    return len(lines)


def anomaly(lab: Lab, now: datetime) -> int:
    """alice logs in at 03:00 from a network she never used, with a password instead of her key."""
    ts = now.replace(hour=3, minute=7, second=12)
    if ts > now:  # the most recent 03:07 that is not in the future
        ts -= timedelta(days=1)
    lab.write(lab.auth, [lab.log(ts, "sshd", f"Accepted password for alice from {SRC_UNUSUAL} port 52211 ssh2")])
    return 1


SCENARIOS = {"baseline": baseline, "bruteforce": bruteforce, "compromise": compromise, "webscan": webscan,
             "portscan": portscan, "anomaly": anomaly}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default="lab/logs")
    ap.add_argument("--only", choices=list(SCENARIOS), action="append")
    args = ap.parse_args()
    lab = Lab(Path(args.dir))
    # Scenarios are laid out over the 10 minutes leading up to now.
    now = datetime.now().replace(microsecond=0) - timedelta(minutes=10)
    for name in args.only or list(SCENARIOS):
        n = SCENARIOS[name](lab, now)
        print(f"{name:<11} {n:>4} lines")


if __name__ == "__main__":
    main()
