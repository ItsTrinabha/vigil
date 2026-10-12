"""Parsers for Linux security-relevant syslog programs.

Each parser takes the syslog message body and returns normalised fields
(ECS-style dotted names) or None when the line carries nothing beyond the
raw message. The raw message is always kept for Sigma keyword rules.
"""
from __future__ import annotations

import re
from collections.abc import Callable

Fields = dict[str, object]

_IP = r"(?P<ip>[0-9a-fA-F:.]+)"

# ---------------------------------------------------------------- sshd -----
_SSH_PATTERNS: list[tuple[re.Pattern, Callable[[re.Match], Fields]]] = []


def _ssh(pattern: str):
    def deco(fn):
        _SSH_PATTERNS.append((re.compile(pattern), fn))
        return fn
    return deco


@_ssh(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from " + _IP +
      r" port (?P<port>\d+)")
def _ssh_failed(m):
    return {"event.category": "authentication", "event.action": "ssh_login_failed",
            "event.outcome": "failure", "user.name": m["user"], "source.ip": m["ip"],
            "source.port": int(m["port"]), "auth.method": m["method"],
            "user.invalid": bool(m["invalid"])}


@_ssh(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from " + _IP + r" port (?P<port>\d+)"
      r"(?: ssh2(?:: (?P<keytype>\S+) (?P<fp>\S+))?)?")
def _ssh_accepted(m):
    f = {"event.category": "authentication", "event.action": "ssh_login_success",
         "event.outcome": "success", "user.name": m["user"], "source.ip": m["ip"],
         "source.port": int(m["port"]), "auth.method": m["method"]}
    if m["fp"]:
        f["auth.key_fingerprint"] = m["fp"]
    return f


@_ssh(r"^Invalid user (?P<user>.*?) from " + _IP + r"(?: port (?P<port>\d+))?")
def _ssh_invalid(m):
    f = {"event.category": "authentication", "event.action": "ssh_invalid_user",
         "event.outcome": "failure", "user.name": m["user"], "source.ip": m["ip"], "user.invalid": True}
    if m["port"]:
        f["source.port"] = int(m["port"])
    return f


@_ssh(r"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
      r"(?P<user>\S+) from " + _IP + r" port (?P<port>\d+)")
def _ssh_maxauth(m):
    return {"event.category": "authentication", "event.action": "ssh_max_auth_exceeded",
            "event.outcome": "failure", "user.name": m["user"], "source.ip": m["ip"],
            "source.port": int(m["port"]), "user.invalid": bool(m["invalid"])}


@_ssh(r"^(?:Connection closed|Disconnected) by (?:(?P<kind>authenticating|invalid) user (?P<user>\S+) )?"
      + _IP + r" port (?P<port>\d+)(?P<preauth> \[preauth\])?")
def _ssh_closed(m):
    f = {"event.category": "network", "event.action": "ssh_connection_closed",
         "source.ip": m["ip"], "source.port": int(m["port"]), "ssh.preauth": bool(m["preauth"])}
    if m["user"]:
        f["user.name"] = m["user"]
    return f


@_ssh(r"^Disconnected from (?:(?P<kind>authenticating|invalid) )?user (?P<user>\S+) " + _IP +
      r" port (?P<port>\d+)")
def _ssh_disconnected_user(m):
    return {"event.category": "network", "event.action": "ssh_disconnected", "user.name": m["user"],
            "source.ip": m["ip"], "source.port": int(m["port"])}


@_ssh(r"^Received disconnect from " + _IP + r" port (?P<port>\d+)")
def _ssh_received_disconnect(m):
    return {"event.category": "network", "event.action": "ssh_disconnected",
            "source.ip": m["ip"], "source.port": int(m["port"])}


@_ssh(r"^Did not receive identification string from " + _IP)
def _ssh_noident(m):
    return {"event.category": "network", "event.action": "ssh_no_identification", "source.ip": m["ip"]}


@_ssh(r"^(?:banner exchange: Connection from |kex_exchange_identification: .*?|Bad protocol version identification .*? from )"
      + _IP)
def _ssh_banner(m):
    return {"event.category": "network", "event.action": "ssh_protocol_error", "source.ip": m["ip"]}


@_ssh(r"^Connection from " + _IP + r" port (?P<port>\d+) on (?P<dst>\S+) port (?P<dport>\d+)")
def _ssh_conn(m):
    return {"event.category": "network", "event.action": "ssh_connection", "source.ip": m["ip"],
            "source.port": int(m["port"]), "destination.ip": m["dst"], "destination.port": int(m["dport"])}


# ------------------------------------------------------------ pam_unix -----
_PAM = re.compile(r"^pam_unix\((?P<svc>[\w-]+):(?P<type>\w+)\): (?P<rest>.*)$")
_KV = re.compile(r"(\w+)=(\S*)")


def parse_pam(msg: str) -> Fields | None:
    m = _PAM.match(msg)
    if not m:
        return None
    svc, typ, rest = m["svc"], m["type"], m["rest"]
    f: Fields = {"pam.service": svc, "pam.type": typ}
    if rest.startswith("authentication failure"):
        kv = dict(_KV.findall(rest))
        f.update({"event.category": "authentication", "event.action": f"{svc}_auth_failure",
                  "event.outcome": "failure"})
        if kv.get("user"):
            f["user.name"] = kv["user"]
        if kv.get("ruser"):
            f["user.effective_name"] = kv["ruser"]
        if kv.get("rhost"):
            f["source.ip"] = kv["rhost"]
        return f
    so = re.match(r"session (opened|closed) for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?"
                  r"(?: by (?P<by>[^\s(]*)(?:\(uid=(?P<byuid>\d+)\))?)?", rest)
    if so:
        f.update({"event.category": "session", "event.action": f"{svc}_session_{so.group(1)}",
                  "event.outcome": "success", "user.name": so["user"]})
        if so["uid"]:
            f["user.id"] = int(so["uid"])
        if so["by"]:
            f["user.effective_name"] = so["by"]
        return f
    pc = re.match(r"password changed for (?P<user>\S+)", rest)
    if pc:
        f.update({"event.category": "iam", "event.action": "password_changed",
                  "event.outcome": "success", "user.name": pc["user"]})
        return f
    return f


def parse_sshd(msg: str) -> Fields | None:
    for pat, fn in _SSH_PATTERNS:
        m = pat.match(msg)
        if m:
            return fn(m)
    pam = parse_pam(msg)
    if pam:
        if pam.get("event.action") == "sshd_auth_failure":
            pam["event.action"] = "ssh_pam_auth_failure"
        return pam
    m = re.match(r"^PAM (?P<n>\d+) more authentication failures?;.*rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?", msg)
    if m:
        f = {"event.category": "authentication", "event.action": "ssh_pam_auth_failure",
             "event.outcome": "failure", "source.ip": m["ip"], "auth.attempts": int(m["n"]) + 1}
        if m["user"]:
            f["user.name"] = m["user"]
        return f
    return None


# ---------------------------------------------------------------- sudo -----
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?P<body>.*)$")


def parse_sudo(msg: str) -> Fields | None:
    pam = parse_pam(msg)
    if pam:
        return pam
    m = _SUDO.match(msg)
    if not m:
        return None
    user, body = m["user"], m["body"]
    parts = [p.strip() for p in body.split(" ; ")]
    kv = {}
    reason = None
    for p in parts:
        k, sep, v = p.partition("=")
        if sep and k.isupper():
            kv[k] = v
        else:
            reason = p
    f: Fields = {"event.category": "process", "user.name": user,
                 "user.target.name": kv.get("USER", "root"), "process.working_directory": kv.get("PWD"),
                 "process.tty": kv.get("TTY"), "process.command_line": kv.get("COMMAND")}
    if kv.get("COMMAND"):
        f["process.executable"] = kv["COMMAND"].split(" ", 1)[0]
        f["process.name"] = f["process.executable"].rsplit("/", 1)[-1]
    if reason is None:
        f.update({"event.action": "sudo_command", "event.outcome": "success"})
    elif "NOT in sudoers" in reason or "not allowed to run" in reason:
        f.update({"event.action": "sudo_not_allowed", "event.outcome": "failure", "sudo.reason": reason})
    elif "incorrect password" in reason:
        n = re.match(r"(\d+)", reason)
        f.update({"event.action": "sudo_incorrect_password", "event.outcome": "failure",
                  "sudo.reason": reason, "auth.attempts": int(n.group(1)) if n else 1})
    else:
        f.update({"event.action": "sudo_other", "event.outcome": "unknown", "sudo.reason": reason})
    return {k: v for k, v in f.items() if v is not None}


# ------------------------------------------------------------------ su -----
def parse_su(msg: str) -> Fields | None:
    pam = parse_pam(msg)
    if pam:
        return pam
    m = re.match(r"^(?P<failed>FAILED SU|FAILED su )?\s*\(to (?P<target>[^)]+)\) (?P<user>\S+) on (?P<tty>\S+)", msg)
    if m:
        ok = not m["failed"]
        return {"event.category": "authentication", "event.action": "su_success" if ok else "su_failure",
                "event.outcome": "success" if ok else "failure", "user.name": m["user"],
                "user.target.name": m["target"], "process.tty": m["tty"]}
    return None


# ------------------------------------------------------ account mgmt -------
def parse_account(program: str, msg: str) -> Fields | None:
    m = re.match(r"^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), "
                 r"shell=(?P<shell>[^,\s]+)", msg)
    if m:
        return {"event.category": "iam", "event.action": "user_created", "event.outcome": "success",
                "user.target.name": m["name"], "user.target.id": int(m["uid"]),
                "group.id": int(m["gid"]), "user.target.home": m["home"], "user.target.shell": m["shell"]}
    m = re.match(r"^new group: name=(?P<name>[^,]+), GID=(?P<gid>\d+)", msg) or \
        re.match(r"^group added to /etc/group: name=(?P<name>[^,]+), GID=(?P<gid>\d+)", msg)
    if m:
        return {"event.category": "iam", "event.action": "group_created", "event.outcome": "success",
                "group.name": m["name"], "group.id": int(m["gid"])}
    m = re.match(r"^delete user '(?P<name>[^']+)'", msg)
    if m:
        return {"event.category": "iam", "event.action": "user_deleted", "event.outcome": "success",
                "user.target.name": m["name"]}
    m = re.match(r"^add '(?P<name>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'", msg) or \
        re.match(r"^user (?P<name>\S+) added by (?P<by>\S+) to group (?P<group>\S+)", msg)
    if m:
        return {"event.category": "iam", "event.action": "group_member_added", "event.outcome": "success",
                "user.target.name": m["name"], "group.name": m["group"]}
    m = re.match(r"^change user '(?P<name>[^']+)' (?P<what>\w+)", msg)
    if m:
        return {"event.category": "iam", "event.action": f"user_{m['what']}_changed",
                "event.outcome": "success", "user.target.name": m["name"]}
    pam = parse_pam(msg)
    if pam:
        return pam
    return None


# ---------------------------------------------------------------- cron -----
def parse_cron(msg: str) -> Fields | None:
    m = re.match(r"^\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)\s*$", msg)
    if m:
        cmd = m["cmd"].strip()
        return {"event.category": "process", "event.action": "cron_exec", "event.outcome": "success",
                "user.name": m["user"], "process.command_line": cmd,
                "process.executable": cmd.split(" ", 1)[0] if cmd else None}
    m = re.match(r"^\((?P<user>[^)]+)\) (?P<op>REPLACE|BEGIN EDIT|END EDIT|LIST|DELETE) \((?P<target>[^)]+)\)", msg)
    if m:
        return {"event.category": "configuration", "event.action": "crontab_modified" if m["op"] in ("REPLACE", "DELETE") else "crontab_access",
                "user.name": m["user"], "user.target.name": m["target"], "cron.operation": m["op"]}
    return parse_pam(msg)


# ------------------------------------------------------- kernel firewall ---
_NETFILTER_KV = re.compile(r"\b(IN|OUT|SRC|DST|PROTO|SPT|DPT|LEN|TTL|MAC)=(\S*)")


def parse_kernel(msg: str) -> Fields | None:
    if "SRC=" not in msg or "DST=" not in msg:
        return None
    kv = dict(_NETFILTER_KV.findall(msg))
    m = re.search(r"\[(UFW [A-Z ]+?)\]", msg)
    label = m.group(1) if m else None
    if label is None:
        pm = re.match(r"^(?:\[\s*\d+\.\d+\]\s*)?(?P<p>[^=]*?)\s*IN=", msg)
        label = pm.group("p").strip() if pm else ""
    action = "firewall_block" if any(w in (label or "").upper() for w in ("BLOCK", "DROP", "REJECT", "DENY")) else (
        "firewall_allow" if "ALLOW" in (label or "").upper() or "ACCEPT" in (label or "").upper() else "firewall_log")
    f: Fields = {"event.category": "network", "event.action": action,
                 "event.outcome": "failure" if action == "firewall_block" else "success",
                 "source.ip": kv.get("SRC"), "destination.ip": kv.get("DST"),
                 "network.transport": (kv.get("PROTO") or "").lower() or None,
                 "observer.ingress.interface": kv.get("IN") or None, "firewall.rule": label or None}
    if kv.get("SPT", "").isdigit():
        f["source.port"] = int(kv["SPT"])
    if kv.get("DPT", "").isdigit():
        f["destination.port"] = int(kv["DPT"])
    return {k: v for k, v in f.items() if v is not None}


def parse_logind(msg: str) -> Fields | None:
    m = re.match(r"^New session (?P<sid>\S+) of user (?P<user>[^.\s]+)\.?", msg)
    if m:
        return {"event.category": "session", "event.action": "session_started", "event.outcome": "success",
                "user.name": m["user"], "session.id": m["sid"]}
    return None


# Programs -> (parser, logsource services)
PROGRAMS: dict[str, tuple[Callable[[str], Fields | None], tuple[str, ...]]] = {
    "sshd": (parse_sshd, ("sshd", "auth")),
    "sshd-session": (parse_sshd, ("sshd", "auth")),
    "sudo": (parse_sudo, ("sudo", "auth")),
    "su": (parse_su, ("auth",)),
    "useradd": (lambda m: parse_account("useradd", m), ("auth",)),
    "userdel": (lambda m: parse_account("userdel", m), ("auth",)),
    "usermod": (lambda m: parse_account("usermod", m), ("auth",)),
    "groupadd": (lambda m: parse_account("groupadd", m), ("auth",)),
    "gpasswd": (lambda m: parse_account("gpasswd", m), ("auth",)),
    "passwd": (lambda m: parse_account("passwd", m), ("auth",)),
    "chpasswd": (lambda m: parse_account("chpasswd", m), ("auth",)),
    "CRON": (parse_cron, ("cron",)),
    "cron": (parse_cron, ("cron",)),
    "crontab": (parse_cron, ("cron",)),
    "kernel": (parse_kernel, ("syslog",)),
    "systemd-logind": (parse_logind, ("auth",)),
    "vsftpd": (lambda m: None, ("vsftpd",)),
    "clamd": (lambda m: None, ("clamav",)),
    "freshclam": (lambda m: None, ("clamav",)),
    "guacd": (lambda m: None, ("guacamole",)),
}


def parse_program(program: str | None, msg: str) -> tuple[Fields | None, tuple[str, ...]]:
    if not program:
        return None, ()
    entry = PROGRAMS.get(program)
    if entry is None:
        if program.startswith("sshd"):
            entry = PROGRAMS["sshd"]
        else:
            # Unknown program: still recognise netfilter-style lines and pam_unix lines.
            return (parse_kernel(msg) or parse_pam(msg)), ()
    parser, services = entry
    try:
        return parser(msg), services
    except Exception:  # a malformed line must never break ingestion
        return None, services
