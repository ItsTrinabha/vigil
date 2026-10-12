import time

from conftest import FIXTURES, parse_one
from vigil.parsers.syslog import parse_syslog


def test_bsd_header():
    h = parse_syslog("Oct 11 22:14:15 web01 sshd[1234]: hello world", now=time.mktime((2026, 10, 12, 0, 0, 0, 0, 0, -1)))
    assert (h.host, h.program, h.pid, h.message) == ("web01", "sshd", 1234, "hello world")


def test_bsd_year_rollover():
    # A December line read on 1 January belongs to the previous year.
    now = 1798761600.0  # 2027-01-01T00:00:00Z
    h = parse_syslog("Dec 31 23:59:00 h cron[1]: x", now=now)
    assert now - h.ts < 120


def test_iso_header():
    h = parse_syslog("2026-10-11T22:14:16.123456+02:00 web01 sudo: msg")
    assert h.program == "sudo" and abs(h.ts - 1791749656.123456) < 1e-3


def test_rfc5424_with_structured_data():
    h = parse_syslog('<165>1 2026-10-11T22:14:04.003Z fw01 firewall 77 ID47 [meta seq="1" zone="wan"] blocked')
    assert h.facility == "local4" and h.severity == 5
    assert h.host == "fw01" and h.program == "firewall" and h.pid == 77
    assert h.structured == {"meta": {"seq": "1", "zone": "wan"}} and h.message == "blocked"


def test_ssh_failed_invalid_user(normalizer):
    ev = parse_one(normalizer, "Oct 11 22:14:15 web01 sshd[12]: Failed password for invalid user admin from 203.0.113.5 port 50122 ssh2")
    assert ev["event.action"] == "ssh_login_failed"
    assert ev["user.name"] == "admin" and ev["user.invalid"] is True
    assert ev["source.ip"] == "203.0.113.5" and ev["source.port"] == 50122
    assert ev["log.product"] == "linux" and "sshd" in ev["log.services"]


def test_ssh_accepted_publickey(normalizer):
    ev = parse_one(normalizer, "Oct 11 22:14:15 web01 sshd[12]: Accepted publickey for deploy from 2001:db8::7 port 51514 ssh2: ED25519 SHA256:abc")
    assert ev["event.action"] == "ssh_login_success" and ev["event.outcome"] == "success"
    assert ev["source.ip"] == "2001:db8::7" and ev["auth.method"] == "publickey"
    assert ev["auth.key_fingerprint"] == "SHA256:abc"


def test_ssh_other_messages(normalizer):
    cases = {
        "Invalid user oracle from 198.51.100.4 port 4444": "ssh_invalid_user",
        "Connection closed by authenticating user root 198.51.100.4 port 22 [preauth]": "ssh_connection_closed",
        "Received disconnect from 198.51.100.4 port 22:11: Bye Bye [preauth]": "ssh_disconnected",
        "error: maximum authentication attempts exceeded for root from 198.51.100.4 port 1 ssh2 [preauth]": "ssh_max_auth_exceeded",
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.4  user=root": "ssh_pam_auth_failure",
        "pam_unix(sshd:session): session opened for user deploy(uid=1000) by (uid=0)": "sshd_session_opened",
    }
    for msg, action in cases.items():
        ev = parse_one(normalizer, f"Oct 11 22:14:15 web01 sshd[12]: {msg}")
        assert ev["event.action"] == action, msg


def test_sudo_variants(normalizer):
    ev = parse_one(normalizer, "Oct 11 22:15:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    assert ev["event.action"] == "sudo_command" and ev["user.name"] == "deploy" and ev["user.target.name"] == "root"
    assert ev["process.command_line"] == "/usr/bin/cat /etc/shadow" and ev["process.executable"] == "/usr/bin/cat"
    ev = parse_one(normalizer, "Oct 11 22:15:00 web01 sudo:   bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")
    assert ev["event.action"] == "sudo_not_allowed" and ev["event.outcome"] == "failure"
    ev = parse_one(normalizer, "Oct 11 22:15:00 web01 sudo:   bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls")
    assert ev["event.action"] == "sudo_incorrect_password" and ev["auth.attempts"] == 3
    ev = parse_one(normalizer, "Oct 11 22:15:00 web01 sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob")
    assert ev["event.action"] == "sudo_auth_failure" and ev["user.name"] == "bob"


def test_account_management(normalizer):
    ev = parse_one(normalizer, "Oct 11 22:16:00 web01 useradd[99]: new user: name=svc, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0")
    assert ev["event.action"] == "user_created" and ev["user.target.id"] == 0 and ev["user.target.name"] == "svc"
    ev = parse_one(normalizer, "Oct 11 22:16:00 web01 usermod[99]: add 'bob' to group 'sudo'")
    assert ev["event.action"] == "group_member_added" and ev["group.name"] == "sudo"
    ev = parse_one(normalizer, "Oct 11 22:16:00 web01 gpasswd[99]: user bob added by root to group docker")
    assert ev["group.name"] == "docker" and ev["user.target.name"] == "bob"
    ev = parse_one(normalizer, "Oct 11 22:16:00 web01 su[9]: FAILED SU (to root) bob on pts/1")
    assert ev["event.action"] == "su_failure" and ev["user.target.name"] == "root"


def test_cron(normalizer):
    ev = parse_one(normalizer, "Oct 11 22:16:00 web01 CRON[5]: (root) CMD (/usr/local/bin/backup.sh --full)")
    assert ev["event.action"] == "cron_exec" and ev["process.executable"] == "/usr/local/bin/backup.sh"
    ev = parse_one(normalizer, "Oct 11 22:16:00 web01 crontab[5]: (root) REPLACE (root)")
    assert ev["event.action"] == "crontab_modified"


def test_ufw_block(normalizer):
    ev = parse_one(normalizer, "Oct 11 22:16:00 web01 kernel: [12.3] [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=192.0.2.9 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=40000 DPT=3389 WINDOW=1024")
    assert ev["event.action"] == "firewall_block" and ev["destination.port"] == 3389
    assert ev["source.ip"] == "192.0.2.9" and ev["network.transport"] == "tcp"


def test_nginx_combined(normalizer):
    line = '203.0.113.5 - - [11/Oct/2026:22:14:15 +0000] "GET /a/b?x=..%2F..%2Fetc%2Fpasswd HTTP/1.1" 404 153 "-" "sqlmap/1.7"'
    ev = parse_one(normalizer, line, path="/var/log/nginx/access.log")
    assert ev["log.category"] == "webserver" and ev["http.response.status_code"] == 404
    assert ev["url.path"] == "/a/b" and ev["url.query"] == "x=..%2F..%2Fetc%2Fpasswd"
    assert ev["url.decoded"] == "/a/b?x=../../etc/passwd" and ev["user_agent.original"] == "sqlmap/1.7"
    assert ev["@timestamp"] == 1791756855.0


def test_json_access_log(normalizer):
    line = ('{"time_local":"11/Oct/2026:22:14:15 +0000","remote_addr":"198.51.100.2","request":"POST /login HTTP/2.0",'
            '"status":"401","body_bytes_sent":"12","http_user_agent":"curl/8"}')
    ev = parse_one(normalizer, line, path="/var/log/nginx/access.log")
    assert ev["http.request.method"] == "POST" and ev["http.response.status_code"] == 401


def test_auditd_assembles_process_creation(normalizer):
    lines = [
        'type=SYSCALL msg=audit(1791756855.100:42): arch=c000003e syscall=59 success=yes exit=0 a0=55e a1=55f '
        'ppid=100 pid=101 auid=1000 uid=0 euid=0 tty=pts0 comm="whoami" exe="/usr/bin/whoami" key="exec"',
        'type=EXECVE msg=audit(1791756855.100:42): argc=2 a0="id" a1=2D75',
        'type=CWD msg=audit(1791756855.100:42): cwd="/root"',
        'type=PROCTITLE msg=audit(1791756855.100:42): proctitle=6964002D75',
    ]
    out = []
    for line in lines:
        out += normalizer.parse({"type": "file", "path": "/var/log/audit/audit.log", "line": line}, host="web01")
    raw_exec = next(e for e in out if e.get("auditd.type") == "EXECVE")
    assert raw_exec["a0"] == "id" and raw_exec["a1"] == "-u"   # hex argument decoded
    syscall = next(e for e in out if e.get("auditd.type") == "SYSCALL")
    assert syscall["a0"] == "55e"                                # syscall args stay raw
    proc = [e for e in out if e.get("log.category") == "process_creation"]
    assert len(proc) == 1
    assert proc[0]["CommandLine"] == "id -u" and proc[0]["Image"] == "/usr/bin/whoami"
    assert proc[0]["process.working_directory"] == "/root" and proc[0]["process.parent.pid"] == 100


def test_windows_xml(normalizer):
    xml = (FIXTURES / "windows_4625.xml").read_text()
    ev = normalizer.parse({"type": "wineventlog", "channel": "Security", "xml": xml}, host="agent-host")[0]
    assert ev["log.product"] == "windows" and ev["log.services"] == ["security"]
    assert ev["EventID"] == 4625 and ev["TargetUserName"] == "administrator"
    assert ev["event.action"] == "logon_failed" and ev["source.ip"] == "198.51.100.23"
    assert ev["winlog.logon.type"] == "network" and ev["host.name"] == "DC01.corp.example"


def test_windows_process_creation(normalizer):
    rec = {"EventID": "1", "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "PC1",
           "EventData": {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami",
                         "ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\bob"}}
    ev = normalizer.parse({"type": "wineventlog", "data": rec})[0]
    assert ev["log.category"] == "process_creation" and ev["process.name"] == "cmd.exe"
    assert ev["CommandLine"] == "cmd.exe /c whoami"


def test_journald_entry(normalizer):
    entry = {"MESSAGE": "Failed password for root from 198.51.100.9 port 22 ssh2", "SYSLOG_IDENTIFIER": "sshd",
             "_PID": "77", "_HOSTNAME": "jhost", "__REALTIME_TIMESTAMP": "1791756855000000"}
    ev = normalizer.parse({"type": "journald", "entry": entry})[0]
    assert ev["event.action"] == "ssh_login_failed" and ev["host.name"] == "jhost" and ev["@timestamp"] == 1791756855.0


def test_process_record(normalizer):
    ev = normalizer.parse({"type": "process", "data": {"pid": 5, "ppid": 1, "exe": "/usr/bin/curl", "cmdline": "curl -s x",
                                                       "user": "www-data", "parent_exe": "/usr/sbin/nginx"}}, host="h")[0]
    assert ev["Image"] == "/usr/bin/curl" and ev["ParentImage"] == "/usr/sbin/nginx" and ev["User"] == "www-data"


def test_garbage_never_raises(normalizer):
    for line in ["", "\x00\x01\x02", "Oct 99 99:99:99 x", "type=FOO msg=audit(", "{not json", "a" * 20000]:
        normalizer.parse({"type": "file", "path": "/var/log/auth.log", "line": line}, host="h")
        normalizer.parse({"type": "file", "path": "/var/log/nginx/access.log", "line": line}, host="h")
