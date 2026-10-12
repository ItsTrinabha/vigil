"""Windows Event Log records (Security, System, Sysmon, PowerShell).

The agent ships each record as rendered XML (from `wevtutil qe /f:xml`) or as
an already-decoded dict. EventData names are kept as-is so SigmaHQ Windows
rules (TargetUserName, LogonType, Image, CommandLine ...) match directly,
and the common ones are mapped onto the normalised schema.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .syslog import parse_iso

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

CHANNEL_SERVICE = {
    "security": "security", "system": "system", "application": "application",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell-classic",
    "microsoft-windows-windows defender/operational": "windefend",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
}


def xml_to_record(xml: str) -> dict | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    sysn = root.find(f"{NS}System")
    if sysn is None:
        return None
    rec: dict = {}
    prov = sysn.find(f"{NS}Provider")
    if prov is not None:
        rec["Provider_Name"] = prov.get("Name")
    for tag in ("EventID", "Level", "Task", "Opcode", "Keywords", "EventRecordID", "Channel", "Computer"):
        n = sysn.find(f"{NS}{tag}")
        if n is not None and n.text is not None:
            rec[tag] = n.text
    tc = sysn.find(f"{NS}TimeCreated")
    if tc is not None:
        rec["TimeCreated"] = tc.get("SystemTime")
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is None:
        ed = root.find(f"{NS}UserData")
    if ed is not None:
        for i, d in enumerate(ed.iter()):
            if d is ed:
                continue
            name = d.get("Name") or d.tag.replace(NS, "").split("}")[-1]
            if d.text is not None and d.text.strip():
                data[name if d.get("Name") or name != "Data" else f"Data{i}"] = d.text
    rec["EventData"] = data
    return rec


LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
               "8": "network_cleartext", "9": "new_credentials", "10": "remote_interactive", "11": "cached_interactive"}


def parse_windows(rec: dict) -> tuple[float | None, str | None, dict, dict]:
    """Returns (ts, host, fields, logsource)."""
    data = rec.get("EventData") or {}
    eid = int(rec.get("EventID", 0) or 0)
    channel = (rec.get("Channel") or "").strip()
    service = CHANNEL_SERVICE.get(channel.lower(), channel.lower() or None)
    f: dict = {"EventID": eid, "Channel": channel, "Provider_Name": rec.get("Provider_Name"),
               "Computer": rec.get("Computer"), "winlog.record_id": rec.get("EventRecordID")}
    f.update(data)
    category = None
    g = data.get
    if service == "security":
        if eid in (4624, 4625):
            ok = eid == 4624
            f.update({"event.category": "authentication", "event.action": "logon_success" if ok else "logon_failed",
                      "event.outcome": "success" if ok else "failure", "user.name": g("TargetUserName"),
                      "user.domain": g("TargetDomainName"), "source.ip": g("IpAddress"),
                      "winlog.logon.type": LOGON_TYPES.get(str(g("LogonType")), g("LogonType"))})
        elif eid == 4688:
            category = "process_creation"
            f.update({"Image": g("NewProcessName"), "ParentImage": g("ParentProcessName"),
                      "User": g("SubjectUserName"), "event.action": "process_started"})
        elif eid == 4720:
            f.update({"event.category": "iam", "event.action": "user_created", "user.target.name": g("TargetUserName"),
                      "user.name": g("SubjectUserName")})
        elif eid in (4728, 4732, 4756):
            f.update({"event.category": "iam", "event.action": "group_member_added", "group.name": g("TargetUserName"),
                      "user.target.name": g("MemberName"), "user.name": g("SubjectUserName")})
        elif eid == 4672:
            f.update({"event.category": "session", "event.action": "special_privileges_assigned", "user.name": g("SubjectUserName")})
        elif eid == 1102:
            f.update({"event.category": "configuration", "event.action": "audit_log_cleared", "user.name": g("SubjectUserName")})
        elif eid == 4740:
            f.update({"event.category": "iam", "event.action": "account_locked_out", "user.target.name": g("TargetUserName")})
    elif service == "sysmon":
        if eid == 1:
            category = "process_creation"
        elif eid == 3:
            category = "network_connection"
            f.update({"source.ip": g("SourceIp"), "destination.ip": g("DestinationIp"),
                      "destination.port": int(g("DestinationPort")) if str(g("DestinationPort") or "").isdigit() else None})
        elif eid == 11:
            category = "file_event"
        elif eid in (12, 13, 14):
            category = "registry_event"
        elif eid == 22:
            category = "dns_query"
    elif service == "system" and eid == 7045:
        f.update({"event.category": "configuration", "event.action": "service_installed",
                  "service.name": g("ServiceName"), "process.executable": g("ImagePath")})
    elif service == "powershell" and eid == 4104:
        category = "ps_script"
        f.update({"event.category": "process", "event.action": "powershell_script_block"})

    if category == "process_creation":
        img = f.get("Image")
        f.update({"event.category": "process_creation", "event.action": "process_started", "event.outcome": "success",
                  "process.executable": img, "process.name": (img or "").replace("\\", "/").rsplit("/", 1)[-1] or None,
                  "process.command_line": g("CommandLine"), "process.parent.executable": f.get("ParentImage"),
                  "process.parent.command_line": g("ParentCommandLine"), "user.name": f.get("User") or g("User")})
    elif category:
        f.setdefault("event.category", category)
    f.setdefault("event.category", "windows")
    f.setdefault("event.action", f"win_event_{eid}")
    logsource = {"product": "windows", "service": service, "category": category}
    ts = parse_iso(rec["TimeCreated"]) if rec.get("TimeCreated") else None
    if f.get("source.ip") in ("-", "::1", "127.0.0.1", ""):
        f.pop("source.ip")
    return ts, rec.get("Computer"), {k: v for k, v in f.items() if v not in (None, "", "-")}, logsource
