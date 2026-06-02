import os
import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Generator

import evtx as evtx_lib

SEVERITY_MAP = {
    # ── Security channel ──────────────────────
    # Authentication
    "4624": "info",      # successful login
    "4625": "high",      # failed login
    "4626": "info",      # user rights assigned
    "4627": "info",      # group membership info
    "4634": "info",      # account logoff
    "4647": "info",      # user initiated logoff
    "4648": "high",      # explicit credential use
    "4649": "high",      # replay attack detected
    "4675": "medium",    # SIDs filtered

    # Account management
    "4720": "high",      # user account created
    "4722": "medium",    # user account enabled
    "4723": "medium",    # password change attempt
    "4724": "medium",    # password reset attempt
    "4725": "high",      # user account disabled
    "4726": "high",      # user account deleted
    "4728": "high",      # user added to global group
    "4729": "medium",    # user removed from global group
    "4732": "high",      # user added to local group
    "4733": "medium",    # user removed from local group
    "4735": "high",      # security group changed
    "4737": "high",      # global group changed
    "4738": "medium",    # user account changed
    "4740": "high",      # user account locked out
    "4741": "high",      # computer account created
    "4743": "high",      # computer account deleted
    "4756": "high",      # user added to universal group

    # Privilege use
    "4672": "medium",    # admin privilege assigned
    "4673": "medium",    # privileged service called
    "4674": "medium",    # privileged object operation

    # Process tracking
    "4688": "medium",    # new process created
    "4689": "info",      # process terminated
    "4696": "medium",    # primary token assigned

    # Audit policy
    "4702": "medium",    # scheduled task updated
    "4698": "high",      # scheduled task created
    "4699": "high",      # scheduled task deleted
    "4700": "high",      # scheduled task enabled
    "4701": "medium",    # scheduled task disabled

    # Object access
    "4663": "medium",    # object access attempt
    "4670": "medium",    # permissions changed
    "4907": "info",      # audit policy changed

    # System events
    "4616": "medium",    # system time changed
    "4657": "medium",    # registry value modified

    # Log management
    "1100": "high",      # event logging stopped
    "1102": "critical",  # security log cleared
    "1104": "high",      # security log full

    # Kerberos
    "4768": "info",      # kerberos ticket requested
    "4769": "info",      # kerberos service ticket
    "4771": "high",      # kerberos pre-auth failed
    "4776": "medium",    # NTLM auth attempt
    "4778": "info",      # session reconnected
    "4779": "info",      # session disconnected

    # Trust/domain
    "4904": "info",      # audit source registered
    "4905": "info",      # audit source unregistered

    # Services (System channel)
    "7045": "high",      # new service installed
    "7040": "medium",    # service start type changed
    "7036": "info",      # service state changed
    "7034": "medium",    # service crashed
    "6008": "medium",    # unexpected shutdown
    "6005": "info",      # event log started
    "6006": "info",      # event log stopped

    # ── Sysmon channel ────────────────────────
    "1":  "medium",      # process creation
    "2":  "medium",      # file creation time changed
    "3":  "medium",      # network connection
    "4":  "info",        # sysmon service state
    "5":  "medium",      # process terminated
    "6":  "high",        # driver loaded
    "7":  "medium",      # image loaded
    "8":  "high",        # create remote thread
    "9":  "high",        # raw disk access
    "10": "high",        # process access
    "11": "medium",      # file created
    "12": "medium",      # registry object created
    "13": "medium",      # registry value set
    "14": "medium",      # registry object renamed
    "15": "high",        # alternate data stream
    "16": "info",        # sysmon config changed
    "17": "high",        # pipe created
    "18": "high",        # pipe connected
    "19": "high",        # wmi filter
    "20": "high",        # wmi consumer
    "21": "high",        # wmi consumer filter
    "22": "medium",      # dns query
    "23": "high",        # file delete archived
    "24": "medium",      # clipboard change
    "25": "high",        # process tampering
    "26": "high",        # file delete logged
    "29": "high",        # file executable detected

    # ── PowerShell channel ────────────────────
    "4100": "medium",    # PowerShell error
    "4103": "medium",    # pipeline execution
    "4104": "high",      # script block logging
    "4105": "info",      # started
    "4106": "info",      # stopped
    "40961": "info",     # PowerShell console started
    "40962": "info",     # PowerShell ready

    # ── Windows Defender channel ──────────────
    "1116": "high",      # malware detected
    "1117": "critical",  # malware action taken
    "1118": "medium",    # antimalware scan started
    "1119": "medium",    # antimalware scan succeeded
    "1120": "high",      # antimalware scan failed
    "5001": "high",      # real-time protection disabled
    "5004": "high",      # real-time protection config changed
    "5007": "high",      # antimalware config changed
    "5010": "high",      # antimalware scan for malware disabled
    "5012": "high",      # antimalware scan for viruses disabled

    # ── Task Scheduler channel ────────────────
    "106":  "medium",    # task registered
    "140":  "medium",    # task updated
    "141":  "high",      # task deleted
    "200":  "info",      # task executed
    "201":  "info",      # task completed

    # ── WMI channel ───────────────────────────
    "5857": "medium",    # WMI provider started
    "5858": "high",      # WMI provider error
    "5859": "high",      # WMI filter registered
    "5860": "high",      # WMI consumer registered
    "5861": "high",      # WMI binding registered

    # ── Application channel ───────────────────
    "1000": "medium",    # application crash
    "1001": "medium",    # application hang
    "1002": "medium",    # application crash report

    # ── Terminal Services channel ─────────────
    "21":   "info",      # remote desktop login
    "22":   "info",      # shell started
    "23":   "info",      # session logoff
    "24":   "info",      # session disconnected
    "25":   "info",      # session reconnected

    # ── Firewall channel ──────────────────────
    "2004": "high",      # firewall rule added
    "2005": "medium",    # firewall rule modified
    "2006": "high",      # firewall rule deleted
    "2009": "high",      # firewall failed to load
    "2033": "high",      # firewall rule deleted all
}

ALWAYS_INFO_EIDS = {
    "5379",  # credential manager read
    "4798",  # user local group query
    "4799",  # security group query
    "4907",  # audit policy on object
    "5059",  # key migration
    "5061",  # cryptographic operation
    "5382",  # vault credential read
    "4703",  # token right adjusted
    "4704",  # user right assigned
    "4705",  # user right removed
    "4717",  # system security access granted
    "4718",  # system security access removed
    "4985",  # state of transaction changed
    "5156",  # firewall connection allowed
    "5158",  # firewall bind allowed
    "4689",  # process exit
    "4634",  # logoff
    "4647",  # user initiated logoff
}

SUSPICIOUS_CHAINS = {
    ("winword.exe",    "powershell.exe"),
    ("winword.exe",    "cmd.exe"),
    ("excel.exe",      "powershell.exe"),
    ("excel.exe",      "cmd.exe"),
    ("outlook.exe",    "powershell.exe"),
    ("outlook.exe",    "cmd.exe"),
    ("mshta.exe",      "powershell.exe"),
    ("wscript.exe",    "powershell.exe"),
    ("cscript.exe",    "powershell.exe"),
    ("regsvr32.exe",   "powershell.exe"),
    ("powershell.exe", "net.exe"),
    ("powershell.exe", "whoami.exe"),
    ("cmd.exe",        "certutil.exe"),
    ("cmd.exe",        "bitsadmin.exe"),
    ("chrome.exe",     "powershell.exe"),
    ("firefox.exe",    "cmd.exe"),
    ("iexplore.exe",   "powershell.exe"),
}


NOISE_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "ANONYMOUS LOGON", "DWM-1", "DWM-2",
    "UMFD-0", "UMFD-1", "UMFD-2",
    "NT AUTHORITY",
}
NORMAL_LOGON_TYPES = {"2", "4", "5", "7"}
EVENT_THRESHOLDS = {
    "4625": 10,
    "4672": 50,
    "4688": 100,
    "4624": 20,
}
_event_counts  = defaultdict(int)
_event_windows = {}

def _is_noise_account(event_data: dict) -> bool:
    username = (
        event_data.get("SubjectUserName", "") or
        event_data.get("TargetUserName", "") or
        event_data.get("SubjectDomainName", "") or
        ""
    ).strip()
    return (username in NOISE_ACCOUNTS or
            username.endswith("$") or
            username == "")

def _logon_type_severity(event_data: dict,
                          base: str) -> str:
    if str(event_data.get("LogonType","")) in NORMAL_LOGON_TYPES:
        return "info"
    return base

def _time_boost(ts: str, base: str) -> str:
    try:
        if base == "info" or ts == "unknown":
            return base
        hour = datetime.strptime(
            ts, "%Y-%m-%dT%H:%M:%SZ").hour
        if hour >= 23 or hour <= 5:
            order = ["info","low","medium","high","critical"]
            return order[min(order.index(base)+1, 4)]
        return base
    except Exception:
        return base

def _freq_severity(event_id: str, ts: str,
                   base: str) -> str:
    try:
        if ts == "unknown":
            return base
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        if event_id not in _event_windows:
            _event_windows[event_id] = dt
            _event_counts[event_id]  = 0
        elapsed = (dt - _event_windows[event_id]).total_seconds()
        if elapsed > 300:
            _event_windows[event_id] = dt
            _event_counts[event_id]  = 0
        _event_counts[event_id] += 1
        if _event_counts[event_id] > EVENT_THRESHOLDS.get(event_id, 9999):
            order = ["info","low","medium","high","critical"]
            return order[min(order.index(base)+1, 4)]
        return base
    except Exception:
        return base


def _check_suspicious_chain(event_data: dict) -> tuple:
    parent = event_data.get("ParentProcessName", "")
    child  = event_data.get("NewProcessName", "")

    if not parent or not child:
        return False, ""

    parent_exe = parent.split("\\")[-1].lower()
    child_exe  = child.split("\\")[-1].lower()

    if (parent_exe, child_exe) in SUSPICIOUS_CHAINS:
        detail = f"Suspicious chain: {parent_exe} → {child_exe}"
        return True, detail

    return False, ""


def _normalize_ts(raw_ts: str) -> str:
    if not raw_ts:
        return "unknown"
    match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", raw_ts)
    return match.group(1) + "Z" if match else "unknown"


def _extract_event_data(event_data: Any) -> dict:
    result = {}
    if not event_data or not isinstance(event_data, dict):
        return result
    raw = event_data.get("Data") or event_data.get("data")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                name = item.get("#attributes", {}).get("Name", "")
                value = item.get("#text", "")
                if name:
                    result[name] = value
    elif isinstance(raw, dict):
        name = raw.get("#attributes", {}).get("Name", "")
        value = raw.get("#text", "")
        if name:
            result[name] = value
    # Flat key-value style: {"SubjectUserSid": "S-1-5-18", ...}
    for k, v in event_data.items():
        if k not in ("Data", "data") and not k.startswith("#") and isinstance(v, (str, int, float)):
            result[k] = str(v)
    return result


def parse_evtx(filepath: str) -> Generator:
    global _event_counts, _event_windows
    _event_counts  = defaultdict(int)
    _event_windows = {}

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"evtx file not found: {filepath}")

    parser = evtx_lib.PyEvtxParser(filepath)
    count = 0

    for record in parser.records_json():
        if isinstance(record, RuntimeError):
            print(f"[warn] Skipping corrupted record: {record}")
            continue

        try:
            raw_data = record["data"]
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            system = data.get("Event", {}).get("System", {})
            event_data_raw = data.get("Event", {}).get("EventData", {})

            # EventID can be plain int/str or a dict wrapping qualifiers
            event_id_raw = system.get("EventID")
            if event_id_raw is None:
                event_id = "unknown"
            elif isinstance(event_id_raw, dict):
                event_id = str(event_id_raw.get("#text", "unknown"))
            else:
                event_id = str(event_id_raw)

            # Timestamp lives inside TimeCreated SystemTime attribute
            time_created = system.get("TimeCreated", {})
            raw_ts = (
                time_created.get("#attributes", {}).get("SystemTime", "")
                if isinstance(time_created, dict)
                else ""
            )
            ts = _normalize_ts(raw_ts)

            extracted_data = _extract_event_data(event_data_raw)
            severity       = SEVERITY_MAP.get(event_id, "info")
            if event_id in ALWAYS_INFO_EIDS:
                severity = "info"
            chain_detail   = ""

            if event_id == "4688":
                is_suspicious, chain_detail = _check_suspicious_chain(extracted_data)
                if is_suspicious:
                    severity = "critical"
                    extracted_data["suspicious_chain"] = chain_detail
                    extracted_data["chain_detected"]   = True

            if _is_noise_account(extracted_data):
                severity = "info"
            else:
                if event_id == "4624":
                    severity = _logon_type_severity(
                        extracted_data, severity)
                severity = _time_boost(ts, severity)
                severity = _freq_severity(
                    event_id, ts, severity)

            yield {
                "ts":         ts,
                "source":     "evtx",
                "event_type": event_id,
                "severity":   severity,
                "raw":        raw_data if isinstance(raw_data, str) else json.dumps(raw_data),
                "metadata": {
                    "EventID":           event_id,
                    "Computer":          str(system.get("Computer", "")),
                    "Channel":           str(system.get("Channel", "")),
                    "EventData":         extracted_data,
                    "suspicious_chain":  chain_detail,
                },
            }
            count += 1
            if count % 100_000 == 0:
                print(f"  [evtx] {count:,} events streamed...")
        except Exception as e:
            print(f"[warn] Skipping unparseable event: {e}")
            continue


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python evtx_parser.py <file.evtx>")
        sys.exit(1)

    events = list(parse_evtx(sys.argv[1]))
    print(f"Total events parsed: {len(events)}")
    print(f"Severities: {set(e['severity'] for e in events)}")
    print(f"Event types: {set(e['event_type'] for e in events)}")
    print("\nFirst 3 events:")
    for e in events[:3]:
        print(json.dumps(e, indent=2))
