"""
simulator/raw_events.py — ECS-to-Raw Vendor Format Converter
=============================================================

Converts ECS (Elastic Common Schema) JSON events to raw vendor log formats —
Sysmon text and Windows Security XML — as they would appear in real endpoint
telemetry. The output is a Splunk/Cribl HEC envelope containing the raw log
in the ``event`` field alongside standard HEC metadata.

Purpose:
    Phase 3 of the Blue Team Detection Engineering project adds an end-to-end
    Cribl normalization pipeline. This module generates the raw-format events
    that are pushed to Cribl's HEC input so the normalization pipeline can be
    tested against realistic source data rather than pre-normalized ECS.

Input:
    ECS event dict (as produced by simulator/simulator.py and the scenario JSON
    files in simulator/scenarios/).

Output:
    HEC envelope dict::

        {
            "event":      "<raw Sysmon text or Windows XML>",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "host":       "WORKSTATION-01",
            "source":     "WinEventLog:Microsoft-Windows-Sysmon/Operational",
            "time":       1741862400,
            "_simulation": { ... }   # preserved for TP/FP scoring
        }

Usage::

    from simulator.raw_events import ecs_to_raw, convert_scenario_to_raw

    hec_event = ecs_to_raw(ecs_event_dict)
    raw_scenario = convert_scenario_to_raw(scenario_dict)

Stdlib only — no external dependencies.
"""

import datetime
import json
import uuid


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_utc() -> datetime.datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_timestamp(ecs_event: dict) -> datetime.datetime:
    """
    Extract the event timestamp from the ECS event.

    Falls back to the current UTC time if ``@timestamp`` is absent or
    cannot be parsed (e.g. the literal placeholder ``{{now}}``).
    """
    raw = ecs_event.get("@timestamp", "")
    if raw and raw != "{{now}}":
        try:
            # Python 3.7+ fromisoformat does not accept trailing 'Z'
            ts = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=datetime.timezone.utc)
            return ts
        except ValueError:
            pass
    return _now_utc()


def _ts_str(ts: datetime.datetime) -> str:
    """Format a datetime as the Sysmon UtcTime string: ``YYYY-MM-DD HH:MM:SS.mmm``."""
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


def _guid() -> str:
    """Return a random GUID in the Sysmon ``{xxxxxxxx-xxxx-…}`` format."""
    return "{" + str(uuid.uuid4()).upper() + "}"


def _get(obj: dict, *keys, default: str = "") -> str:
    """
    Safely traverse a nested dict and return the value as a string.

    Example::

        _get(event, "process", "parent", "executable")
        # → event["process"]["parent"]["executable"] or ""
    """
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key, None)
        if cur is None:
            return default
    return str(cur) if cur is not None else default


def _unix_ts(ts: datetime.datetime) -> int:
    """Return POSIX timestamp as an integer (seconds since epoch)."""
    return int(ts.timestamp())


def _sysmon_fields_to_text(fields: list[tuple[str, str]]) -> str:
    """
    Render a list of ``(FieldName, value)`` tuples as Sysmon key-value text.

    Empty values are included (Sysmon does emit them as empty strings).
    """
    lines = []
    for name, value in fields:
        lines.append(f"{name}: {value}")
    return "\n".join(lines)


def _hec_envelope(
    raw_text: str,
    sourcetype: str,
    source: str,
    host: str,
    ts: datetime.datetime,
    ecs_event: dict,
) -> dict:
    """Wrap a raw log string in a Splunk/Cribl HEC envelope.

    Custom metadata (_simulation) goes in the ``fields`` sub-object per the
    HEC protocol spec.  This ensures Cribl's in_splunk_hec input promotes
    these fields to top-level event properties (``__e._simulation``), which
    the routing rules and downstream scoring depend on.
    """
    envelope: dict = {
        "event": raw_text,
        "sourcetype": sourcetype,
        "host": host,
        "source": source,
        "time": _unix_ts(ts),
    }
    sim = ecs_event.get("_simulation", {})
    if sim:
        envelope["fields"] = {"_simulation": sim}
        # Also keep top-level for backward compat with direct-ingest callers
        envelope["_simulation"] = sim
    return envelope


# ---------------------------------------------------------------------------
# Sysmon EID converters
# ---------------------------------------------------------------------------

def _sysmon_eid1(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 1 — Process Create."""
    proc = ecs_event.get("process", {})
    parent = proc.get("parent", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    fields = [
        ("EventID",            "1"),
        ("UtcTime",            _ts_str(ts)),
        ("ProcessGuid",        _get(ecs_event, "winlog", "event_data", "ProcessGuid") or _guid()),
        ("ProcessId",          _get(proc, "pid") or _get(proc, "entity_id")),
        ("Image",              _get(proc, "executable")),
        ("FileVersion",        _get(ecs_event, "winlog", "event_data", "FileVersion")),
        ("Description",        _get(ecs_event, "winlog", "event_data", "Description")),
        ("Product",            _get(ecs_event, "winlog", "event_data", "Product")),
        ("Company",            _get(ecs_event, "winlog", "event_data", "Company")),
        ("OriginalFileName",   _get(ecs_event, "winlog", "event_data", "OriginalFileName")),
        ("CommandLine",        _get(proc, "command_line")),
        ("CurrentDirectory",   _get(proc, "working_directory")),
        ("User",               full_user),
        ("LogonGuid",          _get(ecs_event, "winlog", "event_data", "LogonGuid") or _guid()),
        ("LogonId",            _get(ecs_event, "winlog", "event_data", "LogonId") or "0x0"),
        ("TerminalSessionId",  _get(ecs_event, "winlog", "event_data", "TerminalSessionId") or "1"),
        ("IntegrityLevel",     _get(ecs_event, "winlog", "event_data", "IntegrityLevel") or "Medium"),
        ("Hashes",             _get(ecs_event, "winlog", "event_data", "Hashes") or
                               ("SHA256=" + _get(proc, "hash", "sha256"))),
        ("ParentProcessGuid",  _get(ecs_event, "winlog", "event_data", "ParentProcessGuid") or _guid()),
        ("ParentProcessId",    _get(parent, "pid")),
        ("ParentImage",        _get(parent, "executable")),
        ("ParentCommandLine",  _get(parent, "command_line")),
        ("ParentUser",         _get(ecs_event, "winlog", "event_data", "ParentUser")),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid3(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 3 — Network Connection."""
    proc = ecs_event.get("process", {})
    net = ecs_event.get("network", {})
    src = ecs_event.get("source", {})
    dst = ecs_event.get("destination", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    fields = [
        ("EventID",          "3"),
        ("UtcTime",          _ts_str(ts)),
        ("ProcessGuid",      _get(ecs_event, "winlog", "event_data", "ProcessGuid") or _guid()),
        ("ProcessId",        _get(proc, "pid")),
        ("Image",            _get(proc, "executable")),
        ("User",             full_user),
        ("Protocol",         _get(net, "transport") or _get(net, "protocol") or "tcp"),
        ("Initiated",        _get(ecs_event, "winlog", "event_data", "Initiated") or "true"),
        ("SourceIsIpv6",     _get(ecs_event, "winlog", "event_data", "SourceIsIpv6") or "false"),
        ("SourceIp",         _get(src, "ip")),
        ("SourceHostname",   _get(src, "domain")),
        ("SourcePort",       _get(src, "port")),
        ("SourcePortName",   _get(ecs_event, "winlog", "event_data", "SourcePortName")),
        ("DestinationIsIpv6","false"),
        ("DestinationIp",    _get(dst, "ip")),
        ("DestinationHostname", _get(dst, "domain")),
        ("DestinationPort",  _get(dst, "port")),
        ("DestinationPortName", _get(ecs_event, "winlog", "event_data", "DestinationPortName")),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid7(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 7 — Image Loaded."""
    proc = ecs_event.get("process", {})
    file_ = ecs_event.get("file", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    fields = [
        ("EventID",         "7"),
        ("UtcTime",         _ts_str(ts)),
        ("ProcessGuid",     _get(ecs_event, "winlog", "event_data", "ProcessGuid") or _guid()),
        ("ProcessId",       _get(proc, "pid")),
        ("Image",           _get(proc, "executable")),
        ("ImageLoaded",     _get(file_, "path") or
                            _get(ecs_event, "winlog", "event_data", "ImageLoaded")),
        ("FileVersion",     _get(ecs_event, "winlog", "event_data", "FileVersion")),
        ("Description",     _get(ecs_event, "winlog", "event_data", "Description")),
        ("Product",         _get(ecs_event, "winlog", "event_data", "Product")),
        ("Company",         _get(ecs_event, "winlog", "event_data", "Company")),
        ("OriginalFileName",_get(ecs_event, "winlog", "event_data", "OriginalFileName")),
        ("Hashes",          _get(ecs_event, "winlog", "event_data", "Hashes") or
                            ("SHA256=" + _get(file_, "hash", "sha256"))),
        ("Signed",          _get(ecs_event, "winlog", "event_data", "Signed") or "false"),
        ("Signature",       _get(ecs_event, "winlog", "event_data", "Signature")),
        ("SignatureStatus", _get(ecs_event, "winlog", "event_data", "SignatureStatus") or "Unavailable"),
        ("User",            full_user),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid8(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 8 — CreateRemoteThread."""
    proc = ecs_event.get("process", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    source_guid = ed.get("SourceProcessGUID") or _guid()
    target_guid = ed.get("TargetProcessGUID") or _guid()

    fields = [
        ("EventID",           "8"),
        ("UtcTime",           _ts_str(ts)),
        ("SourceProcessGuid", source_guid),
        ("SourceProcessId",   _get(proc, "pid")),
        ("SourceImage",       _get(proc, "executable")),
        ("TargetProcessGuid", target_guid),
        ("TargetProcessId",   ed.get("TargetProcessId", "")),
        ("TargetImage",       ed.get("TargetImage", "")),
        ("NewThreadId",       ed.get("NewThreadId", "")),
        ("StartAddress",      ed.get("StartAddress", "")),
        ("StartModule",       ed.get("StartModule", "")),
        ("StartFunction",     ed.get("StartFunction", "")),
        ("SourceUser",        full_user),
        ("TargetUser",        ed.get("TargetUser", "")),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid10(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 10 — ProcessAccess."""
    proc = ecs_event.get("process", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    source_guid = ed.get("SourceProcessGUID") or _guid()
    target_guid = ed.get("TargetProcessGUID") or _guid()

    fields = [
        ("EventID",            "10"),
        ("UtcTime",            _ts_str(ts)),
        ("SourceProcessGUID",  source_guid),
        ("SourceProcessId",    _get(proc, "pid")),
        ("SourceThreadId",     ed.get("SourceThreadId", "")),
        ("SourceImage",        _get(proc, "executable")),
        ("TargetProcessGUID",  target_guid),
        ("TargetProcessId",    ed.get("TargetProcessId", "")),
        ("TargetImage",        ed.get("TargetImage", "")),
        ("GrantedAccess",      ed.get("GrantedAccess", "")),
        ("CallTrace",          ed.get("CallTrace", "")),
        ("SourceUser",         full_user),
        ("TargetUser",         ed.get("TargetUser", "")),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid11(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 11 — FileCreate."""
    proc = ecs_event.get("process", {})
    file_ = ecs_event.get("file", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    target_filename = (
        _get(file_, "path")
        or _get(ecs_event, "winlog", "event_data", "TargetFilename")
        or _get(file_, "name")
    )

    fields = [
        ("EventID",         "11"),
        ("UtcTime",         _ts_str(ts)),
        ("ProcessGuid",     _get(ecs_event, "winlog", "event_data", "ProcessGuid") or _guid()),
        ("ProcessId",       _get(proc, "pid")),
        ("Image",           _get(proc, "executable")),
        ("TargetFilename",  target_filename),
        ("CreationUtcTime", _get(ecs_event, "winlog", "event_data", "CreationUtcTime") or _ts_str(ts)),
        ("User",            full_user),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid13(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 13 — RegistryEvent (Value Set)."""
    proc = ecs_event.get("process", {})
    reg = ecs_event.get("registry", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    target_object = (
        _get(reg, "path")
        or ed.get("TargetObject", "")
        or ((_get(reg, "hive") + "\\" + _get(reg, "key") + "\\" + _get(reg, "value")).strip("\\"))
    )

    details = (
        ed.get("Details", "")
        or _get(reg, "data", "strings")
        or _get(ecs_event, "registry", "value")
    )
    if isinstance(details, list):
        details = " ".join(str(d) for d in details)

    fields = [
        ("EventID",      "13"),
        ("UtcTime",      _ts_str(ts)),
        ("ProcessGuid",  ed.get("ProcessGuid", "") or _guid()),
        ("ProcessId",    _get(proc, "pid")),
        ("Image",        _get(proc, "executable")),
        ("EventType",    ed.get("EventType", "SetValue")),
        ("TargetObject", target_object),
        ("Details",      str(details)),
        ("User",         full_user),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid17(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 17 — PipeEvent (Pipe Created)."""
    proc = ecs_event.get("process", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    pipe_name = (
        ed.get("PipeName", "")
        or _get(ecs_event, "file", "name")
        or _get(ecs_event, "file", "path")
    )

    fields = [
        ("EventID",     "17"),
        ("UtcTime",     _ts_str(ts)),
        ("ProcessGuid", ed.get("ProcessGuid", "") or _guid()),
        ("ProcessId",   _get(proc, "pid")),
        ("PipeName",    pipe_name),
        ("Image",       _get(proc, "executable")),
        ("User",        full_user),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid18(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 18 — PipeEvent (Pipe Connected)."""
    proc = ecs_event.get("process", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})
    user = ecs_event.get("user", {})
    domain = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain}\\{username}" if domain else username

    pipe_name = (
        ed.get("PipeName", "")
        or _get(ecs_event, "file", "name")
        or _get(ecs_event, "file", "path")
    )

    fields = [
        ("EventID",     "18"),
        ("UtcTime",     _ts_str(ts)),
        ("ProcessGuid", ed.get("ProcessGuid", "") or _guid()),
        ("ProcessId",   _get(proc, "pid")),
        ("PipeName",    pipe_name),
        ("Image",       _get(proc, "executable")),
        ("User",        full_user),
    ]
    return _sysmon_fields_to_text(fields)


def _sysmon_eid22(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 22 — DNSEvent (DNS Query)."""
    proc = ecs_event.get("process", {})
    dns = ecs_event.get("dns", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})
    user = ecs_event.get("user", {})
    domain_field = user.get("domain", "")
    username = user.get("name", "")
    full_user = f"{domain_field}\\{username}" if domain_field else username

    query_name = (
        _get(dns, "question", "name")
        or ed.get("QueryName", "")
    )
    query_type = (
        _get(dns, "question", "type")
        or ed.get("QueryType", "AAAA")
    )
    query_status = ed.get("QueryStatus", "0")

    fields = [
        ("EventID",      "22"),
        ("UtcTime",      _ts_str(ts)),
        ("ProcessGuid",  ed.get("ProcessGuid", "") or _guid()),
        ("ProcessId",    _get(proc, "pid")),
        ("QueryName",    query_name),
        ("QueryStatus",  query_status),
        ("QueryResults", ed.get("QueryResults", "")),
        ("Image",        _get(proc, "executable")),
        ("User",         full_user),
        ("QueryType",    query_type),
    ]
    return _sysmon_fields_to_text(fields)


# Dispatch table: EID → (converter_fn, sourcetype, source)
_SYSMON_DISPATCH: dict[str, tuple] = {
    "1":  (_sysmon_eid1,  "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "3":  (_sysmon_eid3,  "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "7":  (_sysmon_eid7,  "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "8":  (_sysmon_eid8,  "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "10": (_sysmon_eid10, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "11": (_sysmon_eid11, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "13": (_sysmon_eid13, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "17": (_sysmon_eid17, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "18": (_sysmon_eid18, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
    "22": (_sysmon_eid22, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                          "WinEventLog:Microsoft-Windows-Sysmon/Operational"),
}


def ecs_to_raw_sysmon(ecs_event: dict) -> dict:
    """
    Convert an ECS event to a raw Sysmon HEC envelope.

    The ``event`` field of the returned dict contains Sysmon key-value text
    exactly as written to the Windows Application event log by the Sysmon
    driver. Supported EIDs: 1, 3, 7, 8, 10, 11, 13, 17, 18, 22.

    For unsupported EIDs the raw text will contain a minimal representation
    with ``EventID`` and ``UtcTime`` only; no exception is raised so the
    pipeline can continue.

    Args:
        ecs_event: A single ECS event dictionary.

    Returns:
        HEC envelope dict with keys: ``event``, ``sourcetype``, ``host``,
        ``source``, ``time``, ``_simulation``.

    Raises:
        TypeError: If ``ecs_event`` is not a dict.
    """
    if not isinstance(ecs_event, dict):
        raise TypeError(f"ecs_to_raw_sysmon expects dict, got {type(ecs_event).__name__}")

    ts = _parse_timestamp(ecs_event)
    event_code = str(ecs_event.get("event", {}).get("code", "")).strip()
    host = _get(ecs_event, "host", "name") or "WORKSTATION-01"

    entry = _SYSMON_DISPATCH.get(event_code)
    if entry:
        converter_fn, sourcetype, source = entry
        raw_text = converter_fn(ecs_event, ts)
    else:
        # Graceful fallback for unknown EIDs
        raw_text = _sysmon_fields_to_text([
            ("EventID", event_code or "0"),
            ("UtcTime", _ts_str(ts)),
        ])
        sourcetype = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
        source = "WinEventLog:Microsoft-Windows-Sysmon/Operational"

    return _hec_envelope(raw_text, sourcetype, source, host, ts, ecs_event)


# ---------------------------------------------------------------------------
# Windows Security XML converters
# ---------------------------------------------------------------------------

def _win_sec_eid4624(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 4624 — An account was successfully logged on."""
    user = ecs_event.get("user", {})
    source = ecs_event.get("source", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})

    subject_username = ed.get("SubjectUserName", "-")
    subject_domain = ed.get("SubjectDomainName", "-")
    target_username = user.get("name", ed.get("TargetUserName", "-"))
    target_domain = user.get("domain", ed.get("TargetDomainName", "-"))
    logon_type = ed.get("LogonType", "3")
    logon_process = ed.get("LogonProcessName", "NtLmSsp")
    auth_package = ed.get("AuthenticationPackageName", "NTLM")
    workstation = ed.get("WorkstationName", _get(ecs_event, "host", "name"))
    ip_address = _get(source, "ip") or ed.get("IpAddress", "-")
    ip_port = _get(source, "port") or ed.get("IpPort", "-")
    logon_id = ed.get("TargetLogonId", "0x0")

    return (
        f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System>"
        f"<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>"
        f"<EventID>4624</EventID>"
        f"<Version>2</Version>"
        f"<Level>0</Level>"
        f"<Task>12544</Task>"
        f"<Opcode>0</Opcode>"
        f"<Keywords>0x8020000000000000</Keywords>"
        f"<TimeCreated SystemTime='{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}0Z'/>"
        f"<EventRecordID>{abs(hash(str(ts))) % 1000000}</EventRecordID>"
        f"<Correlation/>"
        f"<Execution ProcessID='4' ThreadID='8'/>"
        f"<Channel>Security</Channel>"
        f"<Computer>{_get(ecs_event, 'host', 'name') or 'WORKSTATION-01'}</Computer>"
        f"<Security/>"
        f"</System>"
        f"<EventData>"
        f"<Data Name='SubjectUserSid'>S-1-5-18</Data>"
        f"<Data Name='SubjectUserName'>{subject_username}</Data>"
        f"<Data Name='SubjectDomainName'>{subject_domain}</Data>"
        f"<Data Name='SubjectLogonId'>0x3e7</Data>"
        f"<Data Name='TargetUserSid'>S-1-5-21-0000000000-0000000000-0000000000-1001</Data>"
        f"<Data Name='TargetUserName'>{target_username}</Data>"
        f"<Data Name='TargetDomainName'>{target_domain}</Data>"
        f"<Data Name='TargetLogonId'>{logon_id}</Data>"
        f"<Data Name='LogonType'>{logon_type}</Data>"
        f"<Data Name='LogonProcessName'>{logon_process}</Data>"
        f"<Data Name='AuthenticationPackageName'>{auth_package}</Data>"
        f"<Data Name='WorkstationName'>{workstation}</Data>"
        f"<Data Name='LogonGuid'>{{00000000-0000-0000-0000-000000000000}}</Data>"
        f"<Data Name='TransmittedServices'>-</Data>"
        f"<Data Name='LmPackageName'>-</Data>"
        f"<Data Name='KeyLength'>0</Data>"
        f"<Data Name='ProcessId'>0x0</Data>"
        f"<Data Name='ProcessName'>-</Data>"
        f"<Data Name='IpAddress'>{ip_address}</Data>"
        f"<Data Name='IpPort'>{ip_port}</Data>"
        f"</EventData>"
        f"</Event>"
    )


def _win_sec_eid4688(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 4688 — A new process has been created."""
    proc = ecs_event.get("process", {})
    parent = proc.get("parent", {})
    user = ecs_event.get("user", {})
    ed = ecs_event.get("winlog", {}).get("event_data", {})

    subject_username = user.get("name", ed.get("SubjectUserName", "-"))
    subject_domain = user.get("domain", ed.get("SubjectDomainName", "-"))
    new_process_id = ed.get("NewProcessId", _get(proc, "pid") or "0x0")
    new_process_name = _get(proc, "executable") or ed.get("NewProcessName", "-")
    token_elevation = ed.get("TokenElevationType", "%%1938")
    creator_process_id = ed.get("CreatorProcessId", _get(parent, "pid") or "0x0")
    creator_process_name = _get(parent, "executable") or ed.get("CreatorProcessName", "-")
    process_cmd_line = _get(proc, "command_line") or ed.get("CommandLine", "")

    # Format pid as hex if it's a plain integer string
    def _maybe_hex(val: str) -> str:
        try:
            return hex(int(val))
        except (ValueError, TypeError):
            return val or "0x0"

    return (
        f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System>"
        f"<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>"
        f"<EventID>4688</EventID>"
        f"<Version>2</Version>"
        f"<Level>0</Level>"
        f"<Task>13312</Task>"
        f"<Opcode>0</Opcode>"
        f"<Keywords>0x8020000000000000</Keywords>"
        f"<TimeCreated SystemTime='{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}0Z'/>"
        f"<EventRecordID>{abs(hash(str(ts))) % 1000000}</EventRecordID>"
        f"<Correlation/>"
        f"<Execution ProcessID='4' ThreadID='8'/>"
        f"<Channel>Security</Channel>"
        f"<Computer>{_get(ecs_event, 'host', 'name') or 'WORKSTATION-01'}</Computer>"
        f"<Security/>"
        f"</System>"
        f"<EventData>"
        f"<Data Name='SubjectUserSid'>S-1-5-21-0000000000-0000000000-0000000000-1001</Data>"
        f"<Data Name='SubjectUserName'>{subject_username}</Data>"
        f"<Data Name='SubjectDomainName'>{subject_domain}</Data>"
        f"<Data Name='SubjectLogonId'>0x3e7</Data>"
        f"<Data Name='NewProcessId'>{_maybe_hex(str(new_process_id))}</Data>"
        f"<Data Name='NewProcessName'>{new_process_name}</Data>"
        f"<Data Name='TokenElevationType'>{token_elevation}</Data>"
        f"<Data Name='ProcessId'>{_maybe_hex(str(creator_process_id))}</Data>"
        f"<Data Name='CommandLine'>{process_cmd_line}</Data>"
        f"<Data Name='TargetUserSid'>S-1-0-0</Data>"
        f"<Data Name='TargetUserName'>-</Data>"
        f"<Data Name='TargetDomainName'>-</Data>"
        f"<Data Name='TargetLogonId'>0x0</Data>"
        f"<Data Name='ParentProcessName'>{creator_process_name}</Data>"
        f"<Data Name='MandatoryLabel'>S-1-16-8192</Data>"
        f"</EventData>"
        f"</Event>"
    )


def _win_sec_eid7045(ecs_event: dict, ts: datetime.datetime) -> str:
    """EID 7045 — A new service was installed in the system."""
    ed = ecs_event.get("winlog", {}).get("event_data", {})
    service = ecs_event.get("service", {})

    service_name = (
        ed.get("ServiceName", "")
        or _get(service, "name")
        or _get(ecs_event, "process", "name")
    )
    service_file_name = (
        ed.get("ServiceFileName", "")
        or _get(service, "type")
        or _get(ecs_event, "process", "executable")
    )
    service_type = ed.get("ServiceType", "user mode service")
    start_type = ed.get("StartType", "demand start")
    account_name = (
        ed.get("AccountName", "")
        or _get(ecs_event, "user", "name")
        or "LocalSystem"
    )

    return (
        f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System>"
        f"<Provider Name='Service Control Manager' Guid='{{555908D1-A6D7-4695-8E1E-26931D2012F4}}'"
        f" EventSourceName='Service Control Manager'/>"
        f"<EventID Qualifiers='16384'>7045</EventID>"
        f"<Version>0</Version>"
        f"<Level>4</Level>"
        f"<Task>0</Task>"
        f"<Opcode>0</Opcode>"
        f"<Keywords>0x8080000000000000</Keywords>"
        f"<TimeCreated SystemTime='{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}0Z'/>"
        f"<EventRecordID>{abs(hash(str(ts))) % 1000000}</EventRecordID>"
        f"<Correlation/>"
        f"<Execution ProcessID='4' ThreadID='8'/>"
        f"<Channel>System</Channel>"
        f"<Computer>{_get(ecs_event, 'host', 'name') or 'WORKSTATION-01'}</Computer>"
        f"<Security UserID='S-1-5-18'/>"
        f"</System>"
        f"<EventData>"
        f"<Data Name='ServiceName'>{service_name}</Data>"
        f"<Data Name='ServiceFileName'>{service_file_name}</Data>"
        f"<Data Name='ServiceType'>{service_type}</Data>"
        f"<Data Name='StartType'>{start_type}</Data>"
        f"<Data Name='AccountName'>{account_name}</Data>"
        f"</EventData>"
        f"</Event>"
    )


# Dispatch table for Windows Security events
_WIN_SEC_DISPATCH: dict[str, tuple] = {
    "4624": (_win_sec_eid4624, "XmlWinEventLog:Security",
                               "WinEventLog:Security"),
    "4688": (_win_sec_eid4688, "XmlWinEventLog:Security",
                               "WinEventLog:Security"),
    "7045": (_win_sec_eid7045, "XmlWinEventLog:System",
                               "WinEventLog:System"),
}


def ecs_to_raw_windows_security(ecs_event: dict) -> dict:
    """
    Convert a Windows Security/System ECS event to a raw Windows Event XML HEC envelope.

    Supported EIDs: 4624 (Logon), 4688 (Process Create), 7045 (Service Install).

    For unsupported EIDs a minimal XML stub is produced; no exception is raised.

    Args:
        ecs_event: A single ECS event dictionary.

    Returns:
        HEC envelope dict with keys: ``event``, ``sourcetype``, ``host``,
        ``source``, ``time``, ``_simulation``.

    Raises:
        TypeError: If ``ecs_event`` is not a dict.
    """
    if not isinstance(ecs_event, dict):
        raise TypeError(
            f"ecs_to_raw_windows_security expects dict, got {type(ecs_event).__name__}"
        )

    ts = _parse_timestamp(ecs_event)
    event_code = str(ecs_event.get("event", {}).get("code", "")).strip()
    host = _get(ecs_event, "host", "name") or "WORKSTATION-01"

    entry = _WIN_SEC_DISPATCH.get(event_code)
    if entry:
        converter_fn, sourcetype, source = entry
        raw_text = converter_fn(ecs_event, ts)
    else:
        # Graceful fallback
        raw_text = (
            f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><EventID>{event_code or '0'}</EventID>"
            f"<TimeCreated SystemTime='{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}0Z'/>"
            f"<Computer>{host}</Computer></System>"
            f"<EventData/></Event>"
        )
        sourcetype = "XmlWinEventLog:Security"
        source = "WinEventLog:Security"

    return _hec_envelope(raw_text, sourcetype, source, host, ts, ecs_event)


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

# Sysmon EIDs that this module handles
_SYSMON_EIDS = frozenset(_SYSMON_DISPATCH.keys())

# Windows Security / System EIDs
_WIN_SEC_EIDS = frozenset(_WIN_SEC_DISPATCH.keys())

# Additional Windows Security EIDs that we fall back on even without a dedicated template
_WIN_SEC_EID_RANGE = frozenset(str(i) for i in range(4600, 5000)) | {"7045", "7036", "7034"}


def ecs_to_raw(ecs_event: dict) -> dict:
    """
    Dispatcher: routes an ECS event to the correct raw-format converter.

    Routing logic:
    1. If ``agent.type == "sysmon"`` → ``ecs_to_raw_sysmon``
    2. If ``event.code`` is a known Windows Security/System EID → ``ecs_to_raw_windows_security``
    3. If ``event.code`` is in the 4600-4999 range → ``ecs_to_raw_windows_security``
    4. Otherwise → ``ecs_to_raw_sysmon`` (best-effort, produces a fallback envelope)

    The ``_simulation`` metadata block is preserved in the returned envelope so
    that downstream TP/FP scoring works correctly.

    Args:
        ecs_event: A single ECS event dictionary.

    Returns:
        HEC envelope dict with keys: ``event``, ``sourcetype``, ``host``,
        ``source``, ``time``, ``_simulation``.

    Raises:
        TypeError: If ``ecs_event`` is not a dict.
    """
    if not isinstance(ecs_event, dict):
        raise TypeError(f"ecs_to_raw expects dict, got {type(ecs_event).__name__}")

    agent_type = _get(ecs_event, "agent", "type").lower()
    event_code = str(ecs_event.get("event", {}).get("code", "")).strip()

    if agent_type == "sysmon" or event_code in _SYSMON_EIDS:
        # Prefer Sysmon converter when agent.type is explicitly sysmon OR
        # the EID is exclusively a Sysmon EID (1, 3, 7, 8, 10, 11, 13, 17, 18, 22).
        if agent_type == "sysmon" and event_code not in _SYSMON_EIDS and event_code in _WIN_SEC_EIDS:
            # Edge case: sysmon agent but a Security EID — route to Windows Security
            return ecs_to_raw_windows_security(ecs_event)
        return ecs_to_raw_sysmon(ecs_event)

    if event_code in _WIN_SEC_EIDS or event_code in _WIN_SEC_EID_RANGE:
        return ecs_to_raw_windows_security(ecs_event)

    # Unknown / generic — fall back to Sysmon envelope with minimal content
    return ecs_to_raw_sysmon(ecs_event)


# ---------------------------------------------------------------------------
# Scenario converter
# ---------------------------------------------------------------------------

def convert_scenario_to_raw(scenario: dict) -> dict:
    """
    Convert all ECS events in a scenario dict to raw HEC format.

    Processes ``events.attack_sequence`` and ``events.benign_similar`` arrays
    in-place (in a deep copy), converting each event via ``ecs_to_raw``.

    The top-level scenario metadata (``technique_id``, ``technique_name``,
    ``mitre_tactic``, ``expected_detection``, ``log_sources_used``,
    ``platforms``) is preserved unchanged.

    Args:
        scenario: A scenario dict as loaded from ``simulator/scenarios/*.json``.
            Must contain an ``events`` key with sub-keys ``attack_sequence``
            and/or ``benign_similar``.

    Returns:
        A new dict (the original is not mutated) with the same structure but
        all events replaced by HEC envelope dicts.

    Raises:
        TypeError: If ``scenario`` is not a dict or if any event in the arrays
            is not a dict.
        KeyError: If the ``events`` key is missing from ``scenario``.

    Example::

        import json
        from simulator.raw_events import convert_scenario_to_raw

        with open("simulator/scenarios/t1055_001.json") as f:
            scenario = json.load(f)

        raw_scenario = convert_scenario_to_raw(scenario)
        # raw_scenario["events"]["attack_sequence"][0]["event"] → Sysmon text
    """
    if not isinstance(scenario, dict):
        raise TypeError(f"convert_scenario_to_raw expects dict, got {type(scenario).__name__}")

    if "events" not in scenario:
        raise KeyError("scenario dict must contain an 'events' key")

    # Shallow copy of top-level; deep copy the events section only
    result = {k: v for k, v in scenario.items() if k != "events"}
    events_section = scenario["events"]

    raw_events_section: dict = {}

    for list_key in ("attack_sequence", "benign_similar"):
        source_list = events_section.get(list_key, [])
        if not isinstance(source_list, list):
            raw_events_section[list_key] = source_list
            continue

        converted: list[dict] = []
        for idx, ev in enumerate(source_list):
            if not isinstance(ev, dict):
                raise TypeError(
                    f"events.{list_key}[{idx}] must be a dict, got {type(ev).__name__}"
                )
            try:
                converted.append(ecs_to_raw(ev))
            except Exception as exc:  # noqa: BLE001
                # Wrap with context so the caller knows which event failed
                raise RuntimeError(
                    f"Failed to convert events.{list_key}[{idx}]: {exc}"
                ) from exc
        raw_events_section[list_key] = converted

    # Preserve any other keys in the events section (e.g. future extensions)
    for key in events_section:
        if key not in ("attack_sequence", "benign_similar"):
            raw_events_section[key] = events_section[key]

    result["events"] = raw_events_section
    return result


# ---------------------------------------------------------------------------
# CLI convenience (for quick smoke-testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys

    if len(_sys.argv) < 2:
        print(
            "Usage: python -m simulator.raw_events <scenario.json>\n"
            "Converts all events in the scenario to raw HEC format and prints them.",
            file=_sys.stderr,
        )
        _sys.exit(1)

    path = _sys.argv[1]
    with open(path, encoding="utf-8") as _f:
        _scenario = json.load(_f)

    _raw_scenario = convert_scenario_to_raw(_scenario)

    for _list_key in ("attack_sequence", "benign_similar"):
        _events = _raw_scenario["events"].get(_list_key, [])
        for _i, _ev in enumerate(_events):
            print(f"\n--- {_list_key}[{_i}] ({_ev.get('sourcetype', '')}) ---")
            print(_ev.get("event", ""))
