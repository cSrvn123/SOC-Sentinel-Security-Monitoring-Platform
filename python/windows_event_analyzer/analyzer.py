"""Parse, normalize, and produce cautious triage observations for event JSON."""

from __future__ import annotations

import ipaddress
import json
import ntpath
import re
import copy
from datetime import datetime, timedelta, timezone
from collections.abc import Mapping, Sequence
from typing import Any, Optional

from .models import AnalysisReport, NormalizedEvent


class EventInputError(ValueError):
    """Safe input error that never includes the supplied event contents."""


_EVENT_TYPES = {
    ("Windows Security", 4624): "Successful logon",
    ("Windows Security", 4625): "Failed logon",
    ("Sysmon", 1): "Process creation",
    ("Sysmon", 3): "Network connection",
    ("Sysmon", 22): "DNS query",
}
_KEY_RE = re.compile(r"[^a-z0-9]")
_SUSPICIOUS_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"
}
_OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
_PRIVATE_IP_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
# Stable guards for commonly encountered non-global special-purpose space.
# ipaddress.is_global/is_private have received classification corrections in
# patch and minor releases, so these ranges must never become global merely
# because a runtime's embedded registry table is older.
_SPECIAL_PURPOSE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "64:ff9b:1::/48",
        "100::/64",
        "100:0:0:1::/64",
        "2001::/23",
        "2001:2::/48",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    )
)
_GLOBALLY_REACHABLE_SPECIAL_EXCEPTIONS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "192.0.0.9/32",
        "192.0.0.10/32",
        "2001:1::1/128",
        "2001:1::2/128",
        "2001:1::3/128",
        "2001:3::/32",
        "2001:4:112::/48",
        "2001:20::/28",
        "2001:30::/28",
    )
)


def _key(value: object) -> str:
    return _KEY_RE.sub("", str(value).casefold())


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _scalar(value: object) -> Optional[str]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        result = str(value).strip()
        return result if result and result != "-" else None
    if isinstance(value, Mapping):
        for name in ("#text", "text", "value", "@SystemTime", "SystemTime", "@Name", "Name"):
            result = _scalar(value.get(name))
            if result:
                return result
    return None


def _read(mapping: Mapping[str, Any], *names: str) -> Optional[str]:
    normalized = {_key(k): v for k, v in mapping.items()}
    for name in names:
        value = _scalar(normalized.get(_key(name)))
        if value:
            return value
    return None


def _child(mapping: Mapping[str, Any], *names: str) -> Mapping[str, Any]:
    normalized = {_key(k): v for k, v in mapping.items()}
    for name in names:
        result = normalized.get(_key(name))
        if isinstance(result, Mapping):
            return result
    return {}


def _event_data(record: Mapping[str, Any], event_root: Mapping[str, Any], win: Mapping[str, Any]) -> dict[str, Any]:
    raw: object = None
    for parent in (win, event_root, record):
        raw = next((v for k, v in parent.items() if _key(k) in {"eventdata", "data"}), None)
        if raw is not None:
            break
    if isinstance(raw, Mapping):
        data = dict(raw)
        items = next((v for k, v in raw.items() if _key(k) == "data"), None)
        if isinstance(items, list):
            for item in items:
                entry = _mapping(item)
                name = _read(entry, "Name", "@Name")
                value = _read(entry, "#text", "Value", "Data")
                if name and value is not None:
                    data[name] = value
        return data
    if isinstance(raw, list):
        data = {}
        for item in raw:
            entry = _mapping(item)
            name = _read(entry, "Name", "@Name")
            value = _read(entry, "#text", "Value", "Data")
            if name and value is not None:
                data[name] = value
        return data
    return {}


def _event_id(system: Mapping[str, Any], record: Mapping[str, Any], event_root: Mapping[str, Any]) -> Optional[int]:
    raw = _read(system, "EventID", "EventId", "event_id")
    if raw is None:
        raw = _read(event_root, "EventID", "EventId", "event_id") or _read(record, "EventID", "EventId", "event_id")
    if raw is None:
        return None
    try:
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
    except ValueError:
        return None


def _provider_name(system: Mapping[str, Any], record: Mapping[str, Any], event_root: Mapping[str, Any]) -> Optional[str]:
    provider = _child(system, "Provider")
    return (
        _read(system, "providerName", "provider", "source")
        or _read(provider, "Name", "@Name")
        or _read(event_root, "providerName", "provider", "source")
        or _read(record, "providerName", "provider", "source", "event_source")
    )


def _source_kind(provider: Optional[str]) -> Optional[str]:
    if not provider:
        return None
    lowered = provider.casefold()
    if "sysmon" in lowered:
        return "Sysmon"
    if "security" in lowered or "auditing" in lowered:
        return "Windows Security"
    return None


def _parse_record(raw_record: object, index: int) -> tuple[Optional[NormalizedEvent], Optional[str]]:
    record = _mapping(raw_record)
    if not isinstance(raw_record, Mapping):
        return None, f"Record {index}: expected a JSON object."
    event_root = _child(record, "Event") or record
    win = _child(record, "win")
    system = _child(win, "system") or _child(event_root, "System") or _child(record, "System")
    event_id = _event_id(system, record, event_root)
    provider = _provider_name(system, record, event_root)
    source = _source_kind(provider)
    if event_id is None or source is None:
        return None, f"Record {index}: missing or unsupported event source/ID."
    event_type = _EVENT_TYPES.get((source, event_id))
    if event_type is None:
        return None, f"Record {index}: unsupported {source} event ID {event_id}."

    data = _event_data(record, event_root, win)
    maps = (data, system, event_root, record)

    def field(*aliases: str) -> Optional[str]:
        for item in maps:
            found = _read(item, *aliases)
            if found:
                return found
        return None

    time_created = _child(system, "TimeCreated") or _child(event_root, "TimeCreated")
    timestamp = field("timestamp", "timeCreated", "systemTime", "UtcTime") or _read(time_created, "SystemTime", "@SystemTime")
    computer = field("computer", "hostname", "host", "ComputerName")
    if source == "Windows Security":
        username = field("TargetUserName", "SubjectUserName", "UserName", "username", "user")
        source_ip = field("IpAddress", "SourceIp", "SourceNetworkAddress", "source_ip")
    else:
        username = field("User", "UserName", "username", "user")
        source_ip = field("SourceIp", "SourceAddress", "source_ip")
    destination_ip = field("DestinationIp", "DestinationAddress", "destination_ip")
    process_path = field("Image", "ProcessImage", "process_path", "process_image")
    process_name = (ntpath.basename(process_path.replace("/", "\\")) if process_path
                    else field("ProcessName", "process_name"))
    process_id = field("ProcessId", "ProcessID", "process_id")
    parent_process = field("ParentImage", "ParentProcessName", "parent_process", "ParentProcess")
    command_line = field("CommandLine", "command_line")
    dns_query = field("QueryName", "Query", "dns_query", "query_name")

    return NormalizedEvent(timestamp, computer, source, event_id, event_type, username,
        source_ip, destination_ip, process_name, process_path, process_id,
        parent_process, command_line, dns_query), None


def _timestamp_utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _normalized_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value).compressed.casefold()
    except ValueError:
        return None


def _failed_logon_observations(
    events: list[NormalizedEvent], threshold: int, window: timedelta
) -> None:
    grouped: dict[tuple[str, Optional[str], Optional[str]], list[tuple[datetime, int, NormalizedEvent]]] = {}
    for event in events:
        if event.event_id != 4625:
            continue
        event.observations.append("Failed logon observed; review the account, source, and authentication context.")
        if not event.computer:
            event.observations.append(
                "Repeated failed-logon correlation skipped because computer/hostname identity is missing."
            )
            continue
        timestamp = _timestamp_utc(event.timestamp)
        if timestamp is None:
            reason = "missing" if not event.timestamp else "invalid or timezone-naive"
            event.observations.append(
                f"Not included in confirmed time-window correlation because the timestamp is {reason}; an explicit UTC offset is required."
            )
            continue
        username = event.username.casefold() if event.username else None
        source_ip = _normalized_ip(event.source_ip)
        if username is None and source_ip is None:
            event.observations.append(
                "Not grouped for repeated-logon analysis because both account and source IP are missing."
            )
            continue
        key = (event.computer.casefold(), username, source_ip)
        grouped.setdefault(key, []).append((timestamp, id(event), event))

    for entries in grouped.values():
        entries.sort(key=lambda item: item[0])
        left = 0
        for right, (end_time, _identity, _event) in enumerate(entries):
            while end_time - entries[left][0] > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                start_time = entries[left][0]
                account = entries[right][2].username or "(account unavailable)"
                source_ip = entries[right][2].source_ip or "(source IP unavailable)"
                explanation = (
                    f"Repeated failed-logon heuristic: {count} Event ID 4625 records for account {account} "
                    f"and source IP {source_ip} meet threshold {threshold} within {window.total_seconds():g} seconds "
                    f"({start_time.isoformat()} through {end_time.isoformat()} UTC). This is an investigation prompt."
                )
                for _, _, matched_event in entries[left:right + 1]:
                    if explanation not in matched_event.observations:
                        matched_event.observations.append(explanation)


def _process_observations(event: NormalizedEvent) -> None:
    if event.event_id != 1:
        return
    path = (event.process_path or "").replace("/", "\\").casefold()
    writable_markers = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "\\windows\\temp\\")
    if any(marker in path for marker in writable_markers):
        event.observations.append("Process image is under a commonly user-writable location; verify expected software and launch context.")
    parent_name = ntpath.basename((event.parent_process or "").replace("/", "\\")).casefold()
    if parent_name in _OFFICE_PARENTS and (event.process_name or "").casefold() in _SUSPICIOUS_CHILDREN:
        event.observations.append("Office application launched a command or script interpreter; validate business context and parent-child activity.")


def _address_in_networks(address: ipaddress.IPv4Address | ipaddress.IPv6Address, networks: tuple[Any, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _destination_address_type(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify address scope/type without treating it as a threat verdict.

    Explicit type checks precede ``is_global`` because multicast and special
    ranges are not ordinary globally routable unicast. Explicit private and
    special-purpose networks also reduce dependence on ipaddress table changes
    across Python versions; unknown non-global ranges fail closed as special.
    """
    if address.is_loopback:
        return "loopback"
    if address.is_unspecified:
        return "unspecified"
    if address.is_multicast:
        return "IPv4 multicast" if address.version == 4 else "IPv6 multicast"
    if address.is_link_local:
        return "link-local"
    if _address_in_networks(address, _PRIVATE_IP_NETWORKS):
        return "private"
    if _address_in_networks(address, _GLOBALLY_REACHABLE_SPECIAL_EXCEPTIONS):
        return "globally routable unicast"
    if _address_in_networks(address, _SPECIAL_PURPOSE_NETWORKS):
        return "reserved/special-purpose"
    if address.is_reserved or not address.is_global:
        return "reserved/special-purpose"
    return "globally routable unicast"


def classify_ip_address(value: str | None) -> str | None:
    """Return the analyzer's address-type label, or ``None`` for invalid input.

    This describes address scope/type only. It does not assess reputation or
    decide whether observed network activity is benign or malicious.
    """
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return _destination_address_type(address)


def _network_observations(event: NormalizedEvent) -> None:
    if event.event_id != 3 or not event.destination_ip:
        return
    address_type = classify_ip_address(event.destination_ip)
    if address_type is None:
        return
    if address_type == "globally routable unicast":
        event.observations.append(
            "Network event destination is a globally routable unicast IP; review destination, process, and expected network behavior."
        )
    else:
        event.observations.append(
            f"Network event destination is {address_type}; address type alone does not determine whether the activity is benign or malicious."
        )


def _dns_observations(event: NormalizedEvent) -> None:
    if event.event_id != 22 or not event.dns_query:
        return
    query = event.dns_query.rstrip(".").casefold()
    labels = query.split(".")
    reasons = []
    if "xn--" in labels:
        reasons.append("contains an IDN/punycode label")
    if len(labels) >= 6:
        reasons.append("has many subdomain labels")
    if any(len(label) >= 50 for label in labels):
        reasons.append("has a very long DNS label")
    if reasons:
        event.observations.append("DNS query has a heuristic review signal (" + ", ".join(reasons) + "); this is not a maliciousness verdict.")


def analyze_records(
    records: object,
    failed_logon_threshold: int = 3,
    failed_logon_window: timedelta = timedelta(minutes=5),
) -> AnalysisReport:
    """Normalize supported records and attach cautious, batch-aware observations."""
    if isinstance(failed_logon_threshold, bool) or not isinstance(failed_logon_threshold, int) or failed_logon_threshold < 1:
        raise ValueError("failed_logon_threshold must be a positive integer.")
    if not isinstance(failed_logon_window, timedelta) or failed_logon_window.total_seconds() <= 0:
        raise ValueError("failed_logon_window must be a positive timedelta.")
    if isinstance(records, Mapping):
        items: list[object] = [records]
    elif isinstance(records, Sequence) and not isinstance(records, (str, bytes, bytearray)):
        items = list(records)
    else:
        raise EventInputError("Input must be a JSON object or an array of event objects.")
    events: list[NormalizedEvent] = []
    issues: list[str] = []
    event_record_indices: list[int] = []
    for index, raw_record in enumerate(items, start=1):
        event, issue = _parse_record(raw_record, index)
        if event:
            events.append(event)
            event_record_indices.append(index - 1)
        if issue:
            issues.append(issue)
    _failed_logon_observations(events, failed_logon_threshold, failed_logon_window)
    for event in events:
        _process_observations(event)
        _network_observations(event)
        _dns_observations(event)
    return AnalysisReport(len(items), events, issues, copy.deepcopy(items), event_record_indices)


def analyze_json(
    source: str | bytes | bytearray,
    failed_logon_threshold: int = 3,
    failed_logon_window: timedelta = timedelta(minutes=5),
) -> AnalysisReport:
    """Parse JSON text safely and analyze one event or a batch of events."""
    try:
        payload = json.loads(source)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        raise EventInputError("Input is not valid JSON.") from None
    return analyze_records(payload, failed_logon_threshold, failed_logon_window)
