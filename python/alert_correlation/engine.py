"""Conservative, offline correlation for normalized SOC Sentinel event records."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlsplit

from windows_event_analyzer.analyzer import analyze_records
from windows_event_analyzer.models import AnalysisReport, NormalizedEvent

from .models import CorrelationReport, InvestigationCase


@dataclass(frozen=True)
class CorrelationConfig:
    failed_logon_threshold: int = 3
    failed_to_success_window: timedelta = timedelta(minutes=10)
    logon_to_process_window: timedelta = timedelta(minutes=10)

    def __post_init__(self) -> None:
        if (isinstance(self.failed_logon_threshold, bool)
                or not isinstance(self.failed_logon_threshold, int)
                or self.failed_logon_threshold < 1):
            raise ValueError("failed_logon_threshold must be a positive integer")
        for name in ("failed_to_success_window", "logon_to_process_window"):
            value = getattr(self, name)
            if not isinstance(value, timedelta) or value.total_seconds() <= 0:
                raise ValueError(f"{name} must be a positive timedelta")


@dataclass
class _Prepared:
    event: NormalizedEvent
    timestamp: datetime
    references: list[str]
    source_identity: Optional[str]
    original_record: Optional[object]
    original_candidates: list[object] = field(default_factory=list)
    provenance_status: str = "unavailable"
    event_index: int = -1


@dataclass
class _Association:
    original_record: Optional[object]
    candidates: list[object]
    source_identity: Optional[str]
    raw_content_key: Optional[Any]
    status: str


def _utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    raw = value.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _norm_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value).compressed.casefold()
    except ValueError:
        return None


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _normalized_text(value: Optional[str], *, case_sensitive: bool = False) -> Optional[str]:
    if value is None:
        return None
    result = value.strip()
    return result if case_sensitive else result.casefold()


def _timestamp_key(value: Optional[str]) -> Optional[str]:
    parsed = _utc(value)
    return parsed.isoformat() if parsed else _normalized_text(value, case_sensitive=True)


def _event_fingerprint(event: NormalizedEvent) -> tuple[Any, ...]:
    """Return normalized event meaning for source association and duplicate checks.

    Analyzer observations are excluded because batch context can change them without
    changing the source event. Command lines remain case-sensitive because argument
    values are not universally case-insensitive.
    """
    return (
        _normalized_text(event.event_source), event.event_id, _normalized_text(event.event_type),
        _timestamp_key(event.timestamp), _normalized_text(event.computer), _normalized_text(event.username),
        _normalized_text(_norm_ip(event.source_ip) or event.source_ip),
        _normalized_text(_norm_ip(event.destination_ip) or event.destination_ip),
        _normalized_text(event.process_name), _normalized_text(event.process_path),
        _normalized_text(event.process_id), _normalized_text(event.parent_process),
        _normalized_text(event.command_line, case_sensitive=True), _normalized_text(event.dns_query),
    )


def _normalized_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_child(mapping: Mapping[str, Any], *names: str) -> Mapping[str, Any]:
    folded = {"".join(char for char in str(key).casefold() if char.isalnum()): value
              for key, value in mapping.items()}
    for name in names:
        value = folded.get("".join(char for char in name.casefold() if char.isalnum()))
        if isinstance(value, Mapping):
            return value
    return {}


def _mapping_value(mapping: Mapping[str, Any], *names: str) -> Any:
    folded = {"".join(char for char in str(key).casefold() if char.isalnum()): value
              for key, value in mapping.items()}
    for name in names:
        value = folded.get("".join(char for char in name.casefold() if char.isalnum()))
        if isinstance(value, Mapping):
            for leaf in ("#text", "text", "value", "@name", "name"):
                if leaf in value:
                    value = value[leaf]
                    break
        if value is not None and not isinstance(value, (dict, list)):
            text = str(value).strip()
            if text and text != "-":
                return text
    return None


def _source_identity(raw_record: object, event: NormalizedEvent) -> Optional[str]:
    root = _normalized_mapping(raw_record)
    win = _mapping_child(root, "win")
    system = _mapping_child(win, "system")
    if not system:
        event_root = _mapping_child(root, "Event")
        system = _mapping_child(event_root, "System")
    if not system:
        system = _mapping_child(root, "System")
    channel = (_mapping_value(system, "channel") or _mapping_value(root, "channel"))
    record_id = (_mapping_value(system, "eventRecordID", "recordId", "record_id")
                 or _mapping_value(root, "eventRecordID", "recordId", "record_id"))
    computer = _text(event.computer)
    if not (computer and channel and record_id):
        return None
    record_id = record_id.strip()
    if record_id.isascii() and record_id.isdecimal():
        record_id = str(int(record_id, 10))
    # JSON encoding keeps component boundaries unambiguous, even for unusual names.
    return json.dumps((event.event_source.casefold(), computer.casefold(), channel.casefold(), record_id.casefold()),
                      ensure_ascii=True, separators=(",", ":"))


_RAW_KNOWN_KEYS = {
    "source", "eventsource", "eventid", "eventtype", "win", "system", "event", "provider",
    "providername", "name", "eventdata", "data", "channel", "eventrecordid", "recordid",
    "computer", "hostname", "host", "timecreated", "systemtime", "timestamp", "utctime",
    "targetusername", "subjectusername", "username", "user", "ipaddress", "sourceip",
    "sourcenetworkaddress", "sourceaddress", "destinationip", "destinationaddress", "image",
    "processimage", "processpath", "processname", "processid", "parentimage", "parentprocessname",
    "parentprocess", "parentprocessid", "commandline", "queryname", "query", "dnsquery", "processguid",
    "parentprocessguid", "activityid", "logontype", "destinationport", "sourceport", "hashes",
    "targetdomainname", "subjectdomainname", "subjectusersid", "targetusersid", "subjectlogonid",
    "targetlogonid", "#text", "text", "value", "@systemtime", "@name", "qualifiers",
}
_RAW_CASEFOLD_VALUES = {
    "eventsource", "eventtype", "providername", "channel", "computer", "hostname",
    "host", "targetusername", "subjectusername", "username", "user", "image", "processimage",
    "processpath", "processname", "parentimage", "parentprocessname", "parentprocess", "queryname",
    "query", "dnsquery", "processguid", "parentprocessguid", "activityid", "targetdomainname",
    "subjectdomainname", "subjectusersid", "targetusersid", "subjectlogonid", "targetlogonid",
}
_RAW_IP_KEYS = {"ipaddress", "sourceip", "sourcenetworkaddress", "sourceaddress", "destinationip", "destinationaddress"}
_RAW_TIME_KEYS = {"timestamp", "systemtime", "utctime"}
_RAW_NUMERIC_KEYS = {"eventid", "eventrecordid", "recordid", "logontype", "processid", "parentprocessid", "destinationport", "sourceport"}
MAX_EVIDENCE_DEPTH = 128


def _raw_key_token(key: Any) -> str:
    return "".join(char for char in str(key).casefold() if char.isalnum())


_XML_SCALAR_LEAF_TOKENS = {"text", "value", "systemtime", "name"}


def _canonical_raw_payload(
    value: Any,
    key_token: Optional[str] = None,
    active: Optional[set[int]] = None,
    parent_token: Optional[str] = None,
) -> Any:
    """Canonicalize a complete source payload conservatively for duplicate comparison.

    Only known Windows/event representation fields receive case, IP, timestamp, or
    numeric-format normalization. Unknown keys and values retain their distinctions.
    """
    active = active if active is not None else set()
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            return ("circular", identity)
        active.add(identity)
        # Unwrap only mappings made entirely of recognized scalar leaf keys whose
        # values agree after the field-specific canonicalization below. Do not use a
        # normalized-key dictionary here: XML aliases such as #text and text can
        # coexist, and every supplied value must participate in the comparison.
        if key_token in _RAW_KNOWN_KEYS and key_token != "timecreated":
            leaf_values = []
            only_known_leaves = bool(value)
            for leaf_key, leaf_value in value.items():
                if _raw_key_token(leaf_key) not in _XML_SCALAR_LEAF_TOKENS:
                    only_known_leaves = False
                    break
                if leaf_value is not None and not isinstance(leaf_value, (str, int, float, bool)):
                    only_known_leaves = False
                    break
                leaf_values.append(leaf_value)
            same_raw_scalar = (leaf_values and all(type(item) is type(leaf_values[0]) and item == leaf_values[0]
                                                   for item in leaf_values[1:]))
            if only_known_leaves and leaf_values and same_raw_scalar:
                result = _canonical_raw_payload(leaf_values[0], key_token, active, parent_token)
                active.remove(identity)
                return result
        entries = []
        for key, item in value.items():
            raw_token = _raw_key_token(key)
            if raw_token in {"win", "event"}:
                # These are alternate supported envelope shapes for the same event.
                canonical_key = "eventcontainer"
            else:
                canonical_key = raw_token if raw_token in _RAW_KNOWN_KEYS else (type(key).__name__, key)
            entries.append((canonical_key, _canonical_raw_payload(item, raw_token, active, key_token)))
        active.remove(identity)
        return ("mapping", tuple(sorted(entries, key=repr)))
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active:
            return ("circular", identity)
        active.add(identity)
        container_type = "list" if isinstance(value, list) else "tuple"
        result = (container_type, tuple(_canonical_raw_payload(item, None, active, parent_token) for item in value))
        active.remove(identity)
        return result
    if isinstance(value, str):
        stripped = value.strip()
        if key_token in _RAW_TIME_KEYS:
            return ("timestamp", _timestamp_key(stripped))
        if key_token in _RAW_NUMERIC_KEYS:
            try:
                base = 16 if key_token == "eventid" and stripped.lower().startswith("0x") else 10
                return ("number", int(stripped, base))
            except ValueError:
                return ("string", value)
        if key_token in _RAW_CASEFOLD_VALUES or (key_token == "source" and parent_token is None) or (key_token == "name" and parent_token == "provider"):
            return ("text", stripped.casefold())
        if key_token in _RAW_IP_KEYS:
            normalized_ip = _norm_ip(stripped)
            return ("ip", normalized_ip) if normalized_ip else ("string", value)
        return ("string", value)
    if isinstance(value, bool) or value is None:
        return (type(value).__name__, value)
    if isinstance(value, int):
        return ("number", value) if key_token in _RAW_NUMERIC_KEYS else ("integer", value)
    if isinstance(value, float):
        if key_token in _RAW_NUMERIC_KEYS and math.isfinite(value) and value.is_integer():
            return ("number", int(value))
        return ("float", value)
    # JSON event inputs should normally be mappings/lists/scalars. Preserve unsupported
    # values conservatively instead of equating distinct objects by their display text.
    return ("unsupported", type(value).__module__, type(value).__qualname__, id(value))


def _raw_records_equal(left: object, right: object) -> bool:
    try:
        result = left == right
        return result if isinstance(result, bool) else bool(result)
    except Exception:
        return False


def _content_digest(content: tuple[Any, ...]) -> str:
    encoded = json.dumps(content, ensure_ascii=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _raw_event_candidates(raw_records: list[object]) -> dict[tuple[Any, ...], list[tuple[object, NormalizedEvent]]]:
    candidates: dict[tuple[Any, ...], list[tuple[object, NormalizedEvent]]] = {}
    for raw_index, raw_record in enumerate(raw_records):
        if not isinstance(raw_record, Mapping):
            continue
        # Normalize each original row independently. Association below uses candidate
        # cardinality and complete raw content, never positional queue consumption.
        parsed = analyze_records(raw_record)
        for event in parsed.events:
            candidates.setdefault(_event_fingerprint(event), []).append((raw_record, event))
    return candidates


def _register_skipped_event(
    skipped_events: list[dict[str, Any]],
    diagnostics: list[str],
    *,
    event_index: int,
    event_id: Any,
    event_source: Any,
    reason: str,
    provenance_status: Optional[str] = None,
) -> None:
    """Record one event-level exclusion, merging reasons by normalized index."""
    existing = next((item for item in skipped_events if item.get("event_index") == event_index), None)
    prefix = f"Event at normalized position {event_index} was excluded from correlation: "
    if existing is None:
        existing = {"event_index": event_index, "event_id": event_id,
                    "event_source": event_source, "reason": reason}
        if provenance_status is not None:
            existing["provenance_status"] = provenance_status
        skipped_events.append(existing)
    else:
        reasons = existing["reason"].split("; ")
        if reason not in reasons:
            reasons.append(reason)
        existing["reason"] = "; ".join(reasons)
    diagnostics[:] = [item for item in diagnostics if not item.startswith(prefix)]
    diagnostics.append(prefix + existing["reason"] + ". This is an evidence limitation, not a maliciousness verdict.")


def _correlation_field_limitations(event: NormalizedEvent) -> list[str]:
    """Explain event types that cannot fill a correlation role without key fields."""
    missing: list[str] = []
    if event.event_source == "Windows Security" and event.event_id in (4624, 4625) and not _text(event.username):
        missing.append("missing username/account required for failed-to-success or logon-to-process identity matching")
    elif event.event_source == "Sysmon" and event.event_id == 1 and not _text(event.username):
        missing.append("missing username/account required for logon-to-process trigger matching; the event may still serve as contextual parent evidence")
    elif event.event_source == "Sysmon" and event.event_id == 3 and not _norm_ip(event.destination_ip):
        missing.append("missing or invalid destination IP required for network IOC matching")
    elif event.event_source == "Sysmon" and event.event_id == 22 and not _text(event.dns_query):
        missing.append("missing DNS query required for DNS IOC matching")
    return missing


def _associate_originals(
    events: list[object], raw_records: list[object], diagnostics: list[str]
) -> dict[int, _Association]:
    event_groups: dict[tuple[Any, ...], list[int]] = {}
    for index, event in enumerate(events):
        if isinstance(event, NormalizedEvent):
            event_groups.setdefault(_event_fingerprint(event), []).append(index)
    raw_candidates = _raw_event_candidates(raw_records)
    associations: dict[int, _Association] = {}
    identity_payloads: dict[str, set[Any]] = {}
    identity_keys: dict[str, str] = {}
    for candidate_group in raw_candidates.values():
        for raw, parsed_event in candidate_group:
            source_id = _source_identity(raw, parsed_event)
            if source_id is None:
                continue
            identity_payloads.setdefault(source_id, set()).add(_canonical_raw_payload(raw))
            identity_keys[source_id] = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:12]
    for source_id, payloads in identity_payloads.items():
        if len(payloads) > 1:
            diagnostics.append(
                f"Source identity collision for key {identity_keys[source_id]}: records sharing computer/channel/record ID have different complete original payloads; all variants were preserved."
            )
    for fingerprint, candidates in raw_candidates.items():
        if fingerprint not in event_groups:
            diagnostics.append(
                f"Provenance limitation for original event group {_content_digest(fingerprint)}: "
                f"{len(candidates)} supported original record(s) have no normalized event association."
            )
    for fingerprint, indices in event_groups.items():
        candidates = raw_candidates.get(fingerprint, [])
        if not candidates:
            for index in indices:
                associations[index] = _Association(None, [], None, None, "unmatched")
            diagnostics.append(
                f"Provenance unavailable for normalized event group {_content_digest(fingerprint)}: no original record matched its normalized fields."
            )
            continue
        raw_values = [item[0] for item in candidates]
        raw_keys = [_canonical_raw_payload(item) for item in raw_values]
        source_ids = [_source_identity(raw, event) for raw, event in candidates]
        equivalent_duplicate_candidates = (
            len(indices) == len(candidates)
            and all(value == raw_keys[0] for value in raw_keys)
            and len(set(source_ids)) == 1
        )
        if len(indices) == 1 and len(candidates) == 1:
            raw, raw_event = candidates[0]
            associations[indices[0]] = _Association(raw, [raw], _source_identity(raw, raw_event), raw_keys[0], "matched")
            continue
        if equivalent_duplicate_candidates:
            raw, raw_event = candidates[0]
            exact_raw_candidates = all(_raw_records_equal(value, raw_values[0]) for value in raw_values)
            if not exact_raw_candidates:
                diagnostics.append(
                    f"Provenance representation ambiguity for normalized event group {_content_digest(fingerprint)}: "
                    "original candidates differ only by recognized harmless formatting; no exact original was selected and all candidates remain available."
                )
            for index in indices:
                associations[index] = _Association(raw if exact_raw_candidates else None, list(raw_values),
                    _source_identity(raw, raw_event), raw_keys[0],
                    "equivalent-duplicates" if exact_raw_candidates else "ambiguous-equivalent")
            continue

        candidate_ids = {source_id for source_id in source_ids if source_id is not None}
        collision_ids: set[str] = set()
        for source_id in candidate_ids:
            matching_keys = {raw_key for raw_key, candidate_id in zip(raw_keys, source_ids) if candidate_id == source_id}
            if len(matching_keys) > 1:
                collision_ids.add(source_id)
        for source_id in sorted(collision_ids):
            diagnostics.append(
                "Source identity collision for key " + hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:12]
                + ": matching normalized events had different complete original payloads; events were preserved and provenance is ambiguous."
            )
        diagnostics.append(
            f"Provenance ambiguity for normalized event group {_content_digest(fingerprint)}: "
            f"{len(indices)} normalized event(s) matched {len(candidates)} distinct original candidate(s); no positional association was made."
        )
        for index in indices:
            associations[index] = _Association(None, list(raw_values), None, None, "ambiguous")
    return associations


def _prepare(source: AnalysisReport | Iterable[NormalizedEvent]) -> tuple[list[_Prepared], list[object], list[str], list[dict[str, Any]]]:
    if isinstance(source, AnalysisReport):
        events = source.events
        raw_records = list(source.original_records)
        diagnostics = ["Analyzer input issue: " + issue for issue in source.issues]
        associations = _associate_originals(events, raw_records, diagnostics)
    else:
        events = list(source)
        raw_records = []
        diagnostics = []
        associations = {index: _Association(None, [], None, None, "unavailable")
                        for index, event in enumerate(events) if isinstance(event, NormalizedEvent)}
        if events:
            diagnostics.append("Original source records were not supplied; provenance is unavailable for normalized-event input.")
    seen_source_ids: dict[str, dict[tuple[Any, ...], _Prepared]] = {}
    fallback_counts: dict[str, int] = {}
    prepared: list[_Prepared] = []
    skipped_events: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if not isinstance(event, NormalizedEvent):
            _register_skipped_event(skipped_events, diagnostics, event_index=index,
                event_id=None, event_source=None, reason="input value is not a NormalizedEvent")
            continue
        association = associations.get(index, _Association(None, [], None, None, "unmatched"))
        stamp = _utc(event.timestamp)
        computer = _text(event.computer)
        reasons = []
        if stamp is None:
            reasons.append("missing or invalid timezone-aware timestamp")
        if not computer:
            reasons.append("missing computer identity")
        reasons.extend(_correlation_field_limitations(event))
        if reasons:
            reason_text = " and ".join(reasons)
            _register_skipped_event(skipped_events, diagnostics, event_index=index,
                event_id=event.event_id, event_source=event.event_source,
                reason=reason_text, provenance_status=association.status)
            # Timestamp and computer are required by every pattern and prevent
            # preparation. Other identity limitations are pattern-specific; retain
            # the normalized event so it can still provide valid contextual evidence.
            if stamp is None or not computer:
                continue
        fingerprint = _event_fingerprint(event)
        original_record = association.original_record
        source_id = association.source_identity
        if original_record is not None and source_id is None:
            diagnostics.append(
                f"Reliable source identity unavailable for normalized event position {index}; conservative processing retains the event without source-record deduplication."
            )
        content = fingerprint + ((association.raw_content_key,) if association.raw_content_key is not None else ())
        if source_id:
            source_bucket = seen_source_ids.setdefault(source_id, {})
            existing = source_bucket.get(content)
            if existing:
                # Same source identity and same normalized meaning: exact duplicate ingestion.
                continue
            if source_bucket:
                diagnostic = (
                    "Source identity collision for key " + hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:12]
                    + ": records shared computer/channel/record ID but differed in complete original payload; all variants were preserved."
                )
                key_digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:12]
                if not any(f"Source identity collision for key {key_digest}" in item for item in diagnostics):
                    diagnostics.append(diagnostic)
                # Qualify every variant once a collision is known so cases remain distinct
                # and their IDs do not depend on which variant appeared first.
                for prior_content, prior in source_bucket.items():
                    prior.references[:] = ["source_record:" + source_id + ":content:" + _content_digest(prior_content)]
                reference = "source_record:" + source_id + ":content:" + _content_digest(content)
            else:
                reference = "source_record:" + source_id
        else:
            digest = _content_digest(content)
            ordinal = fallback_counts.get(digest, 0) + 1
            fallback_counts[digest] = ordinal
            if association.status == "ambiguous":
                reference = f"source_record_ambiguous:{digest}:{ordinal}"
            elif original_record is not None:
                reference = f"source_record_fallback:{digest}:{ordinal}"
            else:
                reference = f"normalized_event:{digest}:{ordinal}"
        item = _Prepared(event, stamp, [reference], source_id, original_record,
                         list(association.candidates), association.status, index)
        prepared.append(item)
        if source_id:
            seen_source_ids[source_id][content] = item
    prepared.sort(key=lambda item: item.timestamp)
    return prepared, raw_records, diagnostics, skipped_events


def _event_dict(item: _Prepared) -> dict[str, Any]:
    return {"source_references": list(item.references), "source_identity": item.source_identity,
            "original_record": item.original_record,
            "original_record_candidates": list(item.original_candidates),
            "provenance_status": item.provenance_status,
            "event": asdict(item.event)}


def _ioc_key(indicator: str) -> str:
    candidate = indicator.strip()
    if candidate.casefold().startswith(("http://", "https://")):
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").casefold()
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme.casefold()}://{host}{port}{parsed.path}?{parsed.query}#{parsed.fragment}"
    return candidate.rstrip(".").casefold()


def _ioc_field_value(obj: Any, name: str) -> tuple[Any, Optional[Exception]]:
    """Read declared/stored IOC fields without evaluating arbitrary properties."""
    wanted = _raw_key_token(name)
    if isinstance(obj, Mapping):
        try:
            for key, value in obj.items():
                if _raw_key_token(key) == wanted:
                    return value, None
        except Exception as error:
            return None, error
        return None, None

    if is_dataclass(obj) and not isinstance(obj, type):
        try:
            for item in fields(obj):
                if _raw_key_token(item.name) == wanted:
                    return getattr(obj, item.name), None
        except Exception as error:
            return None, error

    accessor_error: Optional[Exception] = None
    try:
        attributes = getattr(obj, "__dict__", None)
    except Exception as error:
        attributes = None
        accessor_error = error
    if isinstance(attributes, Mapping):
        try:
            for key, value in attributes.items():
                if _raw_key_token(key) == wanted:
                    return value, None
        except Exception as error:
            return None, error

    for cls in type(obj).__mro__:
        slots = cls.__dict__.get("__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if isinstance(slot, str) and not slot.startswith("__") and _raw_key_token(slot) == wanted:
                try:
                    return getattr(obj, slot), None
                except Exception as error:
                    return None, error
    return None, accessor_error


def _ioc_values(ioc_results: Iterable[Any], diagnostics: Optional[list[str]] = None) -> dict[str, tuple[str, list[Any]]]:
    results: dict[str, tuple[str, list[Any]]] = {}
    for result_index, result in enumerate(ioc_results):
        validation_value, validation_error = _ioc_field_value(result, "validation_status")
        if validation_error is not None:
            if diagnostics is not None:
                diagnostics.append(
                    f"IOC result {result_index} validation_status was inaccessible ({type(validation_error).__name__}); that result was not used."
                )
            continue
        validation = _text(validation_value)
        if not validation or validation.casefold() != "valid":
            continue
        indicator_value, indicator_error = _ioc_field_value(result, "indicator")
        if indicator_error is not None:
            if diagnostics is not None:
                diagnostics.append(
                    f"IOC result {result_index} indicator was inaccessible ({type(indicator_error).__name__}); that result was not used."
                )
            continue
        indicator = _text(indicator_value)
        if indicator:
            key = _ioc_key(indicator)
            if key not in results:
                results[key] = (indicator, [])
            results[key][1].append(result)
    return results


def _attribute_error_marker(value: Any, name: str, error: Exception) -> dict[str, str]:
    return {
        "$serialization_marker": "attribute_unavailable",
        "$type": f"{type(value).__module__}.{type(value).__qualname__}",
        "$field": name,
        "$error_type": f"{type(error).__module__}.{type(error).__qualname__}",
    }


def _record_attribute_issue(issues: list[str], path: str, value: Any, name: str, error: Exception) -> None:
    issues.append(
        f"IOC evidence at {path}.{name} could not be read from "
        f"{type(value).__module__}.{type(value).__qualname__} ({type(error).__name__})."
    )


def _ioc_result_fields(result: Any, issues: Optional[list[str]] = None) -> dict[str, Any]:
    """Expose every supplied public result field without manufacturing defaults."""
    issues = issues if issues is not None else []
    if isinstance(result, Mapping):
        try:
            return dict(result)
        except Exception as error:
            issues.append(f"IOC result mapping could not be copied ({type(error).__name__}).")
            return {"$serialization_marker": "attributes_unavailable",
                    "$type": f"{type(result).__module__}.{type(result).__qualname__}",
                    "$error_type": f"{type(error).__module__}.{type(error).__qualname__}"}
    if is_dataclass(result) and not isinstance(result, type):
        result_fields: dict[str, Any] = {}
        for item in fields(result):
            try:
                result_fields[item.name] = getattr(result, item.name)
            except Exception as error:
                result_fields[item.name] = _attribute_error_marker(result, item.name, error)
                _record_attribute_issue(issues, "result", result, item.name, error)
        return result_fields
    attributes = _object_attributes(result, issues=issues, path="result")
    if attributes is None:
        return {"$serialization_marker": "unsupported_value",
                "$type": f"{type(result).__module__}.{type(result).__qualname__}"}
    return attributes


def _object_attributes(value: Any, *, issues: Optional[list[str]] = None, path: str = "value") -> Optional[dict[str, Any]]:
    issues = issues if issues is not None else []
    accessor_errors: dict[str, Any] = {}
    try:
        values = getattr(value, "__dict__", None)
    except Exception as error:
        values = None
        accessor_errors["__dict__"] = _attribute_error_marker(value, "__dict__", error)
        _record_attribute_issue(issues, path, value, "__dict__", error)
    if isinstance(values, Mapping):
        try:
            attributes = {str(key): item for key, item in values.items() if not str(key).startswith("__")}
        except Exception as error:
            attributes = {}
            accessor_errors["__dict__"] = _attribute_error_marker(value, "__dict__", error)
            _record_attribute_issue(issues, path, value, "__dict__", error)
        if accessor_errors:
            attributes["$attribute_errors"] = accessor_errors
        return attributes

    slot_names = []
    for cls in type(value).__mro__:
        slots = cls.__dict__.get("__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        slot_names.extend(name for name in slots if isinstance(name, str))
    attributes: dict[str, Any] = {}
    for name in dict.fromkeys(slot_names):
        if name.startswith("__"):
            continue
        try:
            attributes[name] = getattr(value, name)
        except Exception as error:
            attributes[name] = _attribute_error_marker(value, name, error)
            _record_attribute_issue(issues, path, value, name, error)
    if accessor_errors:
        attributes["$attribute_errors"] = accessor_errors
    return attributes if attributes else None


def _json_safe(value: Any, *, path: str, active: dict[int, str], issues: list[str], depth: int = 0) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        issues.append(f"IOC evidence at {path} contains a non-finite number; value was marked unsupported.")
        return {"$serialization_issue": "non-finite number", "$type": "float"}
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()

    identity = id(value)
    if identity in active:
        issues.append(f"IOC evidence at {path} contains a circular reference to {active[identity]}.")
        return {"$serialization_issue": "circular reference", "$reference_to": active[identity]}
    if depth >= MAX_EVIDENCE_DEPTH:
        issues.append(f"IOC evidence at {path} exceeded the maximum serialization depth of {MAX_EVIDENCE_DEPTH}; remaining value was explicitly truncated.")
        return {"$serialization_marker": "maximum_depth_exceeded",
                "$type": f"{type(value).__module__}.{type(value).__qualname__}",
                "$max_depth": MAX_EVIDENCE_DEPTH}
    if isinstance(value, Enum):
        return _json_safe(value.value, path=f"{path}.$value", active=active,
                          issues=issues, depth=depth + 1)

    if isinstance(value, Mapping):
        active[identity] = path
        if all(isinstance(key, str) for key in value):
            result = {key: _json_safe(item, path=f"{path}.{key}", active=active, issues=issues, depth=depth + 1)
                      for key, item in value.items()}
        else:
            issues.append(f"IOC evidence at {path} uses non-string mapping keys; key/value entries were preserved explicitly.")
            result = {"$mapping_entries": [
                {"key": _json_safe(key, path=f"{path}.<key>", active=active, issues=issues, depth=depth + 1),
                 "value": _json_safe(item, path=f"{path}.<value>", active=active, issues=issues, depth=depth + 1)}
                for key, item in value.items()
            ]}
        active.pop(identity, None)
        return result
    if isinstance(value, (list, tuple)):
        active[identity] = path
        result = [_json_safe(item, path=f"{path}[{index}]", active=active, issues=issues, depth=depth + 1)
                  for index, item in enumerate(value)]
        active.pop(identity, None)
        return result
    if is_dataclass(value) and not isinstance(value, type):
        active[identity] = path
        attributes = {}
        for item in fields(value):
            try:
                attributes[item.name] = getattr(value, item.name)
            except Exception as error:
                attributes[item.name] = _attribute_error_marker(value, item.name, error)
                _record_attribute_issue(issues, path, value, item.name, error)
        result = {"$type": f"{type(value).__module__}.{type(value).__qualname__}",
                  "$fields": _json_safe(attributes, path=f"{path}.$fields", active=active,
                                        issues=issues, depth=depth + 1)}
        active.pop(identity, None)
        return result
    attributes = _object_attributes(value, issues=issues, path=path)
    if attributes is not None:
        active[identity] = path
        result = {"$type": f"{type(value).__module__}.{type(value).__qualname__}",
                  "$attributes": _json_safe(attributes, path=f"{path}.$attributes", active=active,
                                             issues=issues, depth=depth + 1)}
        active.pop(identity, None)
        return result
    issues.append(f"IOC evidence at {path} contains unsupported value type {type(value).__module__}.{type(value).__qualname__}.")
    return {"$serialization_issue": "unsupported value type",
            "$type": f"{type(value).__module__}.{type(value).__qualname__}"}


_IOC_CATEGORICAL_FIELDS = {"validationstatus", "reputationstatus", "riskclassification", "indicatortype"}
_IOC_KNOWN_FIELD_KEYS = _IOC_CATEGORICAL_FIELDS | {
    "indicator", "source", "investigationrecommendation", "validationreason", "malicious",
    "suspicious", "harmless", "error",
}


def _comparison_ioc_fields(supplied: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in supplied.items():
        canonical_key = _raw_key_token(key)
        if canonical_key == "indicator":
            continue
        if canonical_key in _IOC_CATEGORICAL_FIELDS and isinstance(value, str):
            value = value.strip().casefold()
        normalized[canonical_key if canonical_key in _IOC_KNOWN_FIELD_KEYS else key] = value
    return normalized


def _ioc_evidence(indicator: str, results: list[Any]) -> tuple[list[str], bool]:
    evidence = []
    states = set()
    serialization_issues: list[str] = []
    for result in results:
        local_issues: list[str] = []
        supplied_raw = _ioc_result_fields(result, local_issues)
        supplied = _json_safe(supplied_raw, path="result", active={}, issues=local_issues)
        if not isinstance(supplied, dict):
            supplied = {"$serialization_issue": "IOC result fields were not a mapping",
                        "$type": type(supplied_raw).__qualname__}
            local_issues.append("IOC result fields were not a mapping.")
        # The canonical indicator key groups equivalent indicators; all other supplied
        # fields participate in conflict detection and remain visible in the case.
        signature_fields = _comparison_ioc_fields(supplied)
        signature = json.dumps(signature_fields, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":"))
        states.add(signature)
        rendered = json.dumps(supplied, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        evidence.append(f"Supplied IOC result for {indicator}: {rendered}")
        serialization_issues.extend(local_issues)
    conflicting = len(states) > 1
    if conflicting:
        evidence.append("Conflicting IOC results were supplied; none was selected as authoritative and no malicious verdict was inferred.")
    evidence.extend("IOC evidence serialization limitation: " + issue for issue in serialization_issues)
    return evidence, conflicting


def _indicator_host(value: str) -> str:
    candidate = value.strip().casefold()
    if candidate.startswith(("http://", "https://")):
        return (urlsplit(candidate).hostname or "").casefold()
    return candidate


def _case(
    pattern: str,
    related: list[_Prepared],
    evidence: list[str],
    missing: list[str],
    recommendations: list[str],
    confidence: str,
    confidence_explanation: str,
    raw_records: list[object],
    source_issues: list[str],
    identity_parts: tuple[str, ...] = (),
) -> InvestigationCase:
    unique = {ref for item in related for ref in item.references}
    identity = "|".join((pattern, *sorted(unique), *sorted(identity_parts)))
    case_id = "SOC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
    accounts = sorted({item.event.username for item in related if item.event.username})
    computers = sorted({item.event.computer for item in related if item.event.computer})
    ips = sorted({ip for item in related for ip in (_norm_ip(item.event.source_ip), _norm_ip(item.event.destination_ip)) if ip})
    times = [item.timestamp for item in related]
    return InvestigationCase(case_id, pattern, min(times).isoformat(), max(times).isoformat(),
        [_event_dict(item) for item in related], accounts, computers, ips, evidence, missing,
        recommendations, confidence, confidence_explanation, list(raw_records), list(source_issues))


def _within(start: datetime, end: datetime, window: timedelta) -> bool:
    return start <= end and end - start <= window


def correlate(
    source: AnalysisReport | Iterable[NormalizedEvent],
    ioc_results: Iterable[Any] = (),
    config: CorrelationConfig = CorrelationConfig(),
) -> CorrelationReport:
    """Build investigation cases from existing normalized events and optional IOC results.

    This function is local-only. It never performs enrichment or any network request.
    The returned ``CorrelationReport`` remains list-compatible for existing callers;
    inspect ``.cases``, ``.diagnostics``, and ``.skipped_events`` for the full result,
    including preparation issues when no investigation case was emitted.
    """
    events, raw_records, diagnostics, skipped_events = _prepare(source)
    iocs = _ioc_values(ioc_results, diagnostics)
    cases: list[InvestigationCase] = []

    failures = [item for item in events if item.event.event_id == 4625 and item.event.event_source == "Windows Security"]
    successes = [item for item in events if item.event.event_id == 4624 and item.event.event_source == "Windows Security"]
    groups: dict[tuple[str, str, Optional[str]], list[_Prepared]] = {}
    for failure in failures:
        event = failure.event
        if not event.computer or not _text(event.username):
            continue
        key = (event.computer.casefold(), event.username.casefold(), _norm_ip(event.source_ip))
        groups.setdefault(key, []).append(failure)
    for success in successes:
        event = success.event
        if not event.computer or not _text(event.username):
            continue
        for (computer, account, source_ip), group in groups.items():
            if computer != event.computer.casefold() or account != event.username.casefold():
                continue
            success_ip = _norm_ip(event.source_ip)
            if source_ip and success_ip and source_ip != success_ip:
                continue
            preceding = [failure for failure in group if _within(failure.timestamp, success.timestamp, config.failed_to_success_window)]
            if len(preceding) < config.failed_logon_threshold:
                continue
            related = preceding + [success]
            ip_continuity_unknown = (source_ip is None) != (success_ip is None)
            if source_ip and success_ip:
                correlation_basis = "same computer/account/source IP"
            elif ip_continuity_unknown:
                correlation_basis = "same computer/account; source-IP continuity could not be established"
            else:
                correlation_basis = "same computer/account; source IP was unavailable on both sides"
            missing = ["Authentication result and business context require analyst verification."]
            if ip_continuity_unknown:
                missing.append("Source-IP continuity could not be established because one side of the failed-to-success sequence has no usable source IP.")
            cases.append(_case("Repeated failed logons followed by successful logon", related,
                [f"{len(preceding)} distinct Event ID 4625 records for the {correlation_basis} precede Event ID 4624 within {config.failed_to_success_window.total_seconds():g} seconds."],
                missing,
                ["Review logon type, source context, account owner, and adjacent endpoint activity."],
                "medium", "The host, account, event order, threshold, and time window match; this is correlation strength, not proof of attack.", raw_records, diagnostics))

    for success in successes:
        se = success.event
        if not se.computer or not _text(se.username):
            continue
        for process in events:
            pe = process.event
            if pe.event_id != 1 or pe.event_source != "Sysmon" or not pe.computer or not _text(pe.username):
                continue
            if pe.computer.casefold() != se.computer.casefold() or pe.username.casefold() != se.username.casefold():
                continue
            if not _within(success.timestamp, process.timestamp, config.logon_to_process_window):
                continue
            reasons = [obs for obs in pe.observations if "user-writable location" in obs or "Office application launched" in obs]
            if not reasons:
                continue
            related = [success, process]
            parent_matches = [candidate for candidate in events
                if candidate is not process
                and candidate.event.event_id == 1
                and candidate.event.event_source == "Sysmon"
                and candidate.event.computer
                and candidate.event.computer.casefold() == pe.computer.casefold()
                and candidate.event.process_path
                and pe.parent_process
                and candidate.event.process_path.casefold() == pe.parent_process.casefold()
                and _within(candidate.timestamp, process.timestamp, config.logon_to_process_window)
                and (not candidate.event.username or candidate.event.username.casefold() == pe.username.casefold())]
            if parent_matches:
                parent_event = max(parent_matches, key=lambda candidate: candidate.timestamp)
                if parent_event not in related:
                    related.append(parent_event)
                    reasons.append("A separate Sysmon process event has a matching parent image on the same computer and within the configured time window; this is contextual evidence only, not confirmed process lineage.")
            cases.append(_case("Successful logon followed by unusual process creation", related,
                ["Event ID 4624 and Event ID 1 share the computer/account and occur in order within the configured window.", *reasons,
                 f"Process parent field: {pe.parent_process or 'not available'}; process ID: {pe.process_id or 'not available'}."],
                ["A baseline for this account and process lineage is not available.",
                 "Process lineage is not confirmed; no matching PID or process GUID relationship was established."],
                ["Confirm the logon was expected and inspect the process image, parent, command line, and change/deployment context."],
                "medium", "Identity, sequence, time, and an analyzer heuristic align; process context is not proof of compromise.", raw_records, diagnostics))

    for item in events:
        event = item.event
        if event.event_id != 3 or event.event_source != "Sysmon" or not event.computer:
            continue
        dest = _norm_ip(event.destination_ip)
        if not dest:
            continue
        for ioc_key, (indicator, results) in iocs.items():
            if _indicator_host(indicator) != dest:
                continue
            ioc_evidence, conflicting = _ioc_evidence(indicator, results)
            cases.append(_case("Network connection associated with an available IOC result", [item],
                [f"Sysmon Event ID 3 destination IP exactly matches supplied, validated IOC {indicator}.", *ioc_evidence,
                 "No lookup was performed by the correlation engine."],
                ["IOC observation time and independent confirmation are not available from the supplied result."] + (["Supplied IOC results conflict; analyst should resolve source provenance."] if conflicting else []),
                ["Verify indicator provenance and compare destination, process, time, and approved network activity."],
                "medium", "Exact indicator-to-destination matching supports an association only; the engine makes no malicious verdict.", raw_records, diagnostics,
                ("ioc:" + ioc_key,)))

    for item in events:
        event = item.event
        if event.event_id != 22 or event.event_source != "Sysmon" or not event.computer or not event.dns_query:
            continue
        query = event.dns_query.rstrip(".").casefold()
        for ioc_key, (indicator, results) in iocs.items():
            if _indicator_host(indicator) != query:
                continue
            ioc_evidence, conflicting = _ioc_evidence(indicator, results)
            cases.append(_case("DNS query associated with an available IOC result", [item],
                [f"Sysmon Event ID 22 query exactly matches supplied, validated IOC {indicator}.", *ioc_evidence,
                 "No lookup was performed by the correlation engine."],
                ["IOC observation time and independent DNS/domain context are not available from the supplied result."] + (["Supplied IOC results conflict; analyst should resolve source provenance."] if conflicting else []),
                ["Validate IOC provenance and investigate resolver, process, destination, and related host activity."],
                "medium", "Exact query-to-indicator matching supports an association only; it does not establish maliciousness.", raw_records, diagnostics,
                ("ioc:" + ioc_key,)))
    return CorrelationReport(cases, diagnostics=diagnostics, skipped_events=skipped_events)
