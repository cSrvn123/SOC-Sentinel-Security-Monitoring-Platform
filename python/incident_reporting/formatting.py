"""Safe JSON and analyst-oriented Markdown formatting for incident reports.

JSON exports preserve original evidence where it is accessible. They may
contain sensitive endpoint information and must be reviewed before sharing.
Serialization markers disclose circular, unsupported, inaccessible, or
depth-limited values; they do not imply that marked evidence is complete.
"""

from __future__ import annotations

import html
import json
import math
import re
from dataclasses import fields, is_dataclass
from datetime import date, datetime, time, timezone
from enum import Enum
from collections.abc import Mapping
from typing import Any

from .models import EventProvenance, IncidentEntities, IncidentReport, IncidentReportCollection
from .timeline import TimelineEntry


MAX_JSON_DEPTH = 128
_MISSING = object()
_REPORT_DATACLASSES = (IncidentReport, IncidentReportCollection, IncidentEntities, EventProvenance, TimelineEntry)
_MARKDOWN_LIMIT = 1200
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|>~])")


class _GeneratedPath:
    """Private path metadata emitted only by this serializer's own markers."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value


def _type_name(value: Any) -> str:
    value_type = type(value)
    module = type.__getattribute__(value_type, "__module__")
    qualname = type.__getattribute__(value_type, "__qualname__")
    safe_module = module if type(module) is str else "unknown-module"
    safe_qualname = qualname if type(qualname) is str else "unknown-type"
    return f"{safe_module}.{safe_qualname}"


def _marker(kind: str, value: Any, path: str, **details: Any) -> dict[str, Any]:
    marker_details = dict(details)
    if type(marker_details.get("reference_to")) is str:
        marker_details["reference_to"] = _GeneratedPath(marker_details["reference_to"])
    return {
        "$serialization_marker": kind,
        "$type": _type_name(value),
        "$path": _GeneratedPath(path),
        **marker_details,
    }


def _attribute_marker(value: Any, attribute: str, path: str, error: BaseException) -> dict[str, Any]:
    error_type = _type_name(error)
    return _marker(
        "attribute_unavailable",
        value,
        path,
        attribute=attribute,
        exception_type=error_type,
    )


def _stable_json_key(value: Any) -> str:
    def tagged(item: Any) -> Any:
        if isinstance(item, _GeneratedPath):
            return [1]
        if type(item) is dict:
            return [6, [[key, tagged(item[key])] for key in sorted(item)]]
        if type(item) is list:
            return [5, [tagged(child) for child in item]]
        if item is None:
            return [3]
        if type(item) is bool:
            return [4, item]
        if type(item) is int:
            return [2, "integer", item]
        if type(item) is float:
            return [2, "number", item]
        if type(item) is str:
            return [0, item]
        raise TypeError("Stable JSON keys require serializer-safe values.")

    return json.dumps(tagged(value), ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _path_key(path: str, key: str) -> str:
    """Append a JSON object key using unambiguous bracket notation."""
    return f"{path}[{json.dumps(str.__str__(key), ensure_ascii=True)}]"


def _path_index(path: str, index: int) -> str:
    return f"{path}[{index}]"


def _replace_path_prefix(value: Any, old: str, new: str) -> Any:
    """Rebase only explicitly tagged serializer-generated path metadata."""
    if isinstance(value, _GeneratedPath):
        path = value.value
        if path == old:
            return _GeneratedPath(new)
        if path.startswith(old) and len(path) > len(old) and path[len(old)] in ".[":
            return _GeneratedPath(new + path[len(old):])
        return value
    if type(value) is dict:
        return {key: _replace_path_prefix(item, old, new) for key, item in value.items()}
    if type(value) is list:
        return [_replace_path_prefix(item, old, new) for item in value]
    return value


def _path_neutral(value: Any) -> Any:
    """Normalize only tagged generated paths for deterministic sorting."""
    if isinstance(value, _GeneratedPath):
        return _GeneratedPath("")
    if type(value) is dict:
        return {key: _path_neutral(item) for key, item in value.items()}
    if type(value) is list:
        return [_path_neutral(item) for item in value]
    return value


def _materialize_generated_paths(value: Any) -> Any:
    """Convert private path tags to public JSON strings after rebasing ends."""
    if isinstance(value, _GeneratedPath):
        return value.value
    if type(value) is dict:
        return {key: _materialize_generated_paths(item) for key, item in value.items()}
    if type(value) is list:
        return [_materialize_generated_paths(item) for item in value]
    return value


def _slot_names(value: Any) -> list[str]:
    names: set[str] = set()
    try:
        hierarchy = type(value).__mro__
    except Exception:
        return []
    for base in hierarchy:
        try:
            declared = vars(base).get("__slots__", ())
        except Exception:
            continue
        if isinstance(declared, str):
            declared = (declared,)
        if isinstance(declared, (tuple, list)):
            names.update(name for name in declared if isinstance(name, str))
    return sorted(names - {"__dict__", "__weakref__"})


def _class_declares_dict_property(value: Any) -> bool:
    try:
        for base in type(value).__mro__:
            descriptor = vars(base).get("__dict__", _MISSING)
            if isinstance(descriptor, property):
                return True
    except Exception:
        return False
    return False


def _serialize_object_attributes(value: Any, *, path: str, active: dict[int, str], depth: int) -> Any:
    """Serialize ordinary instance storage and declared slots without properties."""
    attributes: dict[str, Any] = {}
    attribute_errors: dict[str, Any] = {}
    has_attribute_storage = False
    custom_dict_property = _class_declares_dict_property(value)
    if custom_dict_property:
        attribute_errors["__dict__"] = _marker(
            "computed_attribute_not_accessed", value,
            _path_key(_path_key(path, "$attribute_errors"), "__dict__"),
            attribute="__dict__", reason="computed property not invoked",
        )
    else:
        try:
            instance_attributes = object.__getattribute__(value, "__dict__")
        except AttributeError:
            instance_attributes = _MISSING
        except Exception as error:
            has_attribute_storage = True
            attribute_errors["__dict__"] = _attribute_marker(
                value,
                "__dict__",
                _path_key(_path_key(path, "$attribute_errors"), "__dict__"),
                error,
            )
            instance_attributes = _MISSING
        if isinstance(instance_attributes, dict):
            has_attribute_storage = True
            try:
                names = sorted(name for name in instance_attributes if isinstance(name, str))
            except Exception as error:
                names = []
                attribute_errors["__dict__"] = _attribute_marker(
                    value,
                    "__dict__",
                    _path_key(_path_key(path, "$attribute_errors"), "__dict__"),
                    error,
                )
            for name in names:
                try:
                    field_value = instance_attributes[name]
                except Exception as error:
                    attribute_path = _path_key(_path_key(path, "$attribute_errors"), name)
                    attribute_errors[name] = _attribute_marker(value, name, attribute_path, error)
                else:
                    attributes[name] = _json_safe(
                        field_value,
                        path=_path_key(_path_key(path, "$attributes"), name),
                        active=active,
                        depth=depth + 1,
                    )

    for name in _slot_names(value):
        has_attribute_storage = True
        try:
            slot_value = object.__getattribute__(value, name)
        except Exception as error:
            attribute_path = _path_key(_path_key(path, "$attribute_errors"), name)
            attribute_errors[name] = _attribute_marker(value, name, attribute_path, error)
        else:
            attributes[name] = _json_safe(
                slot_value,
                path=_path_key(_path_key(path, "$attributes"), name),
                active=active,
                depth=depth + 1,
            )

    if attributes or attribute_errors:
        result: dict[str, Any] = {"$type": _type_name(value), "$attributes": attributes}
        if attribute_errors:
            result["$attribute_errors"] = attribute_errors
        return result
    if has_attribute_storage:
        return {"$type": _type_name(value), "$attributes": {}}
    return _marker("unsupported_value", value, path)


def _json_safe(value: Any, *, path: str, active: dict[int, str], depth: int = 0) -> Any:
    """Convert values to JSON-native data with cycle and depth markers.

    Only objects on the current traversal path are considered circular; shared
    objects in separate branches are serialized independently. Object
    properties are not enumerated or invoked. Dataclass fields, instance
    attributes, and declared slots are inspected without mutating their owners.
    """
    if isinstance(value, Enum):
        try:
            enum_value = object.__getattribute__(value, "_value_")
        except Exception as error:
            return _marker(
                "enum_value_unavailable", value, path,
                exception_type=_type_name(error),
            )
        return _json_safe(enum_value, path=path, active=active, depth=depth)
    if value is None or type(value) is bool:
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if isinstance(value, int):
        try:
            return int.__int__(value)
        except Exception as error:
            return _marker(
                "integer_value_unavailable", value, path,
                exception_type=_type_name(error),
            )
    if isinstance(value, float):
        try:
            safe_value = float.__float__(value)
        except Exception as error:
            return _marker(
                "float_value_unavailable", value, path,
                exception_type=_type_name(error),
            )
        if not math.isfinite(safe_value):
            value_text = "NaN" if math.isnan(safe_value) else ("Infinity" if safe_value > 0 else "-Infinity")
            return _marker("non_finite_number", value, path, value_text=value_text)
        return safe_value
    if isinstance(value, datetime):
        try:
            tzinfo = datetime.tzinfo.__get__(value, type(value))
            if tzinfo is not None and type(tzinfo) is not timezone:
                return _marker("timezone_value_unsupported", value, path, timezone_type=_type_name(tzinfo))
            iso_value = datetime.isoformat(value)
        except Exception as error:
            return _marker(
                "datetime_value_unavailable", value, path,
                exception_type=_type_name(error),
            )
        return {"$type": _type_name(value), "$value": iso_value}
    if isinstance(value, date):
        try:
            iso_value = date.isoformat(value)
        except Exception as error:
            return _marker(
                "date_value_unavailable", value, path,
                exception_type=_type_name(error),
            )
        return {"$type": _type_name(value), "$value": iso_value}
    if isinstance(value, time):
        try:
            tzinfo = time.tzinfo.__get__(value, type(value))
            if tzinfo is not None and type(tzinfo) is not timezone:
                return _marker("timezone_value_unsupported", value, path, timezone_type=_type_name(tzinfo))
            iso_value = time.isoformat(value)
        except Exception as error:
            return _marker(
                "time_value_unavailable", value, path,
                exception_type=_type_name(error),
            )
        return {"$type": _type_name(value), "$value": iso_value}

    identity = id(value)
    if identity in active:
        return _marker("circular_reference", value, path, reference_to=active[identity])
    if depth >= MAX_JSON_DEPTH:
        return _marker("maximum_depth_exceeded", value, path, max_depth=MAX_JSON_DEPTH)

    if isinstance(value, Mapping):
        try:
            item_source = value.items()
        except Exception as error:
            return _marker(
                "mapping_unavailable", value, path,
                exception_type=_type_name(error),
            )
        try:
            iterator = iter(item_source)
        except Exception as error:
            return _marker(
                "mapping_unavailable", value, path,
                exception_type=_type_name(error),
            )

        active[identity] = path
        try:
            raw_entries: list[tuple[int, Any, Any, str | None]] = []
            malformed_entries: list[tuple[int, Any, BaseException]] = []
            iteration_error: BaseException | None = None
            entry_index = 0

            while True:
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                except Exception as error:
                    iteration_error = error
                    break

                try:
                    key, item = entry
                except Exception as error:
                    malformed_entries.append((entry_index, entry, error))
                    entry_index += 1
                    continue
                normalized_key = str.__str__(key) if isinstance(key, str) else None
                raw_entries.append((entry_index, key, item, normalized_key))
                entry_index += 1

            plain_keys: set[str] = set()
            plain_shape = iteration_error is None and not malformed_entries
            for _, _, _, normalized_key in raw_entries:
                if normalized_key is None or normalized_key in plain_keys:
                    plain_shape = False
                    break
                plain_keys.add(normalized_key)

            if plain_shape:
                plain_entries: dict[str, Any] = {}
                for _, _, item, normalized_key in raw_entries:
                    assert normalized_key is not None
                    item_path = _path_key(path, normalized_key)
                    try:
                        plain_entries[normalized_key] = _json_safe(
                            item, path=item_path, active=active, depth=depth + 1,
                        )
                    except Exception as error:
                        plain_entries[normalized_key] = _marker(
                            "mapping_value_serialization_failed", item, item_path,
                            exception_type=_type_name(error),
                        )
                return plain_entries

            pairs_with_source_index: list[tuple[int, dict[str, Any]]] = []
            for source_index, key, item, _ in raw_entries:
                provisional_path = _path_index(_path_key(path, "$mapping_entries"), source_index)
                key_path = _path_key(provisional_path, "key")
                item_path = _path_key(provisional_path, "value")
                try:
                    safe_key = _json_safe(key, path=key_path, active=active, depth=depth + 1)
                except Exception as error:
                    safe_key = _marker(
                        "mapping_key_serialization_failed", key, key_path,
                        exception_type=_type_name(error),
                    )
                try:
                    safe_item = _json_safe(item, path=item_path, active=active, depth=depth + 1)
                except Exception as error:
                    safe_item = _marker(
                        "mapping_value_serialization_failed", item, item_path,
                        exception_type=_type_name(error),
                    )
                pairs_with_source_index.append((source_index, {"key": safe_key, "value": safe_item}))

            pairs_with_source_index.sort(key=lambda row: _stable_json_key(_path_neutral(row[1])))
            pairs: list[dict[str, Any]] = []
            mapping_entries_path = _path_key(path, "$mapping_entries")
            for output_index, (source_index, pair) in enumerate(pairs_with_source_index):
                source_path = _path_index(mapping_entries_path, source_index)
                output_path = _path_index(mapping_entries_path, output_index)
                pairs.append(_replace_path_prefix(pair, source_path, output_path))

            result: dict[str, Any] = {
                "$type": _type_name(value),
                "$mapping_entries": pairs,
            }
            if malformed_entries:
                error_path = _path_key(path, "$entry_errors")
                result["$entry_errors"] = [
                    _marker(
                        "mapping_entry_unavailable",
                        entry,
                        _path_index(error_path, output_index),
                        exception_type=_type_name(error),
                        source_entry_index=source_index,
                    )
                    for output_index, (source_index, entry, error) in enumerate(malformed_entries)
                ]
            if iteration_error is not None:
                result["$incomplete_remainder"] = _marker(
                    "mapping_iteration_incomplete",
                    value,
                    _path_key(path, "$incomplete_remainder"),
                    exception_type=_type_name(iteration_error),
                    entries_read=entry_index,
                )
            return result
        finally:
            active.pop(identity, None)

    if isinstance(value, (list, tuple)):
        active[identity] = path
        try:
            try:
                items = [
                    _json_safe(item, path=f"{path}[{index}]", active=active, depth=depth + 1)
                    for index, item in enumerate(value)
                ]
            except Exception as error:
                return _marker(
                    "sequence_unavailable", value, path,
                    exception_type=_type_name(error),
                )
            if isinstance(value, tuple):
                return {"$type": "builtins.tuple", "$values": items}
            return items
        finally:
            active.pop(identity, None)

    if isinstance(value, (set, frozenset)):
        active[identity] = path
        try:
            try:
                iterator = iter(value)
            except Exception as error:
                return _marker(
                    "set_unavailable", value, path,
                    exception_type=_type_name(error),
                )

            serialized_items: list[tuple[int, Any]] = []
            iteration_error: BaseException | None = None
            source_index = 0
            values_path = _path_key(path, "$values")
            while True:
                try:
                    item = next(iterator)
                except StopIteration:
                    break
                except Exception as error:
                    iteration_error = error
                    break

                item_path = _path_index(values_path, source_index)
                try:
                    serialized_item = _json_safe(
                        item,
                        path=item_path,
                        active=dict(active),
                        depth=depth + 1,
                    )
                except Exception as error:
                    serialized_item = _marker(
                        "set_member_serialization_failed",
                        item,
                        item_path,
                        exception_type=_type_name(error),
                    )
                serialized_items.append((source_index, serialized_item))
                source_index += 1

            serialized_items.sort(key=lambda pair: _stable_json_key(_path_neutral(pair[1])))
            items = [
                _replace_path_prefix(
                    item,
                    _path_index(values_path, source_index),
                    _path_index(values_path, output_index),
                )
                for output_index, (source_index, item) in enumerate(serialized_items)
            ]
            result: dict[str, Any] = {"$type": _type_name(value), "$values": items}
            if iteration_error is not None:
                result["$incomplete_remainder"] = _marker(
                    "set_iteration_incomplete",
                    value,
                    _path_key(path, "$incomplete_remainder"),
                    exception_type=_type_name(iteration_error),
                    entries_read=source_index,
                )
            return result
        finally:
            active.pop(identity, None)

    if is_dataclass(value) and not isinstance(value, type):
        try:
            declared_fields = fields(value)
        except Exception as error:
            return _marker(
                "dataclass_fields_unavailable", value, path,
                exception_type=_type_name(error),
            )
        active[identity] = path
        try:
            serialized_fields: dict[str, Any] = {}
            is_report_model = isinstance(value, _REPORT_DATACLASSES)
            field_parent = path if is_report_model else _path_key(path, "$fields")
            for item in declared_fields:
                try:
                    field_value = getattr(value, item.name)
                except Exception as error:
                    field_path = _path_key(field_parent, item.name)
                    serialized_fields[item.name] = _attribute_marker(
                        value, item.name, field_path, error,
                    )
                else:
                    serialized_fields[item.name] = _json_safe(
                        field_value,
                        path=_path_key(field_parent, item.name),
                        active=active,
                        depth=depth + 1,
                    )
            if is_report_model:
                return serialized_fields
            return {"$type": _type_name(value), "$fields": serialized_fields}
        finally:
            active.pop(identity, None)

    # Read ordinary instance storage and declared slots, never arbitrary
    # computed properties. Failures remain visible as typed serialization data.
    active[identity] = path
    try:
        return _serialize_object_attributes(value, path=path, active=active, depth=depth)
    finally:
        active.pop(identity, None)


def _serialize_report(report: IncidentReport | IncidentReportCollection) -> dict[str, Any]:
    if isinstance(report, IncidentReport):
        safe = _json_safe(report, path="$", active={})
        return _materialize_generated_paths(safe)
    if isinstance(report, IncidentReportCollection):
        safe = _json_safe(report, path="$", active={})
        return _materialize_generated_paths(safe)
    raise TypeError("format_json requires an IncidentReport or IncidentReportCollection.")


def format_json(report: IncidentReport | IncidentReportCollection) -> str:
    """Return deterministic JSON; raw records may contain sensitive log data."""
    try:
        payload = _serialize_report(report)
        return json.dumps(payload, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True)
    except Exception as error:
        # Preserve validity and disclose catastrophic serializer failures rather
        # than returning partial or malformed JSON. This is a last-resort marker.
        fallback = _materialize_generated_paths(
            _marker(
                "report_serialization_failed",
                report,
                "$",
                exception_type=_type_name(error),
            )
        )
        return json.dumps(fallback, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True)


def _markdown_text(value: Any, *, limit: int = _MARKDOWN_LIMIT) -> str:
    """Render untrusted values as escaped single-line Markdown text."""
    if isinstance(value, Enum):
        try:
            value = object.__getattribute__(value, "_value_")
        except Exception:
            text = f"[{_type_name(value)}; enum value unavailable]"
        else:
            if isinstance(value, str):
                text = str.__str__(value)
            elif type(value) is bool:
                text = "True" if value else "False"
            elif type(value) is int:
                text = int.__str__(value)
            elif type(value) is float:
                text = float.__str__(value) if math.isfinite(value) else f"non-finite number ({'nan' if math.isnan(value) else ('inf' if value > 0 else '-inf')})"
            else:
                text = f"[{_type_name(value)}; enum value is not a supported scalar]"
    elif value is None:
        text = "Not provided"
    elif isinstance(value, str):
        # Call the base implementation to read str-subclass contents without
        # dispatching to an overridden __str__ method.
        text = str.__str__(value)
    elif type(value) is bool:
        text = "True" if value else "False"
    elif type(value) is int:
        text = int.__str__(value)
    elif type(value) is float:
        text = float.__str__(value) if math.isfinite(value) else f"non-finite number ({'nan' if math.isnan(value) else ('inf' if value > 0 else '-inf')})"
    else:
        text = f"[{_type_name(value)}; see JSON export for structured evidence]"
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ⏎ ")
    text = html.escape(text, quote=True)
    text = _MARKDOWN_SPECIAL.sub(r"\\\1", text)
    if len(text) > limit:
        text = text[:limit] + "… [Markdown value truncated; full evidence is in JSON]"
    return text


def _safe_get(value: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(value, name, default)
    except Exception:
        return default


def _list_values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _markdown_values(value: Any) -> str:
    values = _list_values(value)
    return ", ".join(_markdown_text(item) for item in values) if values else "None recorded."


def _markdown_item(value: Any) -> str:
    if isinstance(value, Mapping):
        selected: list[str] = []
        for key in ("event_source", "event_id", "event_index", "reason"):
            if key in value:
                selected.append(f"{_markdown_text(key)}: {_markdown_text(value[key])}")
        unknown_count = sum(key not in {"event_source", "event_id", "event_index", "reason"} for key in value)
        if unknown_count:
            selected.append(f"additional fields: {unknown_count} (full data in JSON)")
        return "; ".join(selected) if selected else f"Structured item ({len(value)} fields; full data in JSON)"
    return _markdown_text(value)


def _incident_markdown(incident: IncidentReport) -> list[str]:
    lines = [
        f"## Incident Summary: {_markdown_text(incident.incident_id)}",
        f"- Title: {_markdown_text(incident.title)}",
        f"- Source case: {_markdown_text(incident.source_case_id)}",
        f"- Schema version: {_markdown_text(incident.schema_version)}",
        f"- Entities: accounts={_markdown_values(_safe_get(incident.entities, 'accounts', []))}; "
        f"computers={_markdown_values(_safe_get(incident.entities, 'computers', []))}; "
        f"IPs={_markdown_values(_safe_get(incident.entities, 'ips', []))}",
        "",
        "### Correlation Confidence",
        f"- Confidence: {_markdown_text(incident.confidence)}",
        f"- Explanation: {_markdown_text(incident.confidence_explanation)}",
        "Confidence describes correlation strength only; it is not incident severity or proof of compromise.",
        "",
        "### Severity Assessment",
        f"- Severity: {_markdown_text(incident.severity)}",
        "Severity is the analyst-assessed impact and urgency; it is separate from correlation confidence.",
        "",
        "### Analyst Conclusion",
        f"- Conclusion: {_markdown_text(incident.analyst_conclusion)}",
        "A suspicious or inconclusive conclusion is not a confirmed-malicious finding.",
        "",
        "### Severity Rationale",
        _markdown_text(incident.severity_rationale),
        "",
        "### Analyst Conclusion Rationale",
        _markdown_text(incident.analyst_conclusion_rationale),
        "",
        "### Timeline",
    ]
    timeline = _list_values(incident.timeline)
    if not timeline:
        lines.append("- No timeline entries recorded.")
    for entry in timeline:
        index = _safe_get(entry, "related_event_index", "unknown")
        original = _safe_get(entry, "original_timestamp")
        timestamp_status = _safe_get(entry, "timestamp_status", "unavailable")
        event_label = " ".join(
            part for part in (
                _markdown_text(_safe_get(entry, "event_source")) if _safe_get(entry, "event_source") is not None else "",
                f"Event ID {_markdown_text(_safe_get(entry, 'event_id'))}" if _safe_get(entry, "event_id") is not None else "",
                _markdown_text(_safe_get(entry, "event_type")) if _safe_get(entry, "event_type") is not None else "",
            ) if part
        )
        line = f"- Related event {_markdown_text(index)} ({_markdown_text(timestamp_status)}): {_markdown_text(original)}"
        if event_label:
            line += f" — {event_label}"
        normalized = _safe_get(entry, "normalized_timestamp_utc")
        if normalized is not None:
            line += f"; normalized UTC: {_markdown_text(normalized)}"
        lines.append(line)
        refs = _list_values(_safe_get(entry, "source_references", []))
        if refs:
            lines.append("  - Source references: " + ", ".join(_markdown_text(ref) for ref in refs))
        provenance_status = _safe_get(entry, "provenance_status")
        if provenance_status is not None:
            lines.append(f"  - Provenance: {_markdown_text(provenance_status)}")
        for diagnostic in _list_values(_safe_get(entry, "diagnostics", [])):
            lines.append(f"  - Timeline note: {_markdown_text(diagnostic)}")

    lines.extend(("", "### Evidence"))
    evidence = _list_values(incident.evidence)
    lines.extend(f"- {_markdown_text(item)}" for item in evidence) if evidence else lines.append("- No evidence items recorded.")

    lines.extend(("", "### Missing Evidence"))
    missing = _list_values(incident.missing_evidence)
    lines.extend(f"- {_markdown_text(item)}" for item in missing) if missing else lines.append("- None recorded.")

    lines.extend(("", "### Recommendations"))
    recommendations = _list_values(incident.recommendations)
    lines.extend(f"- {_markdown_text(item)}" for item in recommendations) if recommendations else lines.append("- None recorded.")

    lines.extend(("", "### MITRE ATT&CK Mappings"))
    mappings = _list_values(incident.mitre_attack_mappings)
    if not mappings:
        lines.append("- No ATT&CK mappings recorded.")
    for mapping in mappings:
        if not isinstance(mapping, Mapping):
            lines.append(f"- Unsupported mapping value ({_type_name(mapping)}); inspect the JSON export.")
            continue
        status = mapping.get("reference_status", "UNVERIFIED")
        status_value = status
        if isinstance(status, Enum):
            try:
                status_value = object.__getattribute__(status, "_value_")
            except Exception:
                status_value = None
        if isinstance(status_value, str) and str.casefold(str.__str__(status_value)) == "unverified":
            status_label = "UNVERIFIED — syntax only; not validated against a pinned ATT&CK reference."
        else:
            status_label = _markdown_text(status)
        technique = f"{_markdown_text(mapping.get('technique_id'))} — {_markdown_text(mapping.get('technique_name'))}"
        tactic = mapping.get("tactic")
        if tactic is not None:
            technique += f"; tactic: {_markdown_text(tactic)}"
        lines.append(f"- {technique} [{status_label}]")
        lines.append(f"  - Rationale: {_markdown_text(mapping.get('rationale'))}")
        for reference in _list_values(mapping.get("evidence_references", [])):
            if isinstance(reference, Mapping):
                ref_index = reference.get("related_event_index", "unknown")
                ref_status = reference.get("provenance_status", "unavailable")
                refs = _list_values(reference.get("source_references", []))
                ref_line = f"related event {_markdown_text(ref_index)}; provenance {_markdown_text(ref_status)}"
                if refs:
                    ref_line += "; source references: " + ", ".join(_markdown_text(ref) for ref in refs)
                lines.append(f"  - Evidence reference: {ref_line}")
            else:
                lines.append(f"  - Evidence reference: {_markdown_text(reference)}")

    lines.extend(("", "### Provenance and Evidence Limitations"))
    provenance = _list_values(incident.provenance)
    if not provenance and not incident.evidence_limitations:
        lines.append("- No provenance entries or evidence limitations recorded.")
    for entry in provenance:
        index = _safe_get(entry, "related_event_index", "unknown")
        status = _safe_get(entry, "provenance_status", "unavailable")
        refs = _list_values(_safe_get(entry, "source_references", []))
        candidate_records = _list_values(_safe_get(entry, "original_record_candidates", []))
        original_record = _safe_get(entry, "original_record")
        line = f"- Related event {_markdown_text(index)}: provenance {_markdown_text(status)}"
        if refs:
            line += "; source references: " + ", ".join(_markdown_text(ref) for ref in refs)
        source_identity = _safe_get(entry, "source_identity")
        if source_identity is not None:
            line += f"; source identity: {_markdown_text(source_identity)}"
        line += "; associated original record: " + ("present (not expanded)" if original_record is not None else "not associated")
        if candidate_records:
            line += f"; candidate record count: {len(candidate_records)}"
        lines.append(line)
    limitations = _list_values(incident.evidence_limitations)
    lines.extend(f"- Limitation: {_markdown_text(item)}" for item in limitations)
    lines.append(
        "Raw source records are not expanded in Markdown. JSON may contain explicit serialization markers "
        "for circular, unsupported, inaccessible, depth-limited, or non-finite values; review those markers before "
        "treating the serialized evidence as complete. Review JSON for sensitive data before sharing."
    )
    return lines


def format_markdown(report: IncidentReport | IncidentReportCollection) -> str:
    """Render an escaped Markdown report without expanding raw source payloads."""
    if isinstance(report, IncidentReport):
        lines = ["# SOC Sentinel Incident Report", ""]
        lines.extend(_incident_markdown(report))
        return "\n".join(lines)
    if not isinstance(report, IncidentReportCollection):
        raise TypeError("format_markdown requires an IncidentReport or IncidentReportCollection.")

    lines = [
        "# SOC Sentinel Incident Report Collection",
        "",
        "## Collection Summary",
        f"- Schema version: {_markdown_text(report.schema_version)}",
        f"- Incidents: {len(report.incidents)}",
        f"- Original input records: {len(report.original_input_records)} (kept at collection level)",
        f"- Source batches: {_markdown_text(report.collection_metadata.get('original_input_batch_count', 'not recorded') if isinstance(report.collection_metadata, Mapping) else 'not recorded')}",
        "",
        "## Collection Diagnostics",
    ]
    diagnostics = _list_values(report.diagnostics)
    lines.extend(f"- {_markdown_item(item)}" for item in diagnostics) if diagnostics else lines.append("- None recorded.")
    lines.extend(("", "## Skipped Events"))
    skipped = _list_values(report.skipped_events)
    lines.extend(f"- {_markdown_item(item)}" for item in skipped) if skipped else lines.append("- None recorded.")
    lines.extend(("", "Collection-level records, diagnostics, and skipped events are not incident-specific evidence."))
    for incident in report.incidents:
        lines.extend(("", "---", ""))
        lines.extend(_incident_markdown(incident))
    return "\n".join(lines)
