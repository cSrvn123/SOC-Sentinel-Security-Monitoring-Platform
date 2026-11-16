"""Readable serialization of alert-correlation cases."""

from __future__ import annotations

import json
import math
from dataclasses import fields, is_dataclass
from datetime import date, datetime, time
from enum import Enum
from typing import Iterable
from collections.abc import Mapping

from .models import CorrelationReport, InvestigationCase


DISCLAIMER = "Correlation cases are investigation prompts; confidence is match strength, not proof of compromise."
MAX_SERIALIZATION_DEPTH = 128


def _report_metadata(cases: Iterable[InvestigationCase]) -> tuple[bool, list[str], list[dict]]:
    if not isinstance(cases, CorrelationReport):
        return False, [], []
    return True, cases.diagnostics, cases.skipped_events


def _type_name(value: object) -> str:
    cls = type(value)
    return f"{cls.__module__}.{cls.__qualname__}"


def _serialization_marker(kind: str, value: object, **details: object) -> dict[str, object]:
    return {"$serialization_marker": kind, "$type": _type_name(value), **details}


def _json_safe(value: object, *, path: str, active: dict[int, str], depth: int = 0) -> object:
    """Convert case data to JSON-native structures without mutating source values.

    ``active`` tracks only the current recursion path. A shared object encountered
    in separate branches is serialized again; only a back-edge to an active object
    is marked as a circular reference. Structured objects use ``$type`` with
    ``$fields`` or ``$attributes``. Values that cannot be represented natively use
    ``$serialization_marker`` values such as ``circular_reference``,
    ``unsupported_value``, ``non_finite_number``, or ``attribute_unavailable``.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return _serialization_marker("non_finite_number", value, value_text=str(value))
    if isinstance(value, (datetime, date, time)):
        return {"$type": _type_name(value), "$value": value.isoformat()}

    identity = id(value)
    if identity in active:
        return _serialization_marker("circular_reference", value, **{"$reference_to": active[identity]})
    if depth >= MAX_SERIALIZATION_DEPTH:
        return _serialization_marker(
            "maximum_depth_exceeded", value, **{"$max_depth": MAX_SERIALIZATION_DEPTH}
        )
    if isinstance(value, Enum):
        return {"$type": _type_name(value), "$value": _json_safe(
            value.value, path=f"{path}.$value", active=active, depth=depth + 1
        )}

    if isinstance(value, Mapping):
        try:
            entries = list(value.items())
        except Exception as error:
            return _serialization_marker(
                "mapping_unavailable", value, error_type=_type_name(error)
            )
        active[identity] = path
        if all(isinstance(key, str) for key, _ in entries):
            result: object = {
                key: _json_safe(item, path=f"{path}.{key}", active=active, depth=depth + 1)
                for key, item in entries
            }
        else:
            result = {
                "$type": _type_name(value),
                "$mapping_entries": [
                    {
                        "key": _json_safe(key, path=f"{path}.<key>", active=active, depth=depth + 1),
                        "value": _json_safe(item, path=f"{path}.<value>", active=active, depth=depth + 1),
                    }
                    for key, item in entries
                ],
            }
        active.pop(identity, None)
        return result
    if isinstance(value, list):
        active[identity] = path
        result = [_json_safe(item, path=f"{path}[{index}]", active=active, depth=depth + 1)
                  for index, item in enumerate(value)]
        active.pop(identity, None)
        return result
    if isinstance(value, tuple):
        active[identity] = path
        items = [_json_safe(item, path=f"{path}[{index}]", active=active, depth=depth + 1)
                 for index, item in enumerate(value)]
        active.pop(identity, None)
        return {"$type": _type_name(value), "$items": items}

    if is_dataclass(value) and not isinstance(value, type):
        active[identity] = path
        result_fields = {}
        for item in fields(value):
            field_path = f"{path}.{item.name}"
            try:
                field_value = getattr(value, item.name)
            except Exception as error:
                result_fields[item.name] = _serialization_marker(
                    "attribute_unavailable", value,
                    **{"$field": item.name, "$error_type": _type_name(error)}
                )
            else:
                result_fields[item.name] = _json_safe(
                    field_value, path=field_path, active=active, depth=depth + 1
                )
        active.pop(identity, None)
        return {"$type": _type_name(value), "$fields": result_fields}

    attributes_error = None
    try:
        attributes = getattr(value, "__dict__", None)
    except Exception as error:
        attributes = None
        attributes_error = _type_name(error)
    if isinstance(attributes, Mapping):
        try:
            attribute_items = list(attributes.items())
        except Exception as error:
            attributes_error = _type_name(error)
        else:
            active[identity] = path
            result_attributes = {
                str(key): _json_safe(item, path=f"{path}.{key}", active=active, depth=depth + 1)
                for key, item in attribute_items
                if not str(key).startswith("__")
            }
            active.pop(identity, None)
            return {"$type": _type_name(value), "$attributes": result_attributes}

    slot_names = []
    for cls in type(value).__mro__:
        slots = cls.__dict__.get("__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        slot_names.extend(name for name in slots if isinstance(name, str))
    slot_values = {}
    slot_errors = {}
    for name in dict.fromkeys(slot_names):
        if name.startswith("__"):
            continue
        try:
            slot_values[name] = getattr(value, name)
        except AttributeError as error:
            slot_errors[name] = _serialization_marker(
                "attribute_unavailable", value,
                **{"$field": name, "$error_type": _type_name(error)}
            )
        except Exception as error:
            slot_errors[name] = _serialization_marker(
                "attribute_unavailable", value,
                **{"$field": name, "$error_type": _type_name(error)}
            )
    if slot_values or slot_errors:
        active[identity] = path
        result_attributes = {name: _json_safe(item, path=f"{path}.{name}", active=active, depth=depth + 1)
                             for name, item in slot_values.items()}
        active.pop(identity, None)
        result = {"$type": _type_name(value), "$attributes": result_attributes}
        if slot_errors or attributes_error:
            if attributes_error:
                slot_errors["__dict__"] = _serialization_marker(
                    "attribute_unavailable", value,
                    **{"$field": "__dict__", "$error_type": attributes_error}
                )
            result["$attribute_errors"] = slot_errors
        return result

    if attributes_error:
        return _serialization_marker("attributes_unavailable", value, error_type=attributes_error)

    return _serialization_marker("unsupported_value", value)


def _source_evidence_limitations(case: InvestigationCase) -> list[tuple[str, str]]:
    """Find source-record serialization limitations without rendering raw payloads.

    This iterative walk mirrors ``_json_safe``'s depth, cycle, dataclass, mapping,
    instance-attribute, and slot handling. It reports only limitation type and path.
    """
    findings: dict[tuple[str, str], None] = {}
    active: set[int] = {id(case)}
    stack: list[tuple[str, object, int, str]] = []
    records = case.source_records
    if isinstance(records, (list, tuple)):
        for index in range(len(records) - 1, -1, -1):
            stack.append(("visit", records[index], 1, f"source_records[{index}]"))
    elif records is not None:
        stack.append(("visit", records, 0, "source_records"))

    def record(kind: str, path: str) -> None:
        findings[(kind, path)] = None

    while stack:
        action, value, depth, path = stack.pop()
        if action == "leave":
            active.discard(id(value))
            continue
        if value is None or isinstance(value, (str, bool, int)):
            continue
        if isinstance(value, float):
            if not math.isfinite(value):
                record("non_finite_number", path)
            continue
        if isinstance(value, (datetime, date, time)):
            continue

        identity = id(value)
        if identity in active:
            record("circular_reference", path)
            continue
        if depth >= MAX_SERIALIZATION_DEPTH:
            record("maximum_depth_exceeded", path)
            continue
        if isinstance(value, Enum):
            stack.append(("visit", value.value, depth + 1, f"{path}.$value"))
            continue

        children: list[tuple[object, str]] = []
        if isinstance(value, Mapping):
            try:
                items = list(value.items())
            except Exception:
                record("mapping_unavailable", path)
                continue
            if all(isinstance(key, str) for key, _ in items):
                children.extend((item, f"{path}.{key}") for key, item in items)
            else:
                for key, item in items:
                    children.append((key, f"{path}.<key>"))
                    children.append((item, f"{path}.<value>"))
        elif isinstance(value, (list, tuple)):
            children.extend((item, f"{path}[{index}]") for index, item in enumerate(value))
        elif is_dataclass(value) and not isinstance(value, type):
            try:
                dataclass_fields = fields(value)
            except Exception:
                record("attributes_unavailable", path)
                continue
            for item in dataclass_fields:
                field_path = f"{path}.{item.name}"
                try:
                    child = getattr(value, item.name)
                except Exception:
                    record("attribute_unavailable", field_path)
                else:
                    children.append((child, field_path))
        else:
            attributes_error = None
            try:
                attributes = getattr(value, "__dict__", None)
            except Exception:
                attributes = None
                attributes_error = True
            if isinstance(attributes, Mapping):
                try:
                    children.extend(
                        (item, f"{path}.{key}") for key, item in attributes.items()
                        if not str(key).startswith("__")
                    )
                except Exception:
                    attributes_error = True
                    attributes = None
            if not isinstance(attributes, Mapping):
                slot_names = []
                for cls in type(value).__mro__:
                    slots = cls.__dict__.get("__slots__", ())
                    if isinstance(slots, str):
                        slots = (slots,)
                    slot_names.extend(name for name in slots if isinstance(name, str))
                public_slots = [name for name in dict.fromkeys(slot_names) if not name.startswith("__")]
                for name in public_slots:
                    field_path = f"{path}.{name}"
                    try:
                        child = getattr(value, name)
                    except Exception:
                        record("attribute_unavailable", field_path)
                    else:
                        children.append((child, field_path))
                if attributes_error and public_slots:
                    record("attribute_unavailable", f"{path}.__dict__")
                if not public_slots and not attributes_error:
                    record("unsupported_value", path)
                elif not public_slots and attributes_error:
                    record("attributes_unavailable", path)

        active.add(identity)
        stack.append(("leave", value, depth, path))
        for child, child_path in reversed(children):
            stack.append(("visit", child, depth + 1, child_path))

    return list(findings)


def _case_dict(case: InvestigationCase) -> dict[str, object]:
    """Serialize case fields individually so raw records use safe cycle handling."""
    active = {id(case): "case"}
    result = {}
    for item in fields(case):
        result[item.name] = _json_safe(getattr(case, item.name), path=f"case.{item.name}", active=active)
    active.pop(id(case), None)
    return result


def format_json(cases: Iterable[InvestigationCase]) -> str:
    """Format cases; include report diagnostics when passed a CorrelationReport.

    Ordinary iterables retain the legacy ``disclaimer`` and ``cases`` shape.
    """
    is_report, diagnostics, skipped_events = _report_metadata(cases)
    payload = {
        "disclaimer": DISCLAIMER,
        "cases": [_case_dict(case) for case in cases],
    }
    if is_report:
        payload["diagnostics"] = diagnostics
        payload["skipped_events"] = skipped_events
    return json.dumps(payload, indent=2, ensure_ascii=True, allow_nan=False)


def format_text(cases: Iterable[InvestigationCase]) -> str:
    items = list(cases)
    lines = ["SOC Sentinel Correlation Cases", f"Cases: {len(items)}", DISCLAIMER]
    is_report, diagnostics, skipped_events = _report_metadata(cases)
    if is_report:
        lines.extend(("", f"Diagnostics ({len(diagnostics)}):"))
        lines.extend("- " + item for item in diagnostics)
        lines.extend(("", f"Skipped events ({len(skipped_events)}):"))
        for item in skipped_events:
            event_parts = []
            if item.get("event_source"):
                event_parts.append(str(item["event_source"]))
            if item.get("event_id") is not None:
                event_parts.append("Event ID " + str(item["event_id"]))
            if item.get("event_index") is not None:
                event_parts.append("normalized position " + str(item["event_index"]))
            label = ", ".join(event_parts) or "Input event"
            lines.append(f"- {label}: {item.get('reason', 'unspecified exclusion reason')}")
    source_limitations = [
        (case.case_id, kind, path)
        for case in items
        for kind, path in _source_evidence_limitations(case)
    ]
    if source_limitations:
        lines.extend(("", "Original source evidence limitations (payload not expanded):"))
        lines.extend(
            f"- Case {case_id}: {kind} at {path}. JSON preserves a marker at this location; the source evidence may be incomplete."
            for case_id, kind, path in source_limitations
        )
    for case in items:
        lines.extend(("", f"{case.case_id} - {case.detection_pattern}",
            f"Observed: {case.first_observed} through {case.last_observed}",
            f"Confidence: {case.confidence} - {case.confidence_explanation}"))
        for label, values in (("Accounts", case.accounts), ("Computers", case.computers), ("IPs", case.ips)):
            lines.append(f"{label}: {', '.join(values) if values else 'none recorded'}")
        lines.extend("Evidence: " + value for value in case.evidence)
        lines.extend("Missing evidence: " + value for value in case.missing_evidence)
        lines.extend("Recommendation: " + value for value in case.recommendations)
        lines.extend("Source reference: " + ref for related in case.related_events for ref in related["source_references"])
        if is_report and case.source_issues:
            lines.extend("Case source issue: " + issue for issue in case.source_issues)
    return "\n".join(lines)
