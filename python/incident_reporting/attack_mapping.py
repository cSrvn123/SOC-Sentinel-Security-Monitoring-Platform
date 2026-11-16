"""Explicit, evidence-backed ATT&CK mappings for incident reports.

No ATT&CK catalogue is bundled, so this module validates identifier syntax
only. Every mapping is marked UNVERIFIED until checked against a pinned local
reference. Mapping creation is analyst-directed and performs no inference.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .models import IncidentReport


_TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
_MISSING = object()
_AMBIGUOUS_STATUSES = {"ambiguous", "ambiguous-equivalent"}


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must be a non-empty string.")
    return normalized


def _mapping_value(value: Mapping[str, Any], key: str, context: str) -> Any:
    try:
        return value.get(key, _MISSING)
    except Exception as error:
        error_type = f"{type(error).__module__}.{type(error).__qualname__}"
        raise ValueError(f"Cannot safely read {context}.{key} ({error_type}).") from None


def _string_references(value: Any, context: str) -> list[str]:
    if value is _MISSING or value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        if any(not isinstance(item, str) for item in value):
            raise TypeError(f"{context} must contain only strings.")
        return list(value)
    raise TypeError(f"{context} must be a string, list of strings, tuple of strings, or None.")


def _status_value(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "unavailable"
    return value.strip()


def _combined_provenance_status(statuses: list[str], unresolved: bool) -> str:
    normalized = [status.casefold() for status in statuses]
    if any(status in _AMBIGUOUS_STATUSES for status in normalized):
        return "ambiguous"
    if unresolved or not normalized or "unavailable" in normalized:
        return "unavailable"
    if len(set(normalized)) > 1:
        return "unavailable"
    return statuses[0]


def _evidence_reference(incident: IncidentReport, related_event_index: int) -> dict[str, Any]:
    event = incident.related_events[related_event_index]
    references: list[str] = []
    statuses: list[str] = []
    unresolved_provenance = False

    if isinstance(event, Mapping):
        raw_references = _mapping_value(event, "source_references", "related event")
        references.extend(_string_references(raw_references, "related-event source_references"))
        raw_status = _mapping_value(event, "provenance_status", "related event")
        statuses.append(_status_value(raw_status))
    else:
        # A malformed event cannot establish either a source reference or an
        # affirmative provenance status. Its index remains the explicit anchor.
        statuses.append("unavailable")

    for provenance_index, provenance in enumerate(incident.provenance):
        try:
            provenance_event_index = getattr(provenance, "related_event_index")
        except Exception:
            unresolved_provenance = True
            continue
        if (not isinstance(provenance_event_index, int)
                or isinstance(provenance_event_index, bool)
                or provenance_event_index < 0
                or provenance_event_index >= len(incident.related_events)):
            unresolved_provenance = True
            continue
        if provenance_event_index != related_event_index:
            continue

        try:
            raw_references = getattr(provenance, "source_references", None)
            raw_status = getattr(provenance, "provenance_status", "unavailable")
        except Exception as error:
            error_type = f"{type(error).__module__}.{type(error).__qualname__}"
            raise ValueError(
                f"Cannot safely read aligned provenance entry {provenance_index} ({error_type})."
            ) from None
        references.extend(_string_references(raw_references, "provenance source_references"))
        statuses.append(_status_value(raw_status))

    return {
        "related_event_index": related_event_index,
        "source_references": references,
        "provenance_status": _combined_provenance_status(statuses, unresolved_provenance),
    }


def add_attack_mapping(
    incident: IncidentReport,
    *,
    technique_id: str,
    technique_name: str,
    rationale: str,
    evidence_references: list[int] | tuple[int, ...],
    tactic: str | None = None,
) -> dict[str, Any]:
    """Validate and append one explicitly supplied ATT&CK mapping.

    ``evidence_references`` contains related-event indices, the canonical
    incident-local references. The returned mapping is a JSON-friendly dict
    containing source-reference strings and conservative provenance statuses,
    never raw source records. All validation completes before the incident is
    changed. Technique syntax is checked, but existence is not verified because
    no pinned local ATT&CK dataset is available.
    """
    if not isinstance(incident, IncidentReport):
        raise TypeError("add_attack_mapping requires an IncidentReport.")
    if not isinstance(technique_id, str):
        raise TypeError("technique_id must be a string.")
    if _TECHNIQUE_ID.fullmatch(technique_id) is None:
        raise ValueError("technique_id must match Tdddd or Tdddd.ddd syntax.")
    normalized_name = _required_text(technique_name, "technique_name")
    normalized_rationale = _required_text(rationale, "rationale")
    if tactic is not None:
        tactic = _required_text(tactic, "tactic")
    if not isinstance(evidence_references, (list, tuple)):
        raise TypeError("evidence_references must be a list or tuple of related-event indices.")
    if not evidence_references:
        raise ValueError("At least one related-event evidence reference is required.")

    validated_indices: list[int] = []
    for index in evidence_references:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("Each evidence reference must be an integer related-event index.")
        if index < 0 or index >= len(incident.related_events):
            raise ValueError(f"related_event_index {index} is outside incident.related_events.")
        validated_indices.append(index)

    if not isinstance(incident.mitre_attack_mappings, list):
        raise TypeError("incident.mitre_attack_mappings must remain a list of dictionaries.")

    mapping = {
        "technique_id": technique_id,
        "technique_name": normalized_name,
        "tactic": tactic,
        "rationale": normalized_rationale,
        "evidence_references": [
            _evidence_reference(incident, index) for index in validated_indices
        ],
        "reference_status": "UNVERIFIED",
    }
    incident.mitre_attack_mappings.append(mapping)
    return mapping
