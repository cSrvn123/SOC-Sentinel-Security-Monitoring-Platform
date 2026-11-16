"""Timeline construction for Stage 1 incident-report objects.

Timeline entries reference incident.related_events by index. They do not copy,
serialize, or reconstruct original source records.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal
from collections.abc import Mapping

from .models import IncidentReport, IncidentReportCollection


TimestampStatus = Literal["valid", "missing", "invalid"]
_MISSING = object()
_AMBIGUOUS_STATUSES = {"ambiguous", "ambiguous-equivalent"}


@dataclass
class TimelineEntry:
    """Chronological pointer to one related event in an IncidentReport."""

    original_timestamp: Any
    normalized_timestamp_utc: str | None
    timestamp_status: TimestampStatus
    related_event_index: int
    event_source: Any = None
    event_id: Any = None
    event_type: Any = None
    source_references: list[Any] = field(default_factory=list)
    provenance_status: str = "unavailable"
    provenance_indices: list[int] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


def _timestamp(value: Any, *, field_present: bool) -> tuple[Any, datetime | None, TimestampStatus]:
    """Return original value, UTC value for sorting, and explicit status."""
    if not field_present or value is None or (isinstance(value, str) and not value.strip()):
        return value, None, "missing"
    if not isinstance(value, str):
        return value, None, "invalid"

    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return value, None, "invalid"
        normalized = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return value, None, "invalid"
    return value, normalized, "valid"


def _provenance_lookup(
    incident: IncidentReport,
) -> tuple[dict[int, list[tuple[int, Any]]], list[str]]:
    lookup: dict[int, list[tuple[int, Any]]] = {}
    diagnostics: list[str] = []
    for provenance_index, provenance in enumerate(incident.provenance):
        try:
            related_index = getattr(provenance, "related_event_index", None)
        except Exception as error:
            error_type = f"{type(error).__module__}.{type(error).__qualname__}"
            diagnostics.append(
                f"Incident-level provenance entry {provenance_index} could not be linked because "
                f"related_event_index access raised {error_type}; it was not assigned to a related event."
            )
            continue
        if isinstance(related_index, int) and not isinstance(related_index, bool):
            lookup.setdefault(related_index, []).append((provenance_index, provenance))
    return lookup, diagnostics


def _mapping_get(mapping: Mapping, key: str, diagnostics: list[str], path: str) -> Any:
    """Read one mapping field without letting a broken mapping abort the timeline."""
    try:
        return mapping.get(key, _MISSING)
    except Exception as error:
        error_type = f"{type(error).__module__}.{type(error).__qualname__}"
        diagnostics.append(f"Related event field {path}.{key} could not be read ({error_type}).")
        return _MISSING


def _event_fields(value: Any) -> tuple[Any, Any, Any, Any, bool, list[str]]:
    """Read only the known related-event wrapper and normalized event fields."""
    diagnostics: list[str] = []
    if not isinstance(value, Mapping):
        return None, None, None, None, False, ["Related event is not a mapping; event fields are unavailable."]
    event = _mapping_get(value, "event", diagnostics, "related_event")
    if event is _MISSING or not isinstance(event, Mapping):
        if event is not _MISSING:
            diagnostics.append("Related event has no normalized event mapping; event fields are unavailable.")
        else:
            diagnostics.append("Related event normalized event mapping is unavailable.")
        return None, None, None, None, False, diagnostics

    timestamp = _mapping_get(event, "timestamp", diagnostics, "related_event.event")
    source = _mapping_get(event, "event_source", diagnostics, "related_event.event")
    event_id = _mapping_get(event, "event_id", diagnostics, "related_event.event")
    event_type = _mapping_get(event, "event_type", diagnostics, "related_event.event")
    if timestamp is _MISSING:
        has_timestamp = False
        timestamp_value = None
    else:
        has_timestamp = True
        timestamp_value = timestamp
    return (
        timestamp_value,
        None if source is _MISSING else source,
        None if event_id is _MISSING else event_id,
        None if event_type is _MISSING else event_type,
        has_timestamp,
        diagnostics,
    )


def _related_event_provenance(value: Any, diagnostics: list[str]) -> tuple[list[Any], Any]:
    if not isinstance(value, Mapping):
        return [], None
    references = _mapping_get(value, "source_references", diagnostics, "related_event")
    status = _mapping_get(value, "provenance_status", diagnostics, "related_event")
    if references is _MISSING or references is None:
        normalized_references: list[Any] = []
    elif isinstance(references, (list, tuple)):
        normalized_references = list(references)
    else:
        normalized_references = [references]
    return normalized_references, None if status is _MISSING else status


def _aligned_provenance_status(value: Any, diagnostics: list[str], index: int) -> str:
    try:
        status = getattr(value, "provenance_status", "unavailable")
    except Exception as error:
        diagnostics.append(
            f"Aligned provenance entry {index} status could not be read "
            f"({type(error).__module__}.{type(error).__qualname__})."
        )
        return "unavailable"
    return status if isinstance(status, str) and status else "unavailable"


def _build_entry(
    incident: IncidentReport,
    index: int,
    value: Any,
    provenance_lookup: dict[int, list[tuple[int, Any]]],
) -> tuple[TimelineEntry, datetime | None]:
    original, source, event_id, event_type, has_timestamp, diagnostics = _event_fields(value)
    original, normalized, status = _timestamp(original, field_present=has_timestamp)

    matches = provenance_lookup.get(index, [])
    provenance_indices = [item[0] for item in matches]
    wrapper_references, wrapper_status = _related_event_provenance(value, diagnostics)

    if len(matches) == 1:
        provenance = matches[0][1]
        try:
            references_value = getattr(provenance, "source_references", None)
        except Exception as error:
            references_value = None
            diagnostics.append(
                "Aligned provenance source references could not be read "
                f"({type(error).__module__}.{type(error).__qualname__})."
            )
        if isinstance(references_value, (list, tuple)):
            references = list(references_value)
        else:
            references = [] if references_value is None else [references_value]
        provenance_status = _aligned_provenance_status(provenance, diagnostics, matches[0][0])
        status_conflict = wrapper_status is not None and wrapper_status != provenance_status
        if status_conflict:
            conflicting_statuses = (wrapper_status, provenance_status)
            ambiguous_status = next(
                (item for item in conflicting_statuses
                 if isinstance(item, str) and item in _AMBIGUOUS_STATUSES),
                None,
            )
            # If the two representations disagree, never preserve the more certain
            # interpretation. Retain ambiguity when either side explicitly has it.
            provenance_status = ambiguous_status or "unavailable"
            diagnostics.append(
                "Related-event and aligned provenance statuses conflict "
                f"(related_event={wrapper_status!r}, aligned={conflicting_statuses[1]!r}); "
                f"timeline status is conservatively {provenance_status!r}."
            )
        if wrapper_references != references:
            diagnostics.append("Related-event and aligned provenance metadata differ; both source structures remain available by index.")
    elif len(matches) > 1:
        references = wrapper_references
        statuses: list[str] = []
        if wrapper_status is not None:
            statuses.append(wrapper_status if isinstance(wrapper_status, str) and wrapper_status else "unavailable")
        statuses.extend(
            _aligned_provenance_status(provenance, diagnostics, provenance_index)
            for provenance_index, provenance in matches
        )
        if any(status in _AMBIGUOUS_STATUSES for status in statuses):
            provenance_status = "ambiguous"
        elif "unavailable" in statuses or len(set(statuses)) > 1:
            provenance_status = "unavailable"
        else:
            provenance_status = statuses[0] if statuses else "unavailable"
        diagnostics.append("Multiple provenance entries refer to this related-event index; no single provenance entry was selected.")
    else:
        references = wrapper_references
        provenance_status = wrapper_status if isinstance(wrapper_status, str) and wrapper_status else "unavailable"

    if not isinstance(value, Mapping):
        # Retain provenance linked by index even when the event wrapper is malformed.
        if matches:
            diagnostics.append("Related event structure is malformed; provenance was retained by its related-event index.")
    if status != "valid":
        diagnostics.append(f"Related event timestamp is {status}; no timeline timestamp was invented.")

    entry = TimelineEntry(
        original_timestamp=original,
        normalized_timestamp_utc=normalized.isoformat() if normalized is not None else None,
        timestamp_status=status,
        related_event_index=index,
        event_source=source,
        event_id=event_id,
        event_type=event_type,
        source_references=references,
        provenance_status=provenance_status if isinstance(provenance_status, str) else "unavailable",
        provenance_indices=provenance_indices,
        diagnostics=diagnostics,
    )
    return entry, normalized


def build_timeline(incident: IncidentReport) -> list[TimelineEntry]:
    """Build a chronological timeline only from ``incident.related_events``.

    Original timestamp strings are retained verbatim. Offset-aware timestamps
    are normalized to UTC only to determine order. Missing or invalid timestamps
    remain represented by entries at the end, ordered by their original event
    index. Provenance is linked by index and is never upgraded to a more certain
    status.
    """
    if not isinstance(incident, IncidentReport):
        raise TypeError("build_timeline requires an IncidentReport.")

    provenance_lookup, provenance_diagnostics = _provenance_lookup(incident)
    sortable: list[tuple[TimelineEntry, datetime | None]] = []
    for index, related_event in enumerate(incident.related_events):
        sortable.append(_build_entry(incident, index, related_event, provenance_lookup))

    if sortable and provenance_diagnostics:
        # These entries could not be associated with an event index. Surface the
        # incident-level issue without attaching those records to this event.
        sortable[0][0].diagnostics.extend(provenance_diagnostics)

    sortable.sort(key=lambda item: (
        0 if item[1] is not None else 1,
        item[1] if item[1] is not None else datetime.min.replace(tzinfo=timezone.utc),
        item[0].related_event_index,
    ))
    return [entry for entry, _ in sortable]


def build_timelined_collection(collection: IncidentReportCollection) -> IncidentReportCollection:
    """Return a new collection with timelines, leaving the Stage 1 input intact.

    This additive integration fills the existing ``IncidentReport.timeline``
    placeholder using ``build_timeline``. Incident records and collection-level
    context are copied as containers; raw source evidence remains referenced, not
    duplicated or reconstructed.
    """
    if not isinstance(collection, IncidentReportCollection):
        raise TypeError("build_timelined_collection requires an IncidentReportCollection.")

    incidents = [replace(incident, timeline=build_timeline(incident)) for incident in collection.incidents]
    return replace(
        collection,
        incidents=incidents,
        diagnostics=list(collection.diagnostics),
        skipped_events=list(collection.skipped_events),
        original_input_records=list(collection.original_input_records),
        collection_metadata=dict(collection.collection_metadata),
    )
