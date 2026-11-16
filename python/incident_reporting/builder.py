"""Adapter from Alert Correlation output to Stage 1 incident-report models."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from alert_correlation.models import CorrelationReport, InvestigationCase

from .models import (
    SCHEMA_VERSION,
    EventProvenance,
    IncidentEntities,
    IncidentReport,
    IncidentReportCollection,
)


_PROVENANCE_FIELDS = {
    "source_references",
    "source_identity",
    "provenance_status",
    "original_record",
    "original_record_candidates",
}
_IOC_LIMITATION_PREFIX = "IOC evidence serialization limitation:"


def _as_list(value: Any) -> list[Any]:
    """Copy a list-like field container while retaining its evidence values."""
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _related_event_copy(value: Any) -> Any:
    """Copy an event mapping's outer container without copying source records."""
    if isinstance(value, Mapping):
        return dict(value)
    return value


def _provenance_for(index: int, value: Any) -> EventProvenance:
    if not isinstance(value, Mapping):
        return EventProvenance(related_event_index=index)

    refs = value.get("source_references", [])
    candidates = value.get("original_record_candidates", [])
    status = value.get("provenance_status", "unavailable")
    # A missing or malformed status must never be upgraded to exact provenance.
    if not isinstance(status, str) or not status:
        status = "unavailable"
    return EventProvenance(
        related_event_index=index,
        source_references=_as_list(refs),
        source_identity=value.get("source_identity"),
        provenance_status=status,
        original_record=value.get("original_record"),
        original_record_candidates=_as_list(candidates),
        additional_fields={key: item for key, item in value.items() if key not in _PROVENANCE_FIELDS},
    )


def _evidence_limitations(case: InvestigationCase) -> list[Any]:
    limitations = list(_as_list(case.source_issues))
    for item in _as_list(case.evidence):
        if isinstance(item, str) and item.startswith(_IOC_LIMITATION_PREFIX) and item not in limitations:
            limitations.append(item)
    for index, event in enumerate(_as_list(case.related_events)):
        if not isinstance(event, Mapping):
            continue
        status = event.get("provenance_status")
        candidates = event.get("original_record_candidates")
        if status == "ambiguous":
            note = f"Related event {index} has ambiguous original-record provenance."
            if note not in limitations:
                limitations.append(note)
        if isinstance(candidates, (list, tuple)) and len(candidates) > 1:
            note = f"Related event {index} has multiple original-record candidates."
            if note not in limitations:
                limitations.append(note)
    return limitations


def _incident(case: InvestigationCase, duplicate_number: int | None = None) -> IncidentReport:
    if not isinstance(case, InvestigationCase):
        raise TypeError("build_incident_report_collection accepts InvestigationCase objects only.")

    source_case_id = case.case_id
    incident_id = f"INC-{source_case_id}"
    if duplicate_number is not None:
        incident_id = f"{incident_id}-{duplicate_number}"

    related_events = [_related_event_copy(item) for item in _as_list(case.related_events)]
    return IncidentReport(
        incident_id=incident_id,
        schema_version=SCHEMA_VERSION,
        source_case_id=source_case_id,
        title=case.detection_pattern,
        confidence=case.confidence,
        confidence_explanation=case.confidence_explanation,
        related_events=related_events,
        # Stage 1 has no independent timeline interpretation policy yet.
        timeline=[],
        entities=IncidentEntities(
            accounts=list(_as_list(case.accounts)),
            computers=list(_as_list(case.computers)),
            ips=list(_as_list(case.ips)),
        ),
        evidence=list(_as_list(case.evidence)),
        provenance=[_provenance_for(index, item) for index, item in enumerate(related_events)],
        missing_evidence=list(_as_list(case.missing_evidence)),
        recommendations=list(_as_list(case.recommendations)),
        evidence_limitations=_evidence_limitations(case),
    )


def _identity_batch_key(records: list[Any]) -> tuple[int, ...]:
    """Identify repeated copies of the same shared source batch by object identity."""
    return tuple(id(record) for record in records)


def build_incident_report_collection(
    source: CorrelationReport | Iterable[InvestigationCase],
) -> IncidentReportCollection:
    """Adapt correlation cases without changing source cases or event evidence.

    A CorrelationReport contributes its diagnostics and skipped events. An
    ordinary iterable contributes neither. Since the correlation engine stores
    the complete input batch on every case, identical batches are retained once
    at collection level. Distinct batches are concatenated once each, with
    boundaries recorded in collection metadata. Case-specific associated source
    records and ambiguous candidates remain in each incident's provenance.
    """
    is_correlation_report = isinstance(source, CorrelationReport)
    if is_correlation_report:
        cases = list(source)
        diagnostics = list(source.diagnostics)
        skipped_events = list(source.skipped_events)
    else:
        cases = list(source)
        diagnostics = []
        skipped_events = []

    duplicate_ids: dict[str, int] = {}
    incidents: list[IncidentReport] = []
    for case in cases:
        if not isinstance(case, InvestigationCase):
            raise TypeError("build_incident_report_collection accepts InvestigationCase objects only.")
        count = duplicate_ids.get(case.case_id, 0) + 1
        duplicate_ids[case.case_id] = count
        incidents.append(_incident(case, count if count > 1 else None))

    unique_batches: list[tuple[list[Any], list[str]]] = []
    batch_index_by_key: dict[tuple[int, ...], int] = {}
    for case in cases:
        records = _as_list(case.source_records)
        if not records:
            continue
        key = _identity_batch_key(records)
        existing_index = batch_index_by_key.get(key)
        if existing_index is not None:
            unique_batches[existing_index][1].append(case.case_id)
            continue
        batch_index_by_key[key] = len(unique_batches)
        unique_batches.append((records, [case.case_id]))

    original_records: list[Any] = []
    batch_boundaries: list[dict[str, Any]] = []
    for batch_index, (records, source_case_ids) in enumerate(unique_batches):
        start = len(original_records)
        original_records.extend(records)
        batch_boundaries.append({
            "batch_index": batch_index,
            "start": start,
            "count": len(records),
            "source_case_ids": list(source_case_ids),
        })

    return IncidentReportCollection(
        schema_version=SCHEMA_VERSION,
        incidents=incidents,
        diagnostics=diagnostics,
        skipped_events=skipped_events,
        original_input_records=original_records,
        collection_metadata={
            "source_type": "CorrelationReport" if is_correlation_report else "InvestigationCase iterable",
            "source_case_count": len(cases),
            "original_input_batch_count": len(unique_batches),
            "original_input_batch_boundaries": batch_boundaries,
        },
    )
