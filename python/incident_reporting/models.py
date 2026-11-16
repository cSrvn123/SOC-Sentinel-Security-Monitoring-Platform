"""Data models for incident reports adapted from correlation cases.

Severity and conclusion values represent explicit analyst assessments. They are
not inferred from correlation confidence, IOC results, rules, event counts, or
recommendations. Source event records remain opaque Python values so this layer
does not mutate or lossy-serialize evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


SCHEMA_VERSION = "1.0"


class IncidentSeverity(str, Enum):
    """Analyst-assessed incident impact and urgency; never inferred by the model."""

    NOT_ASSESSED = "NOT_ASSESSED"
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        """Render the plain string value for callers using string formatting."""
        return self.value


class AnalystConclusion(str, Enum):
    """Explicit analyst conclusion; CONFIRMED_MALICIOUS is preferred for new assessments.

    ``MALICIOUS`` remains available as a legacy value and is never silently
    converted to ``CONFIRMED_MALICIOUS``.
    """

    NOT_ASSESSED = "NOT_ASSESSED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"

    def __str__(self) -> str:
        """Render the plain string value for callers using string formatting."""
        return self.value


def _validated_enum_value(value: Any, enum_type: type[Enum], field_name: str) -> Enum:
    """Return a valid enum member, accepting its string value for compatibility."""
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError:
            valid_values = ", ".join(member.value for member in enum_type)
            raise ValueError(f"{field_name} must be one of: {valid_values}.") from None
    raise TypeError(f"{field_name} must be a {enum_type.__name__} member or its string value.")


@dataclass
class IncidentEntities:
    """Entities explicitly surfaced by an InvestigationCase."""

    accounts: list[str] = field(default_factory=list)
    computers: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)


@dataclass
class EventProvenance:
    """Provenance attached to one related event, without asserting certainty."""

    related_event_index: int
    source_references: list[Any] = field(default_factory=list)
    source_identity: Any = None
    provenance_status: str = "unavailable"
    original_record: Any = None
    original_record_candidates: list[Any] = field(default_factory=list)
    additional_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentReport:
    """Incident-level view of one source correlation case.

    ``related_events`` retain the complete event mappings supplied by the
    correlation engine. Their nested source records are preserved by reference;
    the builder does not mutate or serialize caller-owned evidence.
    """

    incident_id: str
    schema_version: str
    source_case_id: str
    title: str
    confidence: Any
    confidence_explanation: Any
    related_events: list[Any] = field(default_factory=list)
    timeline: list[Any] = field(default_factory=list)
    entities: IncidentEntities = field(default_factory=IncidentEntities)
    evidence: list[Any] = field(default_factory=list)
    provenance: list[EventProvenance] = field(default_factory=list)
    missing_evidence: list[Any] = field(default_factory=list)
    recommendations: list[Any] = field(default_factory=list)
    evidence_limitations: list[Any] = field(default_factory=list)
    analyst_conclusion: AnalystConclusion = AnalystConclusion.NOT_ASSESSED
    severity: IncidentSeverity = IncidentSeverity.NOT_ASSESSED
    mitre_attack_mappings: list[dict[str, Any]] = field(default_factory=list)
    analyst_conclusion_rationale: str | None = None
    severity_rationale: str | None = None

    def __setattr__(self, name: str, value: Any) -> None:
        """Validate assessment values on initialization and every later assignment.

        Valid string values are normalized to their enum members. Validation is
        completed before assignment, so a rejected update leaves the old value
        intact. Assessment fields remain independently mutable.
        """
        if name == "severity":
            value = _validated_enum_value(value, IncidentSeverity, name)
        elif name == "analyst_conclusion":
            value = _validated_enum_value(value, AnalystConclusion, name)
        elif name in {"severity_rationale", "analyst_conclusion_rationale"}:
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be a string or None.")
        object.__setattr__(self, name, value)


@dataclass
class IncidentReportCollection:
    """A set of incidents plus batch-level correlation context.

    ``original_input_records`` contains each distinct source batch once. If
    cases refer to more than one distinct batch, ``collection_metadata`` records
    the boundaries so records are not silently conflated.
    """

    schema_version: str = SCHEMA_VERSION
    incidents: list[IncidentReport] = field(default_factory=list)
    diagnostics: list[Any] = field(default_factory=list)
    skipped_events: list[Any] = field(default_factory=list)
    original_input_records: list[Any] = field(default_factory=list)
    collection_metadata: dict[str, Any] = field(default_factory=dict)
