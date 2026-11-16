"""Structured investigation cases emitted by the correlation engine."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvestigationCase:
    case_id: str
    detection_pattern: str
    first_observed: str
    last_observed: str
    related_events: list[dict[str, Any]]
    accounts: list[str]
    computers: list[str]
    ips: list[str]
    evidence: list[str]
    missing_evidence: list[str]
    recommendations: list[str]
    confidence: str
    confidence_explanation: str
    source_records: list[object] = field(default_factory=list)
    source_issues: list[str] = field(default_factory=list)


class CorrelationReport(list[InvestigationCase]):
    """List-compatible cases with an owned snapshot of preparation metadata.

    The case collection intentionally remains mutable for compatibility with list
    callers. Diagnostics and skipped-event metadata describe the original
    correlation run: initial case ``source_issues`` are captured into diagnostics
    once at construction, and accessors return defensive copies. Editing a returned
    metadata value or changing the case list afterward cannot silently mutate that
    run metadata. Case-level ``source_issues`` remain attached to each live case.
    """

    def __init__(self, cases=(), diagnostics=(), skipped_events=()):
        case_snapshot = list(cases)
        diagnostic_snapshot = list(diagnostics)
        # Capture case-level source issues once, at report construction. Later
        # mutations to a case must not rewrite the correlation-run metadata.
        for case in case_snapshot:
            for issue in getattr(case, "source_issues", ()) or ():
                if issue not in diagnostic_snapshot:
                    diagnostic_snapshot.append(issue)
        super().__init__(case_snapshot)
        self._diagnostics = tuple(diagnostic_snapshot)
        self._skipped_events = tuple(copy.deepcopy(list(skipped_events)))

    @property
    def diagnostics(self) -> list[str]:
        """Return a mutable copy of diagnostics for this correlation run."""
        return list(self._diagnostics)

    @property
    def skipped_events(self) -> list[dict[str, Any]]:
        """Return a deep copy of skipped-event details for this run."""
        return copy.deepcopy(list(self._skipped_events))

    @property
    def cases(self) -> "CorrelationReport":
        return self

