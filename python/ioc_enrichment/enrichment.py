"""Orchestration that combines syntax validation with a reputation provider."""

from __future__ import annotations

from typing import Protocol

from .models import EnrichmentResult, Indicator, ReputationResult
from .reputation import OfflineReputationProvider
from .validation import validate_indicator


class ReputationProvider(Protocol):
    def lookup(self, indicator: Indicator) -> ReputationResult: ...


def enrich_indicator(value: str, provider: ReputationProvider | None = None) -> EnrichmentResult:
    validation = validate_indicator(value)
    if not validation.valid:
        return EnrichmentResult(validation.indicator, validation.indicator_type.value, "invalid", "not_checked",
            "unknown", "Not queried", "Correct the indicator format before enrichment.", validation.reason)
    reputation = (provider or OfflineReputationProvider()).lookup(Indicator(validation.indicator, validation.indicator_type))
    return EnrichmentResult(validation.indicator, validation.indicator_type.value, "valid",
        reputation.reputation_status, reputation.risk_classification, reputation.source,
        reputation.recommendation, validation.reason, reputation.malicious,
        reputation.suspicious, reputation.harmless, reputation.error)
