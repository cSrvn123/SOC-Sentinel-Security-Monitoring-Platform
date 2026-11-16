"""Data structures shared by IOC enrichment providers and formatters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .classification import IndicatorType


@dataclass(frozen=True)
class ReputationResult:
    reputation_status: str
    risk_classification: str
    source: str
    recommendation: str
    malicious: Optional[int] = None
    suspicious: Optional[int] = None
    harmless: Optional[int] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class EnrichmentResult:
    indicator: str
    indicator_type: str
    validation_status: str
    reputation_status: str
    risk_classification: str
    source: str
    investigation_recommendation: str
    validation_reason: str
    malicious: Optional[int] = None
    suspicious: Optional[int] = None
    harmless: Optional[int] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class Indicator:
    value: str
    indicator_type: IndicatorType
