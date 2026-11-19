"""Windows event analysis for supplied records and optional local collection."""

from .analyzer import AnalysisReport, EventInputError, analyze_json, analyze_records, classify_ip_address
from .collector import EventLogCollectionError, LocalEventBatch, collect_local_events
from .models import NormalizedEvent

__all__ = [
    "AnalysisReport",
    "EventInputError",
    "EventLogCollectionError",
    "LocalEventBatch",
    "NormalizedEvent",
    "analyze_json",
    "analyze_records",
    "classify_ip_address",
    "collect_local_events",
]
