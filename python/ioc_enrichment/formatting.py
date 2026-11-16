"""Analyst-friendly structured and text output formatting."""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import EnrichmentResult


def result_as_dict(result: EnrichmentResult) -> dict[str, object]:
    return asdict(result)


def format_json(result: EnrichmentResult) -> str:
    return json.dumps(result_as_dict(result), indent=2, ensure_ascii=True)


def format_text(result: EnrichmentResult) -> str:
    fields = (("Indicator", result.indicator), ("Indicator type", result.indicator_type),
        ("Validation", result.validation_status), ("Reputation", result.reputation_status),
        ("Risk", result.risk_classification), ("Source", result.source),
        ("Recommendation", result.investigation_recommendation))
    lines = [f"{label}: {value}" for label, value in fields]
    if result.error:
        lines.append(f"Lookup note: {result.error}")
    if result.malicious is not None:
        lines.append(f"Analysis counts: malicious={result.malicious}, suspicious={result.suspicious}, harmless={result.harmless}")
    if result.source.startswith("Synthetic"):
        lines.append("NOTICE: Synthetic offline data; this is not real threat intelligence.")
    return "\n".join(lines)
