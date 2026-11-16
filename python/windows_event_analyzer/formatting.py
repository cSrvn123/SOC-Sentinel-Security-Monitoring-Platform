"""Readable text and JSON formatting for investigation summaries."""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import AnalysisReport


DISCLAIMER = "Observations are heuristic triage prompts only; they do not confirm malicious activity or compromise."


def report_as_dict(report: AnalysisReport) -> dict[str, object]:
    return {
        "input_record_count": report.input_record_count,
        "supported_event_count": len(report.events),
        "issues": report.issues,
        "events": [asdict(event) for event in report.events],
        "original_records": report.original_records,
        "disclaimer": DISCLAIMER,
    }


def format_json(report: AnalysisReport) -> str:
    return json.dumps(report_as_dict(report), indent=2, ensure_ascii=True)


def format_text(report: AnalysisReport) -> str:
    lines = [
        "Windows Security Event Investigation Summary",
        f"Input records: {report.input_record_count}",
        f"Supported events: {len(report.events)}",
    ]
    if report.issues:
        lines.append("Input issues:")
        lines.extend(f"  - {issue}" for issue in report.issues)
    for number, event in enumerate(report.events, start=1):
        lines.extend(("", f"[{number}] {event.event_source} {event.event_id} - {event.event_type}"))
        for label, value in (
            ("Timestamp", event.timestamp), ("Computer", event.computer), ("Username", event.username),
            ("Source IP", event.source_ip), ("Destination IP", event.destination_ip),
            ("Process", event.process_name), ("Process path", event.process_path),
            ("Process ID", event.process_id), ("Parent process", event.parent_process),
            ("Command line", event.command_line), ("DNS query", event.dns_query),
        ):
            if value is not None:
                lines.append(f"  {label}: {value}")
        if event.observations:
            lines.extend(f"  Observation: {item}" for item in event.observations)
        else:
            lines.append("  Observation: No configured heuristic signal for this event.")
    lines.extend(("", DISCLAIMER))
    return "\n".join(lines)
