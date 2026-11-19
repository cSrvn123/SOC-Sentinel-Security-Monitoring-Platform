"""Common event and report structures for the Windows event analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NormalizedEvent:
    timestamp: Optional[str]
    computer: Optional[str]
    event_source: str
    event_id: int
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_id: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    dns_query: Optional[str] = None
    observations: list[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    input_record_count: int
    events: list[NormalizedEvent]
    issues: list[str] = field(default_factory=list)
    original_records: list[object] = field(default_factory=list)
    event_record_indices: list[int] = field(default_factory=list)

