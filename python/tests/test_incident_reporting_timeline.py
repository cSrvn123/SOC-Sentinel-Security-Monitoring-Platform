from __future__ import annotations

import unittest
from collections.abc import Mapping

from incident_reporting.models import (
    EventProvenance,
    IncidentEntities,
    IncidentReport,
    IncidentReportCollection,
)
from incident_reporting.timeline import TimelineEntry, build_timeline, build_timelined_collection


def event(timestamp: object = None, *, present: bool = True, **outer: object) -> dict[str, object]:
    normalized: dict[str, object] = {
        "event_source": "Sysmon",
        "event_id": 1,
        "event_type": "process_creation",
    }
    if present:
        normalized["timestamp"] = timestamp
    return {
        "source_references": ["synthetic-source-reference"],
        "source_identity": "synthetic-source-identity",
        "provenance_status": "matched",
        "original_record": {"synthetic": True},
        "original_record_candidates": [],
        "event": normalized,
        **outer,
    }


def incident(incident_id: str, related_events: list[object], provenance: list[EventProvenance] | None = None) -> IncidentReport:
    return IncidentReport(
        incident_id=incident_id,
        schema_version="1.0",
        source_case_id="SOC-" + incident_id,
        title="Synthetic correlation",
        confidence="medium",
        confidence_explanation="Synthetic test only.",
        related_events=related_events,
        provenance=list(provenance or []),
    )


class IncidentTimelineTests(unittest.TestCase):
    def test_out_of_order_events_sort_by_normalized_utc_and_preserve_original_strings(self) -> None:
        later_local = "2026-01-01T05:00:00+05:30"  # 2025-12-31T23:30:00Z
        earlier_utc = "2025-12-31T23:20:00Z"
        report = incident("INC-ORDER", [event(later_local), event(earlier_utc)])

        timeline = build_timeline(report)

        self.assertEqual([item.related_event_index for item in timeline], [1, 0])
        self.assertEqual([item.original_timestamp for item in timeline], [earlier_utc, later_local])
        self.assertEqual(
            [item.normalized_timestamp_utc for item in timeline],
            ["2025-12-31T23:20:00+00:00", "2025-12-31T23:30:00+00:00"],
        )
        self.assertTrue(all(item.timestamp_status == "valid" for item in timeline))

    def test_different_offsets_for_same_instant_use_original_index_as_tie_breaker(self) -> None:
        first = "2026-01-01T00:00:00Z"
        second = "2026-01-01T01:00:00+01:00"
        timeline = build_timeline(incident("INC-TIE", [event(first), event(second)]))

        self.assertEqual([item.related_event_index for item in timeline], [0, 1])
        self.assertEqual(timeline[0].normalized_timestamp_utc, timeline[1].normalized_timestamp_utc)
        self.assertEqual([item.original_timestamp for item in timeline], [first, second])

    def test_uppercase_and_lowercase_z_are_supported_without_rewriting_originals(self) -> None:
        upper = "2026-02-03T04:05:06Z"
        lower = "2026-02-03T04:05:06z"
        timeline = build_timeline(incident("INC-Z", [event(upper), event(lower)]))

        self.assertEqual([item.timestamp_status for item in timeline], ["valid", "valid"])
        self.assertEqual([item.original_timestamp for item in timeline], [upper, lower])
        self.assertEqual(timeline[0].normalized_timestamp_utc, "2026-02-03T04:05:06+00:00")

    def test_missing_invalid_and_naive_timestamps_are_not_invented_and_sort_last(self) -> None:
        valid = "2026-01-01T00:00:00Z"
        invalid = "synthetic-not-a-time"
        naive = "2026-01-01T00:00:00"
        events = [
            event(invalid),
            event(None, present=False),
            event(naive),
            event(valid),
            event(""),
            event(123),
        ]

        timeline = build_timeline(incident("INC-TIMES", events))

        self.assertEqual([item.related_event_index for item in timeline], [3, 0, 1, 2, 4, 5])
        self.assertEqual([item.timestamp_status for item in timeline],
                         ["valid", "invalid", "missing", "invalid", "missing", "invalid"])
        self.assertEqual([item.original_timestamp for item in timeline],
                         [valid, invalid, None, naive, "", 123])
        self.assertEqual([item.normalized_timestamp_utc for item in timeline],
                         ["2026-01-01T00:00:00+00:00", None, None, None, None, None])

    def test_source_references_and_provenance_are_linked_by_related_event_index(self) -> None:
        raw0 = {"candidate": "synthetic-0"}
        raw1 = {"candidate": "synthetic-1"}
        events = [
            event("2026-01-01T00:00:00Z", source_references=["ref-0"], provenance_status="matched"),
            event("2026-01-01T00:00:01Z", source_references=["ref-1"], provenance_status="ambiguous",
                  original_record=None, original_record_candidates=[raw0, raw1]),
        ]
        # Deliberately reverse provenance storage order: the explicit event index is authoritative.
        provenance = [
            EventProvenance(1, ["ref-1"], None, "ambiguous", None, [raw0, raw1]),
            EventProvenance(0, ["ref-0"], "identity-0", "matched", raw0, [raw0]),
        ]
        report = incident("INC-PROV", events, provenance)

        timeline = build_timeline(report)

        self.assertEqual([item.related_event_index for item in timeline], [0, 1])
        self.assertEqual(timeline[0].source_references, ["ref-0"])
        self.assertEqual(timeline[0].provenance_status, "matched")
        self.assertEqual(timeline[0].provenance_indices, [1])
        self.assertEqual(timeline[1].source_references, ["ref-1"])
        self.assertEqual(timeline[1].provenance_status, "ambiguous")
        self.assertEqual(timeline[1].provenance_indices, [0])
        linked = report.provenance[timeline[1].provenance_indices[0]]
        self.assertIsNone(linked.original_record)
        self.assertEqual(linked.original_record_candidates, [raw0, raw1])

    def test_missing_provenance_is_unavailable_and_malformed_entry_keeps_its_index(self) -> None:
        candidate = {"candidate": "synthetic"}
        malformed: object = "not-a-related-event-mapping"
        report = incident("INC-MALFORMED", [event("2026-01-01T00:00:00Z"), malformed], [
            EventProvenance(1, ["safe-ref"], None, "ambiguous", None, [candidate]),
        ])

        timeline = build_timeline(report)

        self.assertEqual([item.related_event_index for item in timeline], [0, 1])
        self.assertEqual(timeline[0].provenance_status, "matched")
        self.assertEqual(timeline[0].provenance_indices, [])
        self.assertEqual(timeline[1].timestamp_status, "missing")
        self.assertIsNone(timeline[1].normalized_timestamp_utc)
        self.assertEqual(timeline[1].source_references, ["safe-ref"])
        self.assertEqual(timeline[1].provenance_status, "ambiguous")
        self.assertEqual(timeline[1].provenance_indices, [0])
        self.assertTrue(any("malformed" in item for item in timeline[1].diagnostics))
        self.assertEqual(report.provenance[0].original_record_candidates, [candidate])

    def test_malformed_nested_event_preserves_safely_accessible_scalar_reference(self) -> None:
        malformed = {
            "source_references": "synthetic-single-reference",
            "provenance_status": "unavailable",
            "event": "malformed-event-payload",
        }
        entry = build_timeline(incident("INC-MALFORMED-MAP", [malformed]))[0]

        self.assertEqual(entry.related_event_index, 0)
        self.assertEqual(entry.timestamp_status, "missing")
        self.assertEqual(entry.source_references, ["synthetic-single-reference"])
        self.assertEqual(entry.provenance_status, "unavailable")
        self.assertTrue(any("no normalized event mapping" in item for item in entry.diagnostics))

    def test_mapping_accessor_exception_keeps_event_index_and_safe_provenance(self) -> None:
        class RaisingEventMapping(Mapping):
            def __init__(self) -> None:
                self.data = {
                    "source_references": ["safe-reference"],
                    "provenance_status": "ambiguous",
                }

            def __getitem__(self, key: str) -> object:
                if key == "event":
                    raise RuntimeError("synthetic mapping lookup failure")
                return self.data[key]

            def __iter__(self):
                return iter(self.data)

            def __len__(self) -> int:
                return len(self.data)

        malformed = RaisingEventMapping()
        before = dict(malformed.data)
        timeline = build_timeline(incident("INC-RAISING-MAP", [malformed]))

        self.assertEqual(len(timeline), 1)
        entry = timeline[0]
        self.assertEqual(entry.related_event_index, 0)
        self.assertEqual(entry.timestamp_status, "missing")
        self.assertEqual(entry.original_timestamp, None)
        self.assertIsNone(entry.event_id)
        self.assertEqual(entry.source_references, ["safe-reference"])
        self.assertEqual(entry.provenance_status, "ambiguous")
        self.assertTrue(any("RuntimeError" in item for item in entry.diagnostics))
        self.assertEqual(malformed.data, before)

    def test_conflicting_statuses_never_upgrade_ambiguous_provenance(self) -> None:
        candidates = [{"candidate": "synthetic-a"}, {"candidate": "synthetic-b"}]
        scenarios = (
            ("ambiguous", ["matched"], "ambiguous"),
            ("matched", ["ambiguous"], "ambiguous"),
            ("matched", ["unavailable"], "unavailable"),
            ("matched", ["ambiguous", "matched"], "ambiguous"),
            ("matched", ["unavailable", "matched"], "unavailable"),
            ("ambiguous", ["matched", "matched"], "ambiguous"),
            ("unavailable", ["matched", "matched"], "unavailable"),
            ("matched", ["matched", "matched"], "matched"),
        )
        for wrapper_status, aligned_statuses, expected in scenarios:
            with self.subTest(wrapper=wrapper_status, aligned=aligned_statuses):
                related = event(
                    "2026-01-01T00:00:00Z",
                    source_references=["wrapper-reference"],
                    provenance_status=wrapper_status,
                    original_record=None if wrapper_status == "ambiguous" else candidates[0],
                    original_record_candidates=candidates,
                )
                provenance = [
                    EventProvenance(
                        0,
                        [f"aligned-reference-{index}"],
                        None,
                        aligned_status,
                        candidates[0] if aligned_status == "matched" else None,
                        candidates,
                    )
                    for index, aligned_status in enumerate(aligned_statuses)
                ]
                report = incident("INC-STATUS-CONFLICT", [related], provenance)

                entry = build_timeline(report)[0]

                self.assertEqual(entry.provenance_status, expected)
                self.assertEqual(entry.provenance_indices, list(range(len(provenance))))
                self.assertEqual(report.related_events[0]["original_record_candidates"], candidates)
                self.assertTrue(all(item.original_record_candidates == candidates for item in report.provenance))
                if len(provenance) == 1 and wrapper_status != aligned_statuses[0]:
                    self.assertTrue(any("statuses conflict" in item for item in entry.diagnostics))
                self.assertEqual(entry.source_references, ["wrapper-reference"] if len(provenance) > 1
                                 else ["aligned-reference-0"])

    def test_raising_provenance_index_does_not_hide_valid_neighboring_provenance(self) -> None:
        class RaisingRelatedIndex:
            def __init__(self) -> None:
                self.source_references = ["safely-readable-orphan-reference"]
                self.provenance_status = "ambiguous"

            @property
            def related_event_index(self) -> int:
                raise RuntimeError("synthetic inaccessible provenance index")

        malformed = RaisingRelatedIndex()
        valid = EventProvenance(1, ["valid-neighbor-reference"], "synthetic-id", "matched")
        report = incident(
            "INC-BAD-PROVENANCE",
            [
                event("2026-01-01T00:00:00Z", provenance_status="unavailable"),
                event("2026-01-01T00:00:01Z", provenance_status="matched",
                      source_references=["valid-neighbor-reference"]),
            ],
            [malformed, valid],
        )

        timeline = build_timeline(report)
        by_index = {entry.related_event_index: entry for entry in timeline}

        self.assertEqual(by_index[0].provenance_indices, [])
        self.assertEqual(by_index[0].provenance_status, "unavailable")
        self.assertEqual(by_index[1].provenance_indices, [1])
        self.assertEqual(by_index[1].provenance_status, "matched")
        self.assertEqual(by_index[1].source_references, ["valid-neighbor-reference"])
        self.assertIs(report.provenance[0], malformed)
        self.assertEqual(malformed.source_references, ["safely-readable-orphan-reference"])
        self.assertEqual(malformed.provenance_status, "ambiguous")
        self.assertTrue(any("not assigned to a related event" in message
                            for entry in timeline for message in entry.diagnostics))

    def test_multiple_incidents_have_separate_timelines_and_no_collection_context_entries(self) -> None:
        first = incident("INC-FIRST", [event("2026-01-01T00:00:02Z"), event("2026-01-01T00:00:01Z")])
        second = incident("INC-SECOND", [event("2026-02-01T00:00:00Z")])
        collection = IncidentReportCollection(
            incidents=[first, second],
            diagnostics=["collection-only diagnostic"],
            skipped_events=[{"event_index": 99, "reason": "collection-only skip"}],
            original_input_records=[{"batch-only": True}],
        )

        result = build_timelined_collection(collection)

        self.assertIsNot(result, collection)
        self.assertEqual([item.related_event_index for item in result.incidents[0].timeline], [1, 0])
        self.assertEqual([item.related_event_index for item in result.incidents[1].timeline], [0])
        self.assertEqual(len(result.incidents[0].timeline), 2)
        self.assertEqual(len(result.incidents[1].timeline), 1)
        self.assertTrue(all(item.event_id == 1 for item in result.incidents[0].timeline))
        self.assertFalse(any("collection-only" in str(item) for incident_item in result.incidents
                             for entry in incident_item.timeline for item in entry.diagnostics))
        self.assertEqual(result.diagnostics, collection.diagnostics)
        self.assertEqual(result.skipped_events, collection.skipped_events)
        self.assertEqual(result.original_input_records, collection.original_input_records)
        self.assertEqual(first.timeline, [])
        self.assertEqual(second.timeline, [])

    def test_source_events_records_and_provenance_are_not_mutated(self) -> None:
        raw = {"nested": ["original"]}
        related = event("2026-01-01T00:00:00Z", original_record=raw, original_record_candidates=[raw])
        provenance = EventProvenance(0, ["ref"], "identity", "matched", raw, [raw])
        report = incident("INC-IMMUTABLE", [related], [provenance])
        before_event = dict(related)
        before_candidates = list(provenance.original_record_candidates)
        before_nested = list(raw["nested"])

        timeline = build_timeline(report)
        result = build_timelined_collection(IncidentReportCollection(incidents=[report]))

        self.assertEqual(related, before_event)
        self.assertEqual(provenance.original_record_candidates, before_candidates)
        self.assertEqual(raw["nested"], before_nested)
        self.assertIs(result.incidents[0].provenance[0].original_record, raw)
        self.assertEqual(timeline[0].related_event_index, 0)

    def test_empty_incident_produces_empty_timeline(self) -> None:
        self.assertEqual(build_timeline(incident("INC-EMPTY", [])), [])

    def test_duplicate_provenance_indices_are_not_collapsed_or_selected(self) -> None:
        related = event("2026-01-01T00:00:00Z", source_references=["wrapper-ref"], provenance_status="unavailable")
        one = EventProvenance(0, ["prov-a"], None, "ambiguous")
        two = EventProvenance(0, ["prov-b"], None, "unavailable")
        entry = build_timeline(incident("INC-DUP-PROV", [related], [one, two]))[0]

        self.assertEqual(entry.provenance_indices, [0, 1])
        self.assertEqual(entry.source_references, ["wrapper-ref"])
        self.assertEqual(entry.provenance_status, "ambiguous")
        self.assertTrue(any("Multiple provenance entries" in item for item in entry.diagnostics))


if __name__ == "__main__":
    unittest.main()
