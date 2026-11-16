from __future__ import annotations

import unittest

from alert_correlation.engine import correlate
from alert_correlation.models import CorrelationReport, InvestigationCase
from ioc_enrichment.models import EnrichmentResult
from incident_reporting import (
    AnalystConclusion,
    IncidentReport,
    IncidentSeverity,
    build_incident_report_collection,
)
from windows_event_analyzer.analyzer import analyze_records


def case(
    case_id: str = "SOC-SYNTHETIC-1",
    *,
    records: list[object] | None = None,
    related_events: list[object] | None = None,
) -> InvestigationCase:
    return InvestigationCase(
        case_id=case_id,
        detection_pattern="Synthetic correlation pattern",
        first_observed="2026-01-01T00:00:00+00:00",
        last_observed="2026-01-01T00:01:00+00:00",
        related_events=list(related_events or []),
        accounts=["synthetic.user"],
        computers=["synthetic-host"],
        ips=["192.0.2.10"],
        evidence=["Synthetic evidence only."],
        missing_evidence=["Independent confirmation is unavailable."],
        recommendations=["Review synthetic context; no action was performed."],
        confidence="medium",
        confidence_explanation="Synthetic correlation strength only.",
        source_records=list(records or []),
        source_issues=[],
    )


def incident_report(**assessment: object) -> IncidentReport:
    fields: dict[str, object] = {
        "incident_id": "INC-SYNTHETIC-ASSESSMENT",
        "schema_version": "1.0",
        "source_case_id": "SOC-SYNTHETIC-ASSESSMENT",
        "title": "Synthetic assessment test",
        "confidence": "high",
        "confidence_explanation": "Synthetic correlation strength only.",
    }
    fields.update(assessment)
    return IncidentReport(**fields)  # type: ignore[arg-type]


class IncidentReportingBuilderTests(unittest.TestCase):
    def test_one_case_produces_one_incident_and_preserves_case_fields(self) -> None:
        source = case()
        collection = build_incident_report_collection([source])

        self.assertEqual(len(collection.incidents), 1)
        incident = collection.incidents[0]
        self.assertEqual(incident.source_case_id, source.case_id)
        self.assertEqual(incident.incident_id, "INC-" + source.case_id)
        self.assertEqual(incident.title, source.detection_pattern)
        self.assertEqual(incident.confidence, source.confidence)
        self.assertEqual(incident.confidence_explanation, source.confidence_explanation)
        self.assertEqual(incident.evidence, source.evidence)
        self.assertEqual(incident.missing_evidence, source.missing_evidence)
        self.assertEqual(incident.recommendations, source.recommendations)
        self.assertEqual(incident.timeline, [])

    def test_multiple_cases_produce_multiple_incidents(self) -> None:
        collection = build_incident_report_collection([case("SOC-A"), case("SOC-B")])
        self.assertEqual([item.source_case_id for item in collection.incidents], ["SOC-A", "SOC-B"])

    def test_correlation_report_metadata_survives_at_collection_level(self) -> None:
        raw = {"synthetic": {"record": 1}}
        report = CorrelationReport(
            [case(records=[raw])],
            diagnostics=["Synthetic diagnostic."],
            skipped_events=[{"event_id": 999, "reason": "synthetic unsupported event"}],
        )
        collection = build_incident_report_collection(report)

        self.assertEqual(collection.diagnostics, ["Synthetic diagnostic."])
        self.assertEqual(collection.skipped_events, [{"event_id": 999, "reason": "synthetic unsupported event"}])
        self.assertEqual(len(collection.original_input_records), 1)
        self.assertIs(collection.original_input_records[0], raw)

    def test_actual_analyzer_and_correlation_output_adapts_without_losing_provenance(self) -> None:
        raw = {
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 22,
            "timestamp": "2026-01-01T00:00:00Z",
            "computer": "synthetic-host",
            "event_data": {"QueryName": "updates.example"},
        }
        analysis = analyze_records([raw])
        ioc = EnrichmentResult(
            indicator="updates.example",
            indicator_type="domain",
            validation_status="valid",
            reputation_status="synthetic_unknown",
            risk_classification="unknown",
            source="Synthetic offline fixture",
            investigation_recommendation="Synthetic only",
            validation_reason="Synthetic test fixture",
        )
        correlation = correlate(analysis, [ioc])
        collection = build_incident_report_collection(correlation)

        self.assertEqual(len(collection.incidents), 1)
        incident = collection.incidents[0]
        self.assertEqual(incident.related_events[0]["event"]["event_id"], 22)
        self.assertEqual(incident.provenance[0].provenance_status, "matched")
        self.assertIs(incident.provenance[0].original_record, analysis.original_records[0])
        self.assertEqual(len(collection.original_input_records), 1)
        self.assertIs(collection.original_input_records[0], analysis.original_records[0])

    def test_ordinary_iterable_does_not_invent_diagnostics_or_skips(self) -> None:
        collection = build_incident_report_collection(iter([case()]))
        self.assertEqual(collection.diagnostics, [])
        self.assertEqual(collection.skipped_events, [])
        self.assertEqual(collection.collection_metadata["source_type"], "InvestigationCase iterable")

    def test_shared_batch_is_stored_once_at_collection_level(self) -> None:
        first_record = {"record": "synthetic-1"}
        second_record = {"record": "synthetic-2"}
        report = CorrelationReport([
            case("SOC-A", records=[first_record, second_record]),
            case("SOC-B", records=[first_record, second_record]),
        ])
        collection = build_incident_report_collection(report)

        self.assertEqual(collection.original_input_records, [first_record, second_record])
        self.assertEqual(collection.collection_metadata["original_input_batch_count"], 1)
        self.assertEqual(collection.collection_metadata["original_input_batch_boundaries"][0]["count"], 2)
        self.assertEqual(len(collection.incidents), 2)

    def test_distinct_batches_are_preserved_once_each_with_boundaries(self) -> None:
        first = {"record": "synthetic-a"}
        second = {"record": "synthetic-b"}
        collection = build_incident_report_collection([
            case("SOC-A", records=[first]), case("SOC-B", records=[second])
        ])

        self.assertEqual(collection.original_input_records, [first, second])
        self.assertEqual(collection.collection_metadata["original_input_batch_count"], 2)
        self.assertEqual(
            [item["count"] for item in collection.collection_metadata["original_input_batch_boundaries"]],
            [1, 1],
        )

    def test_repeated_batches_keep_case_ids_on_their_first_seen_boundary(self) -> None:
        patterns = (
            ("A-B-A", ["A", "B", "A"]),
            ("A-B-B-A", ["A", "B", "B", "A"]),
            ("A-B-C-A-B", ["A", "B", "C", "A", "B"]),
            ("A-A", ["A", "A"]),
        )
        for label, sequence in patterns:
            with self.subTest(pattern=label):
                records = {name: {"batch": name} for name in dict.fromkeys(sequence)}
                occurrences: dict[str, int] = {}
                cases = []
                expected_case_ids: dict[str, list[str]] = {}
                for batch_name in sequence:
                    occurrences[batch_name] = occurrences.get(batch_name, 0) + 1
                    case_id = f"{batch_name}-{occurrences[batch_name]}"
                    cases.append(case(case_id, records=[records[batch_name]]))
                    expected_case_ids.setdefault(batch_name, []).append(case_id)

                collection = build_incident_report_collection(cases)
                boundaries = collection.collection_metadata["original_input_batch_boundaries"]
                first_seen_order = list(expected_case_ids)

                self.assertEqual(
                    [item["source_case_ids"] for item in boundaries],
                    [expected_case_ids[name] for name in first_seen_order],
                )
                self.assertEqual(
                    collection.original_input_records,
                    [records[name] for name in first_seen_order],
                )
                self.assertTrue(all(
                    actual is records[name]
                    for actual, name in zip(collection.original_input_records, first_seen_order)
                ))
                self.assertEqual(
                    [item["batch_index"] for item in boundaries],
                    list(range(len(first_seen_order))),
                )

    def test_equivalent_but_separately_copied_records_remain_distinct_batches(self) -> None:
        first = {"record": "same synthetic content"}
        second = {"record": "same synthetic content"}
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

        collection = build_incident_report_collection([
            case("SOC-COPY-A", records=[first]),
            case("SOC-COPY-B", records=[second]),
        ])

        self.assertEqual(collection.collection_metadata["original_input_batch_count"], 2)
        self.assertEqual(
            [item["source_case_ids"] for item in collection.collection_metadata["original_input_batch_boundaries"]],
            [["SOC-COPY-A"], ["SOC-COPY-B"]],
        )
        self.assertIs(collection.original_input_records[0], first)
        self.assertIs(collection.original_input_records[1], second)

    def test_related_event_keeps_unknown_fields_and_case_specific_evidence(self) -> None:
        raw = {"event_data": {"synthetic_field": "unchanged"}}
        source_event = {
            "source_references": ["source_record:synthetic"],
            "source_identity": "synthetic-identity",
            "provenance_status": "exact",
            "original_record": raw,
            "original_record_candidates": [raw],
            "event": {"event_id": 3, "event_source": "Sysmon"},
            "custom_evidence_field": {"retained": True},
        }
        incident = build_incident_report_collection([case(related_events=[source_event])]).incidents[0]

        self.assertEqual(incident.related_events[0]["custom_evidence_field"], {"retained": True})
        self.assertEqual(incident.related_events[0]["event"], {"event_id": 3, "event_source": "Sysmon"})
        self.assertEqual(incident.provenance[0].source_references, ["source_record:synthetic"])
        self.assertEqual(incident.provenance[0].additional_fields["custom_evidence_field"], {"retained": True})
        self.assertIs(incident.provenance[0].original_record, raw)

    def test_exact_and_ambiguous_provenance_remain_distinguishable(self) -> None:
        exact_record = {"record": "exact synthetic evidence"}
        candidate_a = {"record": "candidate a"}
        candidate_b = {"record": "candidate b"}
        exact = {
            "source_references": ["source_record:exact"], "source_identity": "identity-exact",
            "provenance_status": "exact", "original_record": exact_record,
            "original_record_candidates": [exact_record],
        }
        ambiguous = {
            "source_references": ["source_record_ambiguous:synthetic"], "source_identity": None,
            "provenance_status": "ambiguous", "original_record": None,
            "original_record_candidates": [candidate_a, candidate_b],
        }
        incidents = build_incident_report_collection([
            case("SOC-EXACT", related_events=[exact]), case("SOC-AMBIG", related_events=[ambiguous])
        ]).incidents

        self.assertEqual(incidents[0].provenance[0].provenance_status, "exact")
        self.assertIs(incidents[0].provenance[0].original_record, exact_record)
        self.assertEqual(incidents[1].provenance[0].provenance_status, "ambiguous")
        self.assertIsNone(incidents[1].provenance[0].original_record)
        self.assertEqual(incidents[1].provenance[0].original_record_candidates, [candidate_a, candidate_b])
        self.assertTrue(any("ambiguous" in item for item in incidents[1].evidence_limitations))

    def test_missing_evidence_recommendations_and_serialization_limitations_survive(self) -> None:
        source = case()
        source.evidence = [
            "Supplied IOC result for synthetic.example: {}",
            "IOC evidence serialization limitation: synthetic field was inaccessible.",
        ]
        source.missing_evidence = ["No synthetic confirmation."]
        source.recommendations = ["Investigate only; no response action was executed."]
        source.source_issues = ["Synthetic provenance limitation."]

        incident = build_incident_report_collection([source]).incidents[0]
        self.assertEqual(incident.missing_evidence, source.missing_evidence)
        self.assertEqual(incident.recommendations, source.recommendations)
        self.assertEqual(incident.evidence, source.evidence)
        self.assertIn("Synthetic provenance limitation.", incident.evidence_limitations)
        self.assertIn(source.evidence[1], incident.evidence_limitations)

    def test_confidence_is_not_used_as_severity_or_conclusion(self) -> None:
        source = case()
        source.confidence = "high"
        source.confidence_explanation = "Synthetic strong match; not a verdict."
        incident = build_incident_report_collection([source]).incidents[0]

        self.assertEqual(incident.confidence, "high")
        self.assertEqual(incident.confidence_explanation, source.confidence_explanation)
        self.assertEqual(incident.severity, "NOT_ASSESSED")
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)
        self.assertEqual(incident.mitre_attack_mappings, [])

    def test_source_cases_and_raw_records_are_not_mutated(self) -> None:
        raw = {"nested": ["synthetic value"]}
        related = {"source_references": ["ref"], "original_record": raw,
                   "original_record_candidates": [raw], "provenance_status": "exact"}
        source = case(records=[raw], related_events=[related])
        original_evidence = list(source.evidence)
        original_refs = list(related["source_references"])
        original_nested = list(raw["nested"])

        collection = build_incident_report_collection([source])
        collection.incidents[0].evidence.append("local report-only field")
        collection.incidents[0].related_events[0]["local_report_only"] = True
        collection.incidents[0].provenance[0].source_references.append("local ref")

        self.assertEqual(source.evidence, original_evidence)
        self.assertEqual(related["source_references"], original_refs)
        self.assertNotIn("local_report_only", related)
        self.assertEqual(raw["nested"], original_nested)

    def test_empty_input_produces_valid_empty_collection(self) -> None:
        collection = build_incident_report_collection([])
        self.assertEqual(collection.incidents, [])
        self.assertEqual(collection.diagnostics, [])
        self.assertEqual(collection.skipped_events, [])
        self.assertEqual(collection.original_input_records, [])
        self.assertEqual(collection.collection_metadata["source_case_count"], 0)

    def test_duplicate_source_case_ids_receive_distinct_incident_ids(self) -> None:
        collection = build_incident_report_collection([case("SOC-DUP"), case("SOC-DUP")])
        self.assertEqual([item.incident_id for item in collection.incidents], ["INC-SOC-DUP", "INC-SOC-DUP-2"])

    def test_incident_severity_exposes_the_supported_scale(self) -> None:
        self.assertEqual(
            [item.value for item in IncidentSeverity],
            ["NOT_ASSESSED", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        )
        self.assertTrue(all(isinstance(item, str) and str(item) == item.value for item in IncidentSeverity))

    def test_analyst_conclusion_retains_legacy_values_and_adds_confirmed_malicious(self) -> None:
        self.assertEqual(
            [item.value for item in AnalystConclusion],
            ["NOT_ASSESSED", "INCONCLUSIVE", "SUSPICIOUS", "BENIGN", "MALICIOUS", "CONFIRMED_MALICIOUS"],
        )
        self.assertTrue(all(isinstance(item, str) and str(item) == item.value for item in AnalystConclusion))
        self.assertIs(AnalystConclusion.MALICIOUS, AnalystConclusion("MALICIOUS"))
        self.assertIsNot(AnalystConclusion.MALICIOUS, AnalystConclusion.CONFIRMED_MALICIOUS)

    def test_high_confidence_and_malicious_ioc_evidence_do_not_assess_incident(self) -> None:
        source = case()
        source.confidence = "high"
        source.evidence = [
            "Synthetic IOC fixture: reputation_status=malicious, malicious_count=8.",
            "This is supplied intelligence evidence, not an analyst conclusion.",
        ]
        source.recommendations = ["Review and validate the supplied IOC context."]

        incident = build_incident_report_collection([source]).incidents[0]

        self.assertEqual(incident.confidence, "high")
        self.assertEqual(incident.evidence, source.evidence)
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)

    def test_severity_and_conclusion_are_independently_assigned(self) -> None:
        incident = build_incident_report_collection([case()]).incidents[0]

        incident.severity = IncidentSeverity.HIGH
        incident.severity_rationale = "Synthetic impact and urgency assessment."
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)
        self.assertIsNone(incident.analyst_conclusion_rationale)

        incident.analyst_conclusion = AnalystConclusion.CONFIRMED_MALICIOUS
        incident.analyst_conclusion_rationale = "Synthetic corroborated evidence supports this conclusion."
        self.assertEqual(incident.severity, IncidentSeverity.HIGH)
        self.assertEqual(incident.severity_rationale, "Synthetic impact and urgency assessment.")
        self.assertEqual(
            incident.analyst_conclusion_rationale,
            "Synthetic corroborated evidence supports this conclusion.",
        )

    def test_assessment_fields_do_not_change_evidence_timeline_provenance_or_batch_context(self) -> None:
        raw = {"synthetic": "source-record"}
        related = {
            "source_references": ["synthetic-source-reference"],
            "source_identity": "synthetic-source-identity",
            "provenance_status": "matched",
            "original_record": raw,
            "original_record_candidates": [raw],
            "event": {
                "timestamp": "2026-01-01T00:00:00Z",
                "event_source": "SyntheticSource",
                "event_id": 1,
                "event_type": "synthetic_event",
            },
        }
        source_case = case("SOC-ASSESSMENT", records=[raw], related_events=[related])
        report = CorrelationReport(
            [source_case],
            diagnostics=["Synthetic collection diagnostic."],
            skipped_events=[{"event_index": 99, "reason": "synthetic skipped event"}],
        )
        collection = build_incident_report_collection(report)
        incident = collection.incidents[0]
        incident.timeline = ["synthetic timeline marker"]
        evidence_before = list(incident.evidence)
        timeline_before = list(incident.timeline)
        provenance_before = list(incident.provenance)
        source_references_before = list(incident.provenance[0].source_references)
        original_record_before = incident.provenance[0].original_record
        diagnostics_before = list(collection.diagnostics)
        skipped_before = list(collection.skipped_events)

        incident.severity = IncidentSeverity.CRITICAL
        incident.severity_rationale = "Synthetic assessed impact and urgency."
        incident.analyst_conclusion = AnalystConclusion.SUSPICIOUS
        incident.analyst_conclusion_rationale = "Synthetic analyst reasoning only."

        self.assertEqual(incident.evidence, evidence_before)
        self.assertEqual(incident.timeline, timeline_before)
        self.assertEqual(incident.provenance, provenance_before)
        self.assertEqual(incident.provenance[0].source_references, source_references_before)
        self.assertIs(incident.provenance[0].original_record, original_record_before)
        self.assertEqual(collection.diagnostics, diagnostics_before)
        self.assertEqual(collection.skipped_events, skipped_before)
        self.assertIs(collection.original_input_records[0], raw)

    def test_all_assessment_enum_members_and_strings_validate_at_init_and_assignment(self) -> None:
        for severity in IncidentSeverity:
            for conclusion in AnalystConclusion:
                with self.subTest(severity=severity.value, conclusion=conclusion.value):
                    report = incident_report(severity=severity, analyst_conclusion=conclusion)
                    self.assertIs(report.severity, severity)
                    self.assertIs(report.analyst_conclusion, conclusion)

                    report.severity = severity.value
                    report.analyst_conclusion = conclusion.value
                    self.assertIs(report.severity, severity)
                    self.assertIs(report.analyst_conclusion, conclusion)

    def test_invalid_assessment_assignments_are_rejected_without_changing_valid_state(self) -> None:
        report = incident_report()
        report.severity = IncidentSeverity.HIGH
        report.analyst_conclusion = AnalystConclusion.MALICIOUS

        for invalid in ("SEVERE", "", 7, None):
            with self.subTest(field="severity", invalid=repr(invalid)):
                with self.assertRaises((TypeError, ValueError)):
                    report.severity = invalid
                self.assertIs(report.severity, IncidentSeverity.HIGH)

        for invalid in ("MAYBE", "", 7, None):
            with self.subTest(field="analyst_conclusion", invalid=repr(invalid)):
                with self.assertRaises((TypeError, ValueError)):
                    report.analyst_conclusion = invalid
                self.assertIs(report.analyst_conclusion, AnalystConclusion.MALICIOUS)

        with self.assertRaises(ValueError):
            incident_report(severity="SEVERE")
        with self.assertRaises(ValueError):
            incident_report(analyst_conclusion="MAYBE")

    def test_rationale_types_are_validated_during_initialization_and_assignment(self) -> None:
        report = incident_report(
            severity_rationale="Synthetic impact and urgency.",
            analyst_conclusion_rationale="Synthetic reasoning.",
        )
        self.assertEqual(report.severity_rationale, "Synthetic impact and urgency.")
        self.assertEqual(report.analyst_conclusion_rationale, "Synthetic reasoning.")

        report.severity_rationale = None
        report.analyst_conclusion_rationale = None
        self.assertIsNone(report.severity_rationale)
        self.assertIsNone(report.analyst_conclusion_rationale)

        report.severity_rationale = "Retained valid severity rationale."
        report.analyst_conclusion_rationale = "Retained valid conclusion rationale."
        for field_name in ("severity_rationale", "analyst_conclusion_rationale"):
            previous = getattr(report, field_name)
            for invalid in (42, object()):
                with self.subTest(field=field_name, invalid_type=type(invalid).__name__):
                    with self.assertRaises(TypeError):
                        setattr(report, field_name, invalid)
                    self.assertEqual(getattr(report, field_name), previous)
            with self.assertRaises(TypeError):
                incident_report(**{field_name: object()})


if __name__ == "__main__":
    unittest.main()
