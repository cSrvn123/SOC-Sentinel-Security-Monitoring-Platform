"""Synthetic, offline end-to-end integration scenarios for SOC Sentinel."""

from __future__ import annotations

import copy
import ipaddress
import json
import unittest
from datetime import timedelta
from typing import Any

from alert_correlation.engine import CorrelationConfig, correlate
from alert_correlation.models import CorrelationReport, InvestigationCase
from incident_reporting import (
    AnalystConclusion,
    IncidentReportCollection,
    IncidentSeverity,
    add_attack_mapping,
    build_incident_report_collection,
    format_json,
    format_markdown,
)
from incident_reporting.timeline import build_timelined_collection
from ioc_enrichment.enrichment import enrich_indicator
from ioc_enrichment.models import EnrichmentResult
from ioc_enrichment.reputation import OfflineReputationProvider
from ioc_enrichment.validation import validate_indicator
from windows_event_analyzer.analyzer import analyze_records


_HOST = "SYNTHETIC-WIN11"
_ACCOUNT = "synthetic.user"
_SECURITY_SOURCE = "Microsoft-Windows-Security-Auditing"
_SYSMON_SOURCE = "Microsoft-Windows-Sysmon/Operational"


def _security_event(
    event_id: int,
    timestamp: str,
    record_id: str,
    *,
    ip: str = "192.0.2.25",
) -> dict[str, Any]:
    return {
        "source": _SECURITY_SOURCE,
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": _HOST,
        "channel": "Security",
        "eventRecordID": record_id,
        "event_data": {"TargetUserName": _ACCOUNT, "IpAddress": ip},
    }


def _sysmon_event(
    event_id: int,
    timestamp: str,
    record_id: str,
    **event_data: Any,
) -> dict[str, Any]:
    return {
        "source": _SYSMON_SOURCE,
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": _HOST,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "eventRecordID": record_id,
        "event_data": {"User": _ACCOUNT, **event_data},
    }


def _wazuh_sysmon_event(
    event_id: int,
    timestamp: str,
    record_id: str,
    **event_data: Any,
) -> dict[str, Any]:
    """Build the analyzer-supported Wazuh ``win.system`` / ``win.eventdata`` shape."""
    return {
        "win": {
            "system": {
                "providerName": _SYSMON_SOURCE,
                "eventID": event_id,
                "systemTime": timestamp,
                "computer": _HOST,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "eventRecordID": record_id,
            },
            "eventdata": {"User": _ACCOUNT, **event_data},
        }
    }


def _ioc_candidates(analysis: Any) -> list[str]:
    """Extract only normalized Sysmon network and DNS indicator fields."""
    values: list[str] = []
    seen: set[str] = set()
    for event in analysis.events:
        candidate = None
        if event.event_source == "Sysmon" and event.event_id == 3:
            candidate = event.destination_ip
        elif event.event_source == "Sysmon" and event.event_id == 22:
            candidate = event.dns_query
        if isinstance(candidate, str) and candidate and candidate not in seen:
            seen.add(candidate)
            values.append(candidate)
    return values


def _run_offline_pipeline(
    records: list[dict[str, Any]],
    *,
    supplied_results: tuple[EnrichmentResult, ...] = (),
) -> dict[str, Any]:
    """Run existing APIs only; no provider capable of network access is used."""
    raw_snapshot = copy.deepcopy(records)
    analysis = analyze_records(records)
    candidates = _ioc_candidates(analysis)
    results = [
        enrich_indicator(candidate, OfflineReputationProvider())
        for candidate in candidates
    ]
    results.extend(supplied_results)
    result_snapshot = copy.deepcopy(results)
    correlations = correlate(
        analysis,
        ioc_results=results,
        config=CorrelationConfig(
            failed_logon_threshold=3,
            failed_to_success_window=timedelta(minutes=10),
            logon_to_process_window=timedelta(minutes=10),
        ),
    )
    collection = build_timelined_collection(
        build_incident_report_collection(correlations)
    )
    return {
        "raw_snapshot": raw_snapshot,
        "analysis": analysis,
        "candidates": candidates,
        "ioc_results": results,
        "ioc_snapshot": result_snapshot,
        "correlations": correlations,
        "collection": collection,
    }


def _assert_exports(test: unittest.TestCase, collection: IncidentReportCollection) -> dict[str, Any]:
    json_text = format_json(collection)
    test.assertEqual(json_text, format_json(collection))
    payload = json.loads(json_text)
    markdown = format_markdown(collection)
    test.assertEqual(markdown, format_markdown(collection))
    test.assertNotIn('"event_data"', markdown)
    return {"json": payload, "markdown": markdown}


def _compose_malicious_scenario_case(
    cases: list[InvestigationCase],
    correlations: CorrelationReport,
) -> CorrelationReport:
    """Test-only analyst grouping; the correlation engine does not do this."""
    expected_patterns = {
        "Successful logon followed by unusual process creation",
        "Network connection associated with an available IOC result",
        "DNS query associated with an available IOC result",
    }
    if {case.detection_pattern for case in cases} != expected_patterns:
        raise AssertionError("The synthetic composite requires each expected engine case exactly once.")

    related_by_reference: dict[str, dict[str, Any]] = {}
    for case in cases:
        for related in case.related_events:
            references = related.get("source_references", [])
            if not references:
                raise AssertionError("Synthetic composition requires source references for every event.")
            reference = references[0]
            if reference in related_by_reference and related_by_reference[reference] != related:
                raise AssertionError("A source reference mapped to conflicting related-event evidence.")
            related_by_reference[reference] = related

    related_events = sorted(
        related_by_reference.values(),
        key=lambda item: (item["event"]["timestamp"], item["source_references"][0]),
    )
    confidence_values = {case.confidence for case in cases}
    if len(confidence_values) != 1:
        raise AssertionError("This test-only composition does not aggregate confidence categories.")
    source_issues = list(dict.fromkeys(issue for case in cases for issue in case.source_issues))
    composite = InvestigationCase(
        case_id="SCENARIO-MALICIOUS-001",
        detection_pattern="Analyst-curated combined synthetic scenario",
        first_observed=min(case.first_observed for case in cases),
        last_observed=max(case.last_observed for case in cases),
        related_events=related_events,
        accounts=sorted({value for case in cases for value in case.accounts}),
        computers=sorted({value for case in cases for value in case.computers}),
        ips=sorted({value for case in cases for value in case.ips}),
        evidence=[
            f"Analyst-curated component case {case.case_id}: {case.detection_pattern}."
            for case in cases
        ] + [item for case in cases for item in case.evidence],
        missing_evidence=list(dict.fromkeys(item for case in cases for item in case.missing_evidence)),
        recommendations=list(dict.fromkeys(item for case in cases for item in case.recommendations)),
        confidence=next(iter(confidence_values)),
        confidence_explanation=(
            "Copied from the component cases, which all reported medium correlation confidence; "
            "the analyst-curated composition does not increase that confidence."
        ),
        source_records=list(cases[0].source_records),
        source_issues=source_issues,
    )
    return CorrelationReport(
        [composite],
        diagnostics=correlations.diagnostics,
        skipped_events=correlations.skipped_events,
    )


class EndToEndIncidentScenarioTests(unittest.TestCase):
    def test_reserved_synthetic_ioc_fixtures_are_valid_and_explicitly_offline(self) -> None:
        ip_result = validate_indicator("203.0.113.66")
        domain_result = validate_indicator("suspicious.example")
        self.assertTrue(ip_result.valid)
        self.assertTrue(domain_result.valid)
        self.assertFalse(ipaddress.ip_address("203.0.113.66").is_global)

        provider = OfflineReputationProvider()
        ip_enrichment = enrich_indicator("203.0.113.66", provider)
        domain_enrichment = enrich_indicator("suspicious.example", provider)
        for result in (ip_enrichment, domain_enrichment):
            self.assertEqual(result.validation_status, "valid")
            self.assertEqual(result.reputation_status, "synthetic_suspicious")
            self.assertIn("Synthetic offline", result.source)

    def test_benign_repeated_logons_require_explicit_assessment(self) -> None:
        records = [
            _security_event(4625, "2026-02-01T10:00:00Z", "1001"),
            _security_event(4625, "2026-02-01T10:00:05Z", "1002"),
            _security_event(4625, "2026-02-01T10:00:10Z", "1003"),
            _security_event(4624, "2026-02-01T10:01:00Z", "1004"),
        ]
        result = _run_offline_pipeline(records)
        analysis = result["analysis"]
        correlations = result["correlations"]
        collection = result["collection"]

        self.assertEqual(records, result["raw_snapshot"])
        self.assertEqual(analysis.original_records, records)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["ioc_results"], [])
        self.assertEqual(len(correlations), 1)
        case = correlations[0]
        self.assertEqual(case.detection_pattern, "Repeated failed logons followed by successful logon")
        self.assertEqual(len(case.related_events), 4)
        self.assertEqual(case.confidence, "medium")
        self.assertTrue(all(event.observations for event in analysis.events[:3]))
        self.assertEqual(len(collection.incidents), 1)

        incident = collection.incidents[0]
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual(len(incident.timeline), 4)
        self.assertEqual([entry.related_event_index for entry in incident.timeline], [0, 1, 2, 3])
        self.assertTrue(all(entry.timestamp_status == "valid" for entry in incident.timeline))
        self.assertTrue(all(entry.provenance_status == "matched" for entry in incident.timeline))
        self.assertEqual(collection.original_input_records, records)
        self.assertEqual(collection.diagnostics, [])
        self.assertEqual(collection.skipped_events, [])

        incident.analyst_conclusion = AnalystConclusion.BENIGN
        incident.analyst_conclusion_rationale = "Synthetic exercise confirms expected user password mistakes."
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        incident.severity = IncidentSeverity.INFORMATIONAL
        incident.severity_rationale = "Analyst assessed the resolved synthetic activity as low impact."
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.BENIGN)
        self.assertEqual(incident.mitre_attack_mappings, [])

        exported = _assert_exports(self, collection)
        rendered_incident = exported["json"]["incidents"][0]
        self.assertEqual(rendered_incident["analyst_conclusion"], "BENIGN")
        self.assertEqual(rendered_incident["severity"], "INFORMATIONAL")
        self.assertIn("password mistakes", rendered_incident["analyst_conclusion_rationale"])
        self.assertNotIn("original_input_records", rendered_incident)
        self.assertIn("BENIGN", exported["markdown"])
        self.assertIn("INFORMATIONAL", exported["markdown"])

    def test_suspicious_encoded_powershell_is_only_a_suspicious_assessment(self) -> None:
        records = [
            _security_event(4624, "2026-02-02T10:00:00Z", "2001"),
            _wazuh_sysmon_event(
                1,
                "2026-02-02T10:02:00Z",
                "2002",
                Image=r"C:\Users\synthetic.user\AppData\Local\Temp\powershell.exe",
                ProcessId="4242",
                ParentImage=r"C:\Windows\explorer.exe",
                CommandLine="powershell.exe -NoProfile -EncodedCommand SYNTHETIC-TEST-DATA",
            ),
        ]
        result = _run_offline_pipeline(records)
        analysis = result["analysis"]
        correlations = result["correlations"]
        collection = result["collection"]

        self.assertEqual(records, result["raw_snapshot"])
        self.assertEqual(result["candidates"], [])
        self.assertEqual(len(correlations), 1)
        process_event = analysis.events[1]
        self.assertTrue(any("user-writable location" in item for item in process_event.observations))
        self.assertFalse(any("encoded-command detection" in item.casefold() for item in process_event.observations))
        self.assertEqual(process_event.command_line, "powershell.exe -NoProfile -EncodedCommand SYNTHETIC-TEST-DATA")
        self.assertEqual(analysis.original_records, records)
        self.assertEqual(correlations[0].detection_pattern, "Successful logon followed by unusual process creation")
        self.assertEqual(len(collection.incidents), 1)

        incident = collection.incidents[0]
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual(incident.confidence, "medium")
        process_index = next(
            index for index, related in enumerate(incident.related_events)
            if related["event"]["event_id"] == 1
        )
        incident.analyst_conclusion = AnalystConclusion.SUSPICIOUS
        incident.analyst_conclusion_rationale = (
            "The synthetic encoded-command invocation and writable path warrant review; "
            "the inert log string does not establish payload execution or intent."
        )
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        incident.severity = IncidentSeverity.MEDIUM
        incident.severity_rationale = "Analyst-selected triage priority for this synthetic review."
        mapping = add_attack_mapping(
            incident,
            technique_id="T1059.001",
            technique_name="PowerShell",
            rationale="The referenced Sysmon process event records a PowerShell invocation.",
            evidence_references=[process_index],
        )
        self.assertEqual(mapping["reference_status"], "UNVERIFIED")
        self.assertEqual(mapping["evidence_references"][0]["related_event_index"], process_index)
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.SUSPICIOUS)

        exported = _assert_exports(self, collection)
        json_incident = exported["json"]["incidents"][0]
        self.assertEqual(json_incident["confidence"], "medium")
        self.assertEqual(json_incident["severity"], "MEDIUM")
        self.assertEqual(json_incident["analyst_conclusion"], "SUSPICIOUS")
        self.assertNotIn("SYNTHETIC-TEST-DATA", exported["markdown"])
        self.assertIn("UNVERIFIED", exported["markdown"])

        # The encoded switch alone is not an analyzer heuristic or an incident.
        command_only = [
            _security_event(4624, "2026-02-02T11:00:00Z", "2011"),
            _sysmon_event(
                1,
                "2026-02-02T11:01:00Z",
                "2012",
                Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ProcessId="4243",
                ParentImage=r"C:\Windows\explorer.exe",
                CommandLine="powershell.exe -EncodedCommand SYNTHETIC-TEST-DATA",
            ),
        ]
        command_only_result = _run_offline_pipeline(command_only)
        self.assertFalse(command_only_result["analysis"].events[1].observations)
        self.assertEqual(len(command_only_result["correlations"]), 0)
        self.assertEqual(command_only_result["collection"].incidents, [])

    def test_benign_offline_ioc_association_never_sets_malicious_assessment(self) -> None:
        records = [
            _sysmon_event(
                3,
                "2026-02-02T12:00:00Z",
                "2101",
                Image=r"C:\Program Files\SyntheticApp\app.exe",
                ProcessId="4251",
                DestinationIp="198.51.100.10",
            ),
        ]
        result = _run_offline_pipeline(records)
        self.assertEqual(result["candidates"], ["198.51.100.10"])
        self.assertEqual(len(result["ioc_results"]), 1)
        self.assertEqual(result["ioc_results"][0].reputation_status, "synthetic_benign")
        self.assertIn("Synthetic offline", result["ioc_results"][0].source)
        self.assertEqual(len(result["correlations"]), 1)
        self.assertIn("Network connection", result["correlations"][0].detection_pattern)

        incident = result["collection"].incidents[0]
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual(incident.confidence, "medium")
        incident.analyst_conclusion = AnalystConclusion.BENIGN
        incident.analyst_conclusion_rationale = "The synthetic fixture marks this reserved-address activity as expected."
        self.assertNotEqual(incident.analyst_conclusion, AnalystConclusion.CONFIRMED_MALICIOUS)
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)

    def test_malicious_synthetic_evidence_requires_explicit_composition_and_assessment(self) -> None:
        records = [
            _security_event(4624, "2026-02-03T10:00:00Z", "3001"),
            _sysmon_event(
                1,
                "2026-02-03T10:01:00Z",
                "3002",
                Image=r"C:\Users\synthetic.user\AppData\Local\Temp\powershell.exe",
                ProcessId="4342",
                ParentImage=r"C:\Windows\explorer.exe",
                CommandLine="powershell.exe -EncodedCommand SYNTHETIC-TEST-DATA",
            ),
            _sysmon_event(
                3,
                "2026-02-03T10:02:00Z",
                "3003",
                Image=r"C:\Windows\System32\example.exe",
                ProcessId="4343",
                SourceIp="192.0.2.25",
                DestinationIp="203.0.113.66",
            ),
            _sysmon_event(
                22,
                "2026-02-03T10:03:00Z",
                "3004",
                Image=r"C:\Windows\System32\example.exe",
                QueryName="suspicious.example",
            ),
        ]
        result = _run_offline_pipeline(records)
        analysis = result["analysis"]
        enrichments = result["ioc_results"]
        correlations = result["correlations"]
        self.assertEqual(records, result["raw_snapshot"])
        self.assertEqual([item.indicator for item in enrichments], ["203.0.113.66", "suspicious.example"])
        self.assertTrue(all(item.reputation_status == "synthetic_suspicious" for item in enrichments))
        self.assertTrue(all("Synthetic offline" in item.source for item in enrichments))
        self.assertEqual(
            {case.detection_pattern for case in correlations},
            {
                "Successful logon followed by unusual process creation",
                "Network connection associated with an available IOC result",
                "DNS query associated with an available IOC result",
            },
        )
        self.assertTrue(all(case.confidence == "medium" for case in correlations))
        self.assertTrue(all(result_value == before for result_value, before in zip(enrichments, result["ioc_snapshot"])))

        direct_collection = result["collection"]
        self.assertEqual(len(direct_collection.incidents), 3)
        self.assertTrue(all(item.analyst_conclusion == AnalystConclusion.NOT_ASSESSED for item in direct_collection.incidents))
        self.assertTrue(all(item.severity == IncidentSeverity.NOT_ASSESSED for item in direct_collection.incidents))
        self.assertTrue(all(item.mitre_attack_mappings == [] for item in direct_collection.incidents))

        # Explicitly combine the three engine cases for this test's analyst review.
        # This is not a behavior provided by correlate().
        composite_report = _compose_malicious_scenario_case(list(correlations), correlations)
        collection = build_timelined_collection(build_incident_report_collection(composite_report))
        self.assertEqual(len(collection.incidents), 1)
        incident = collection.incidents[0]
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual(incident.confidence, "medium")
        self.assertEqual(len(incident.related_events), 4)
        self.assertEqual(len(incident.timeline), 4)
        self.assertEqual(
            [entry.event_id for entry in incident.timeline],
            [4624, 1, 3, 22],
        )
        self.assertTrue(all(entry.provenance_status == "matched" for entry in incident.timeline))
        self.assertEqual(len(collection.original_input_records), 4)
        self.assertEqual(collection.collection_metadata["original_input_batch_count"], 1)

        process_index = next(
            index for index, related in enumerate(incident.related_events)
            if related["event"]["event_id"] == 1
        )
        incident.analyst_conclusion = AnalystConclusion.CONFIRMED_MALICIOUS
        incident.analyst_conclusion_rationale = (
            "Synthetic scenario ground truth identifies the combined process, network, and DNS activity "
            "as unauthorized; the supplied synthetic reputation results are supporting context, not proof."
        )
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        incident.severity = IncidentSeverity.HIGH
        incident.severity_rationale = "Analyst-selected urgency for the controlled synthetic exercise."
        mapping = add_attack_mapping(
            incident,
            technique_id="T1059.001",
            technique_name="PowerShell",
            rationale="The referenced process event records the synthetic PowerShell invocation.",
            evidence_references=[process_index],
        )
        self.assertEqual(mapping["reference_status"], "UNVERIFIED")
        self.assertEqual(mapping["evidence_references"][0]["related_event_index"], process_index)
        self.assertEqual(incident.confidence, "medium")
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.CONFIRMED_MALICIOUS)
        self.assertEqual(incident.severity, IncidentSeverity.HIGH)

        exported = _assert_exports(self, collection)
        json_incident = exported["json"]["incidents"][0]
        self.assertEqual(json_incident["analyst_conclusion"], "CONFIRMED_MALICIOUS")
        self.assertEqual(json_incident["severity"], "HIGH")
        self.assertEqual(json_incident["confidence"], "medium")
        self.assertEqual(len(exported["json"]["original_input_records"]), 4)
        self.assertNotIn("collection_metadata", json_incident)
        self.assertNotIn("SYNTHETIC-TEST-DATA", exported["markdown"])
        self.assertIn(r"CONFIRMED\_MALICIOUS", exported["markdown"])
        self.assertIn("UNVERIFIED", exported["markdown"])

    def test_inconclusive_conflict_keeps_skipped_event_out_of_timeline(self) -> None:
        records = [
            _sysmon_event(
                3,
                "2026-02-04T10:00:00Z",
                "4001",
                Image=r"C:\Windows\System32\example.exe",
                ProcessId="4441",
                DestinationIp="203.0.113.66",
            ),
            _sysmon_event(
                1,
                "",
                "4002",
                Image=r"C:\Windows\System32\example.exe",
                ProcessId="4442",
                ParentImage=r"C:\Windows\explorer.exe",
                CommandLine="example.exe --synthetic-incomplete-time",
            ),
        ]
        base_result = enrich_indicator("203.0.113.66", OfflineReputationProvider())
        conflicting_result = EnrichmentResult(
            indicator="203.0.113.66",
            indicator_type="IPv4",
            validation_status="valid",
            reputation_status="synthetic_benign_conflict",
            risk_classification="low",
            source="Synthetic conflicting scenario fixture",
            investigation_recommendation="Keep the conflict visible for analyst review.",
            validation_reason="Synthetic scenario data only.",
            malicious=0,
            suspicious=0,
            harmless=3,
        )
        result_snapshot = copy.deepcopy((base_result, conflicting_result))
        run = _run_offline_pipeline(records, supplied_results=(conflicting_result,))
        correlations = run["correlations"]
        collection = run["collection"]

        self.assertEqual(records, run["raw_snapshot"])
        self.assertEqual(run["ioc_results"], run["ioc_snapshot"])
        self.assertEqual(run["candidates"], ["203.0.113.66"])
        self.assertEqual(len(correlations), 1)
        case = correlations[0]
        self.assertIn("Network connection", case.detection_pattern)
        self.assertTrue(any("Conflicting IOC results" in item for item in case.evidence))
        self.assertTrue(any("Supplied IOC results conflict" in item for item in case.missing_evidence))
        self.assertTrue(any("IOC observation time" in item for item in case.missing_evidence))
        self.assertEqual(len(collection.incidents), 1)
        self.assertEqual(len(collection.skipped_events), 1)
        self.assertEqual(collection.skipped_events[0]["event_id"], 1)
        self.assertTrue(any("timestamp" in item.casefold() for item in collection.diagnostics))
        self.assertEqual(collection.original_input_records, records)

        incident = collection.incidents[0]
        self.assertEqual(len(incident.related_events), 1)
        self.assertEqual(incident.related_events[0]["event"]["event_id"], 3)
        self.assertEqual(len(incident.timeline), 1)
        self.assertEqual(incident.timeline[0].event_id, 3)
        self.assertEqual(incident.timeline[0].related_event_index, 0)
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual(incident.mitre_attack_mappings, [])

        # Only an explicit analyst step changes the conclusion; severity stays unassessed.
        incident.analyst_conclusion = AnalystConclusion.INCONCLUSIVE
        incident.analyst_conclusion_rationale = "Synthetic reputation sources conflict and independent context is absent."
        self.assertEqual(incident.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual((base_result, conflicting_result), result_snapshot)

        exported = _assert_exports(self, collection)
        self.assertEqual(len(exported["json"]["skipped_events"]), 1)
        self.assertEqual(len(exported["json"]["incidents"][0]["timeline"]), 1)
        self.assertNotIn("skipped_events", exported["json"]["incidents"][0])
        self.assertNotIn("diagnostics", exported["json"]["incidents"][0])
        self.assertIn("INCONCLUSIVE", exported["markdown"])
        self.assertIn("Skipped Events", exported["markdown"])

    def test_skip_only_input_keeps_collection_context_without_fabricating_incident(self) -> None:
        records = [
            _sysmon_event(
                3,
                "",
                "5001",
                Image=r"C:\Windows\System32\example.exe",
                ProcessId="4541",
                DestinationIp="203.0.113.66",
            ),
        ]
        result = _run_offline_pipeline(records)
        analysis = result["analysis"]
        correlations = result["correlations"]
        builder_collection = build_incident_report_collection(correlations)

        self.assertEqual(len(correlations), 0)
        self.assertEqual(len(correlations.skipped_events), 1)
        self.assertEqual(builder_collection.incidents, [])
        self.assertEqual(builder_collection.original_input_records, [])

        # The frozen builder has no case from which to recover the input batch.
        # Preserve it explicitly at the existing collection-level field in this test harness.
        preserved_collection = IncidentReportCollection(
            schema_version=builder_collection.schema_version,
            incidents=[],
            diagnostics=builder_collection.diagnostics,
            skipped_events=builder_collection.skipped_events,
            original_input_records=copy.deepcopy(analysis.original_records),
            collection_metadata={
                **builder_collection.collection_metadata,
                "source_type": "test-only zero-case retention wrapper",
                "original_input_batch_count": 1,
                "original_input_batch_boundaries": [{
                    "batch_index": 0,
                    "start": 0,
                    "count": len(analysis.original_records),
                    "source_case_ids": [],
                }],
            },
        )
        self.assertEqual(preserved_collection.incidents, [])
        self.assertEqual(preserved_collection.original_input_records, records)
        self.assertEqual(len(preserved_collection.skipped_events), 1)
        exported = _assert_exports(self, preserved_collection)
        self.assertEqual(exported["json"]["incidents"], [])
        self.assertEqual(len(exported["json"]["original_input_records"]), 1)
        self.assertIn("Skipped Events", exported["markdown"])


if __name__ == "__main__":
    unittest.main()
