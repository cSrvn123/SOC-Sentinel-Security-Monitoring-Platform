"""Stage 7 synthetic SOC investigation using the existing public APIs only."""

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
    IncidentSeverity,
    add_attack_mapping,
    build_incident_report_collection,
    format_json,
    format_markdown,
)
from incident_reporting.timeline import build_timelined_collection
from ioc_enrichment.enrichment import enrich_indicator
from ioc_enrichment.reputation import OfflineReputationProvider
from windows_event_analyzer.analyzer import analyze_records


_HOST = "SOC-LAB-01"
_ACCOUNT = r"SYNTHETIC\analyst.demo"
_SERVICE_ACCOUNT = r"SYNTHETIC\service.demo"
_POWERSHELL_IMAGE = r"C:\Users\SYNTHETIC\analyst.demo\AppData\Local\Temp\powershell.exe"
_SYNTHETIC_SHA256 = "A" * 64
_SUSPICIOUS_IP = "203.0.113.66"
_SUSPICIOUS_DOMAIN = "suspicious.example"


def _security_event(
    event_id: int,
    timestamp: str,
    record_id: str,
    *,
    username: str = _ACCOUNT,
    source_ip: str = "192.0.2.25",
    logon_type: str = "3",
    target_logon_id: str = "0xA100",
) -> dict[str, Any]:
    return {
        "source": "Microsoft-Windows-Security-Auditing",
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": _HOST,
        "channel": "Security",
        "eventRecordID": record_id,
        "event_data": {
            "TargetUserName": username,
            "IpAddress": source_ip,
            "LogonType": logon_type,
            "TargetLogonId": target_logon_id,
        },
    }


def _sysmon_event(
    event_id: int,
    timestamp: str,
    record_id: str,
    **event_data: Any,
) -> dict[str, Any]:
    """Use a Wazuh-shaped Sysmon object accepted by the real analyzer."""
    return {
        "win": {
            "system": {
                "providerName": "Microsoft-Windows-Sysmon",
                "eventID": event_id,
                "systemTime": timestamp,
                "computer": _HOST,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "eventRecordID": record_id,
            },
            "eventdata": event_data,
        }
    }


def _event_data(record: dict[str, Any]) -> dict[str, Any]:
    if "event_data" in record:
        return record["event_data"]
    return record["win"]["eventdata"]


def _record_id(record: dict[str, Any]) -> str:
    if "eventRecordID" in record:
        return str(record["eventRecordID"])
    return str(record["win"]["system"]["eventRecordID"])


def _synthetic_records() -> list[dict[str, Any]]:
    records = [
        _security_event(4625, "2026-04-07T09:58:10+00:00", "7001"),
        _security_event(4625, "2026-04-07T09:58:20+00:00", "7002"),
        _security_event(4625, "2026-04-07T09:58:30+00:00", "7003"),
        _security_event(
            4624,
            "2026-04-07T10:00:00+00:00",
            "7004",
            logon_type="10",
            target_logon_id="0xA101",
        ),
        _sysmon_event(
            1,
            "2026-04-07T10:00:30+00:00",
            "7100",
            User=_ACCOUNT,
            Image=r"C:\Windows\explorer.exe",
            ProcessId="1000",
            ProcessGuid="{11111111-1111-4111-8111-111111111111}",
            ParentImage=r"C:\Windows\winlogon.exe",
            ParentProcessId="700",
            ParentProcessGuid="{00000000-0000-4000-8000-000000000000}",
            CommandLine="explorer.exe",
        ),
        _sysmon_event(
            1,
            "2026-04-07T10:02:00+00:00",
            "7101",
            User=_ACCOUNT,
            Image=_POWERSHELL_IMAGE,
            ProcessId="6684",
            ProcessGuid="{22222222-2222-4222-8222-222222222222}",
            ParentImage=r"C:\Windows\explorer.exe",
            ParentProcessId="1000",
            ParentProcessGuid="{11111111-1111-4111-8111-111111111111}",
            CommandLine="powershell.exe -NoProfile -EncodedCommand SYNTHETIC-TEST-DATA",
            Hashes=f"SHA256={_SYNTHETIC_SHA256}",
        ),
        _sysmon_event(
            22,
            "2026-04-07T10:02:40+00:00",
            "7102",
            User=_ACCOUNT,
            Image=_POWERSHELL_IMAGE,
            ProcessId="6684",
            ProcessGuid="{22222222-2222-4222-8222-222222222222}",
            QueryName=_SUSPICIOUS_DOMAIN,
            QueryStatus="0",
            QueryResults="203.0.113.66",
        ),
        _sysmon_event(
            3,
            "2026-04-07T10:03:00+00:00",
            "7103",
            User=_ACCOUNT,
            Image=_POWERSHELL_IMAGE,
            ProcessId="6684",
            ProcessGuid="{22222222-2222-4222-8222-222222222222}",
            Protocol="tcp",
            SourceIp="192.0.2.25",
            SourcePort="51432",
            DestinationIp=_SUSPICIOUS_IP,
            DestinationPort="443",
        ),
        # Unrelated, ordinary process activity on the same host and account.
        _sysmon_event(
            1,
            "2026-04-07T10:03:30+00:00",
            "7201",
            User=_ACCOUNT,
            Image=r"C:\Windows\System32\notepad.exe",
            ProcessId="8120",
            ProcessGuid="{33333333-3333-4333-8333-333333333333}",
            ParentImage=r"C:\Windows\explorer.exe",
            ParentProcessId="1000",
            ParentProcessGuid="{11111111-1111-4111-8111-111111111111}",
            CommandLine="notepad.exe",
        ),
        # A separate synthetic user and logon, unrelated to the target sequence.
        _security_event(
            4624,
            "2026-04-07T10:05:00+00:00",
            "7010",
            username=_SERVICE_ACCOUNT,
            source_ip="192.0.2.80",
            logon_type="5",
            target_logon_id="0xB200",
        ),
    ]
    return records


def _extract_synthetic_hash(record: dict[str, Any]) -> str:
    """Extract SHA-256 from raw Event ID 1 data; the analyzer has no hash field."""
    hashes = _event_data(record).get("Hashes", "")
    for item in hashes.split(","):
        algorithm, separator, value = item.partition("=")
        if separator and algorithm.strip().casefold() == "sha256":
            return value.strip()
    raise AssertionError("Synthetic process record did not contain its expected SHA-256 field.")


def _compose_investigation_cases(
    cases: list[InvestigationCase],
    source_report: CorrelationReport,
) -> CorrelationReport:
    """Test-only analyst composition; this is not correlate() behavior."""
    expected_patterns = {
        "Repeated failed logons followed by successful logon",
        "Successful logon followed by unusual process creation",
        "Network connection associated with an available IOC result",
        "DNS query associated with an available IOC result",
    }
    if len(cases) != len(expected_patterns) or {case.detection_pattern for case in cases} != expected_patterns:
        raise AssertionError("Expected one independent engine case for each Stage 7 pattern.")

    related_by_reference: dict[str, dict[str, Any]] = {}
    for case in cases:
        for related in case.related_events:
            references = related.get("source_references", [])
            if len(references) != 1 or not isinstance(references[0], str):
                raise AssertionError("Composition requires one stable source reference per synthetic event.")
            reference = references[0]
            existing = related_by_reference.get(reference)
            if existing is not None and existing != related:
                raise AssertionError("One source reference resolved to conflicting event evidence.")
            related_by_reference[reference] = copy.deepcopy(related)

    related_events = sorted(
        related_by_reference.values(),
        key=lambda related: (
            related["event"]["timestamp"],
            related["source_references"][0],
        ),
    )
    confidence_values = {case.confidence for case in cases}
    if len(confidence_values) != 1:
        raise AssertionError("This training composition does not aggregate confidence categories.")
    source_records = copy.deepcopy(cases[0].source_records)
    if any(case.source_records != source_records for case in cases):
        raise AssertionError("Component cases do not refer to the same preserved input batch.")

    composite = InvestigationCase(
        case_id="STAGE7-SYNTHETIC-001",
        detection_pattern="Analyst-curated suspicious PowerShell investigation",
        first_observed=min(case.first_observed for case in cases),
        last_observed=max(case.last_observed for case in cases),
        related_events=related_events,
        accounts=sorted({value for case in cases for value in case.accounts}),
        computers=sorted({value for case in cases for value in case.computers}),
        ips=sorted({value for case in cases for value in case.ips}),
        evidence=[item for case in cases for item in case.evidence],
        missing_evidence=list(dict.fromkeys(item for case in cases for item in case.missing_evidence)),
        recommendations=list(dict.fromkeys(item for case in cases for item in case.recommendations)),
        confidence=next(iter(confidence_values)),
        confidence_explanation=(
            "Copied from four medium-confidence component correlations; the analyst composition "
            "does not increase correlation confidence."
        ),
        source_records=source_records,
        source_issues=list(dict.fromkeys(issue for case in cases for issue in case.source_issues)),
    )
    return CorrelationReport(
        [composite],
        diagnostics=source_report.diagnostics,
        skipped_events=source_report.skipped_events,
    )


def _run_synthetic_pipeline() -> dict[str, Any]:
    records = _synthetic_records()
    raw_snapshot = copy.deepcopy(records)
    analysis = analyze_records(records)

    # Indicator extraction is explicit. IP and domain come from normalized
    # network/DNS events; the process hash is extracted from its retained raw record.
    network_events = [event for event in analysis.events if event.event_source == "Sysmon" and event.event_id == 3]
    dns_events = [event for event in analysis.events if event.event_source == "Sysmon" and event.event_id == 22]
    process_records = [
        record for record in analysis.original_records
        if _event_data(record).get("Image") == _POWERSHELL_IMAGE
        and _event_data(record).get("Hashes") == f"SHA256={_SYNTHETIC_SHA256}"
    ]
    if len(network_events) != 1 or len(dns_events) != 1 or len(process_records) != 1:
        raise AssertionError("Synthetic indicator extraction inputs were incomplete or ambiguous.")
    indicators = [
        network_events[0].destination_ip,
        dns_events[0].dns_query,
        _extract_synthetic_hash(process_records[0]),
    ]
    if indicators != [_SUSPICIOUS_IP, _SUSPICIOUS_DOMAIN, _SYNTHETIC_SHA256]:
        raise AssertionError("Indicator extraction returned unexpected values.")

    offline_provider = OfflineReputationProvider()
    enrichment_results = [enrich_indicator(value, offline_provider) for value in indicators]
    enrichment_snapshot = copy.deepcopy(enrichment_results)
    correlations = correlate(
        analysis,
        ioc_results=enrichment_results,
        config=CorrelationConfig(
            failed_logon_threshold=3,
            failed_to_success_window=timedelta(minutes=10),
            logon_to_process_window=timedelta(minutes=10),
        ),
    )
    component_collection = build_timelined_collection(build_incident_report_collection(correlations))
    analyst_composition = _compose_investigation_cases(list(correlations), correlations)
    collection = build_timelined_collection(build_incident_report_collection(analyst_composition))

    incident = collection.incidents[0]
    incident.evidence_limitations.extend([
        "No verified payload analysis was performed; the command line is inert synthetic text.",
        "Process lineage is not independently verified by a PID or ProcessGuid analysis module.",
        "No independently verified threat-intelligence reputation is available; all IOC results are synthetic.",
        "No live endpoint investigation, Wazuh alert, or Wazuh rule-engine validation occurred.",
        "No confirmed business impact or asset-criticality information is available.",
        "Network and DNS process associations are analyst hypotheses based on matching event fields, not engine-established links.",
    ])
    incident.analyst_conclusion = AnalystConclusion.SUSPICIOUS
    incident.analyst_conclusion_rationale = (
        "The synthetic process event uses a writable path and is followed by matching synthetic network and DNS "
        "indicator associations. These signals justify continued investigation, but synthetic reputation, an "
        "encoded-command string, and event-field matches do not prove payload execution or malicious intent."
    )
    incident.severity = IncidentSeverity.MEDIUM
    incident.severity_rationale = (
        "Analyst-selected medium triage urgency for several related suspicious signals on one synthetic host; "
        "no confirmed impact, data loss, persistence, or critical-asset context is present."
    )
    process_index = next(
        index for index, related in enumerate(incident.related_events)
        if related["event"]["event_id"] == 1
        and related["event"].get("process_path") == _POWERSHELL_IMAGE
    )
    mapping = add_attack_mapping(
        incident,
        technique_id="T1059.001",
        technique_name="PowerShell",
        rationale="The referenced Sysmon Event ID 1 records a PowerShell process invocation; this does not establish malicious intent.",
        evidence_references=[process_index],
    )

    return {
        "records": records,
        "raw_snapshot": raw_snapshot,
        "analysis": analysis,
        "indicators": indicators,
        "enrichment_results": enrichment_results,
        "enrichment_snapshot": enrichment_snapshot,
        "correlations": correlations,
        "component_collection": component_collection,
        "collection": collection,
        "incident": incident,
        "mapping": mapping,
    }


class Stage7SocInvestigationTests(unittest.TestCase):
    def test_complete_synthetic_investigation_preserves_evidence_and_exports(self) -> None:
        run = _run_synthetic_pipeline()
        records = run["records"]
        analysis = run["analysis"]
        correlations = run["correlations"]
        collection = run["collection"]
        incident = run["incident"]

        self.assertEqual(analysis.input_record_count, len(records))
        self.assertEqual(len(analysis.events), len(records))
        self.assertEqual(analysis.original_records, records)
        self.assertEqual([event.event_id for event in analysis.events], [
            4625, 4625, 4625, 4624, 1, 1, 22, 3, 1, 4624,
        ])

        powershell = next(event for event in analysis.events if event.process_path == _POWERSHELL_IMAGE)
        self.assertEqual(powershell.process_id, "6684")
        self.assertEqual(powershell.parent_process, r"C:\Windows\explorer.exe")
        self.assertEqual(powershell.command_line, "powershell.exe -NoProfile -EncodedCommand SYNTHETIC-TEST-DATA")
        self.assertTrue(any("user-writable location" in item for item in powershell.observations))
        self.assertFalse(hasattr(powershell, "hashes"))
        network_event = next(event for event in analysis.events if event.event_id == 3)
        dns_event = next(event for event in analysis.events if event.event_id == 22)
        self.assertEqual(network_event.destination_ip, _SUSPICIOUS_IP)
        self.assertEqual(network_event.process_id, "6684")
        self.assertEqual(dns_event.dns_query, _SUSPICIOUS_DOMAIN)
        self.assertEqual(dns_event.process_id, "6684")
        raw_process = next(record for record in analysis.original_records if _record_id(record) == "7101")
        self.assertEqual(_event_data(raw_process)["ProcessGuid"], "{22222222-2222-4222-8222-222222222222}")
        self.assertEqual(_event_data(raw_process)["ParentProcessGuid"], "{11111111-1111-4111-8111-111111111111}")
        self.assertEqual(_event_data(raw_process)["ParentProcessId"], "1000")
        self.assertEqual(_extract_synthetic_hash(raw_process), _SYNTHETIC_SHA256)
        raw_network = next(record for record in analysis.original_records if _record_id(record) == "7103")
        self.assertEqual(_event_data(raw_network)["Protocol"], "tcp")
        self.assertEqual(_event_data(raw_network)["SourcePort"], "51432")
        self.assertEqual(_event_data(raw_network)["DestinationPort"], "443")
        raw_dns = next(record for record in analysis.original_records if _record_id(record) == "7102")
        self.assertEqual(_event_data(raw_dns)["QueryResults"], "203.0.113.66")

        self.assertEqual(run["indicators"], [_SUSPICIOUS_IP, _SUSPICIOUS_DOMAIN, _SYNTHETIC_SHA256])
        ioc_by_indicator = {item.indicator: item for item in run["enrichment_results"]}
        self.assertEqual(ioc_by_indicator[_SUSPICIOUS_IP].reputation_status, "synthetic_suspicious")
        self.assertEqual(ioc_by_indicator[_SUSPICIOUS_DOMAIN].reputation_status, "synthetic_suspicious")
        self.assertEqual(ioc_by_indicator[_SYNTHETIC_SHA256.lower()].reputation_status, "synthetic_unknown")
        self.assertTrue(all("Synthetic offline" in item.source for item in run["enrichment_results"]))
        self.assertFalse(ipaddress.ip_address(_SUSPICIOUS_IP).is_global)

        expected_patterns = {
            "Repeated failed logons followed by successful logon",
            "Successful logon followed by unusual process creation",
            "Network connection associated with an available IOC result",
            "DNS query associated with an available IOC result",
        }
        self.assertEqual(len(correlations), 4)
        self.assertEqual({case.detection_pattern for case in correlations}, expected_patterns)
        self.assertTrue(all(case.confidence == "medium" for case in correlations))
        self.assertEqual(len(run["component_collection"].incidents), 4)
        self.assertTrue(all(item.analyst_conclusion == AnalystConclusion.NOT_ASSESSED for item in run["component_collection"].incidents))
        self.assertTrue(all(item.severity == IncidentSeverity.NOT_ASSESSED for item in run["component_collection"].incidents))

        network_case = next(case for case in correlations if "Network connection" in case.detection_pattern)
        dns_case = next(case for case in correlations if "DNS query" in case.detection_pattern)
        self.assertEqual(len(network_case.related_events), 1)
        self.assertEqual(len(dns_case.related_events), 1)
        self.assertEqual(network_case.related_events[0]["event"]["event_id"], 3)
        self.assertEqual(dns_case.related_events[0]["event"]["event_id"], 22)
        self.assertIn("Synthetic offline", " ".join(network_case.evidence))
        self.assertIn("Synthetic offline", " ".join(dns_case.evidence))
        process_case = next(case for case in correlations if "unusual process" in case.detection_pattern)
        self.assertTrue(any("Process lineage is not confirmed" in item for item in process_case.missing_evidence))

        relevant_ids = {"7001", "7002", "7003", "7004", "7100", "7101", "7102", "7103"}
        record_id_by_reference = {
            reference: _record_id(related["original_record"])
            for related in incident.related_events
            for reference in related["source_references"]
        }
        timeline_record_ids = [
            record_id_by_reference[reference]
            for entry in incident.timeline
            for reference in entry.source_references
        ]
        self.assertEqual(set(timeline_record_ids), relevant_ids)
        self.assertNotIn("7201", timeline_record_ids)
        self.assertNotIn("7010", timeline_record_ids)
        self.assertEqual(len(collection.original_input_records), len(records))
        self.assertEqual(collection.original_input_records, records)
        self.assertEqual(collection.collection_metadata["original_input_batch_count"], 1)
        self.assertTrue(all(entry.provenance_status == "matched" for entry in incident.provenance))
        for provenance in incident.provenance:
            related = incident.related_events[provenance.related_event_index]
            self.assertEqual(provenance.source_references, related["source_references"])
            self.assertEqual(provenance.original_record, related["original_record"])
        self.assertEqual(len(incident.timeline), len(incident.related_events))
        self.assertEqual(
            [entry.related_event_index for entry in incident.timeline],
            list(range(len(incident.related_events))),
        )
        originals_by_id = {_record_id(record): record for record in records}
        for provenance in incident.provenance:
            record_id = _record_id(provenance.original_record)
            self.assertEqual(provenance.original_record, originals_by_id[record_id])

        self.assertEqual(incident.confidence, "medium")
        self.assertEqual(incident.analyst_conclusion, AnalystConclusion.SUSPICIOUS)
        self.assertEqual(incident.severity, IncidentSeverity.MEDIUM)
        self.assertIn("synthetic reputation", incident.analyst_conclusion_rationale)
        self.assertIn("no confirmed impact", incident.severity_rationale)
        self.assertNotEqual(incident.analyst_conclusion_rationale, incident.severity_rationale)
        self.assertEqual(run["mapping"]["technique_id"], "T1059.001")
        self.assertEqual(run["mapping"]["reference_status"], "UNVERIFIED")
        mapped_index = run["mapping"]["evidence_references"][0]["related_event_index"]
        self.assertEqual(incident.related_events[mapped_index]["event"]["event_id"], 1)
        for source_reference in incident.related_events[mapped_index]["source_references"]:
            self.assertIn(source_reference, run["mapping"]["evidence_references"][0]["source_references"])
        self.assertEqual(incident.mitre_attack_mappings[0]["reference_status"], "UNVERIFIED")
        component_evidence = {item for case in correlations for item in case.evidence}
        self.assertTrue(component_evidence.issubset(set(incident.evidence)))

        json_text = format_json(collection)
        self.assertEqual(json_text, format_json(collection))
        exported = json.loads(json_text)
        self.assertEqual(exported["incidents"][0]["confidence"], "medium")
        self.assertEqual(exported["incidents"][0]["severity"], "MEDIUM")
        self.assertEqual(exported["incidents"][0]["analyst_conclusion"], "SUSPICIOUS")
        self.assertEqual(exported["incidents"][0]["mitre_attack_mappings"][0]["reference_status"], "UNVERIFIED")
        self.assertEqual(len(exported["original_input_records"]), len(records))
        self.assertNotIn("original_input_records", exported["incidents"][0])

        markdown = format_markdown(collection)
        self.assertEqual(markdown, format_markdown(collection))
        for section in (
            "Incident Summary", "Correlation Confidence", "Severity Assessment", "Analyst Conclusion",
            "Severity Rationale", "Analyst Conclusion Rationale", "Timeline", "Evidence",
            "Missing Evidence", "Recommendations", "MITRE ATT&CK Mappings",
            "Provenance and Evidence Limitations",
        ):
            self.assertIn(section, markdown)
        self.assertIn("UNVERIFIED", markdown)
        self.assertNotIn("SYNTHETIC-TEST-DATA", markdown)
        self.assertNotIn("eventdata", markdown.casefold())

        # Review and export must not mutate the caller-owned event or IOC inputs.
        self.assertEqual(records, run["raw_snapshot"])
        self.assertEqual(run["enrichment_results"], run["enrichment_snapshot"])

    def test_indicator_matches_and_confidence_do_not_auto_assess_or_link_processes(self) -> None:
        run = _run_synthetic_pipeline()
        correlations = run["correlations"]
        component_incidents = run["component_collection"].incidents
        self.assertTrue(all(incident.analyst_conclusion == AnalystConclusion.NOT_ASSESSED for incident in component_incidents))
        self.assertTrue(all(incident.severity == IncidentSeverity.NOT_ASSESSED for incident in component_incidents))

        for case in correlations:
            if "Network connection" in case.detection_pattern or "DNS query" in case.detection_pattern:
                # The engine associates one event with a supplied IOC; it does not
                # join that event to Sysmon Event ID 1 by ProcessId or ProcessGuid.
                self.assertEqual(len(case.related_events), 1)
                self.assertNotEqual(case.related_events[0]["event"]["event_id"], 1)
                self.assertEqual(case.confidence, "medium")

    def test_encoded_command_text_alone_is_not_a_detection_or_malicious_verdict(self) -> None:
        records = [
            _security_event(4624, "2026-04-07T11:00:00Z", "8001"),
            _sysmon_event(
                1,
                "2026-04-07T11:01:00Z",
                "8002",
                User=_ACCOUNT,
                Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ProcessId="9000",
                ProcessGuid="{44444444-4444-4444-8444-444444444444}",
                ParentImage=r"C:\Windows\explorer.exe",
                ParentProcessId="1000",
                ParentProcessGuid="{11111111-1111-4111-8111-111111111111}",
                CommandLine="powershell.exe -EncodedCommand SYNTHETIC-TEST-DATA",
            ),
        ]
        analysis = analyze_records(records)
        self.assertFalse(analysis.events[1].observations)
        report = correlate(analysis)
        self.assertEqual(len(report), 0)
        collection = build_timelined_collection(build_incident_report_collection(report))
        self.assertEqual(collection.incidents, [])


if __name__ == "__main__":
    unittest.main()
