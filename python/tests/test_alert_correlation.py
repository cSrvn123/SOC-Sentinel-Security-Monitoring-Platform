from __future__ import annotations

import json
import copy
import unittest
from dataclasses import dataclass
from datetime import timedelta
from types import SimpleNamespace

from windows_event_analyzer.analyzer import analyze_records
from ioc_enrichment.models import EnrichmentResult

from alert_correlation.engine import CorrelationConfig, _canonical_raw_payload, _prepare, _source_identity, correlate
from alert_correlation.formatting import DISCLAIMER, format_json, format_text
from alert_correlation.models import CorrelationReport, InvestigationCase


def security(event_id: int, stamp: str, computer: str = "LAB-A", user: str = "analyst", ip: str = "203.0.113.10") -> dict[str, object]:
    record: dict[str, object] = {"source": "Microsoft-Windows-Security-Auditing", "event_id": event_id,
        "timestamp": stamp, "computer": computer, "event_data": {"TargetUserName": user, "IpAddress": ip}}
    return record


def sysmon(event_id: int, stamp: str, computer: str = "LAB-A", user: str = "analyst", **data: object) -> dict[str, object]:
    payload = {"User": user, **data}
    return {"source": "Microsoft-Windows-Sysmon/Operational", "event_id": event_id,
        "timestamp": stamp, "computer": computer, "event_data": payload}


def normalized(*records: dict[str, object]):
    return analyze_records(list(records))


def ioc(value: str, kind: str = "domain", status: str = "synthetic_suspicious", validation: str = "valid",
        *, risk: str = "unknown", source: str = "Synthetic offline fixture",
        recommendation: str = "Synthetic only", malicious: int | None = None,
        suspicious: int | None = None, harmless: int | None = None,
        error: str | None = None) -> EnrichmentResult:
    return EnrichmentResult(value, kind, validation, status, risk, source,
        recommendation, "synthetic test", malicious=malicious, suspicious=suspicious,
        harmless=harmless, error=error)


@dataclass
class IOCDetail:
    count: int
    note: str


@dataclass
class DataclassIOCResult:
    indicator: str
    validation_status: str
    reputation_status: str
    risk_classification: str
    source: str
    investigation_recommendation: str
    detail: IOCDetail


@dataclass
class RawSourceDataclass:
    label: str
    nested: object


class RawSourceObject:
    def __init__(self, value: object) -> None:
        self.value = value


class UnsupportedRawValue:
    __slots__ = ()


class OrdinaryIOCDetail:
    def __init__(self) -> None:
        self.counts = {"malicious": 4, "harmless": 12}
        self.notes = ["synthetic", "nested"]


class UnsupportedIOCValue:
    __slots__ = ()

    def __str__(self) -> str:
        return "must-not-be-used-as-evidence"


class IOCWithRaisingDict:
    __slots__ = ("indicator", "validation_status", "reputation_status", "risk_classification", "source", "detail")

    def __init__(self, detail: object) -> None:
        self.indicator = "updates.example"
        self.validation_status = "valid"
        self.reputation_status = "unknown"
        self.risk_classification = "unknown"
        self.source = "synthetic fixture"
        self.detail = detail

    @property
    def __dict__(self):
        raise RuntimeError("synthetic __dict__ access failure")


class IOCWithRaisingSlot:
    __slots__ = ("indicator", "validation_status", "reputation_status", "risk_classification",
                 "source", "available", "detail", "failure_type")

    def __init__(self, detail: object, failure_type: type[Exception]) -> None:
        self.indicator = "updates.example"
        self.validation_status = "valid"
        self.reputation_status = "unknown"
        self.risk_classification = "unknown"
        self.source = "synthetic fixture"
        self.available = {"note": "retained synthetic detail"}
        self.detail = detail
        self.failure_type = failure_type

    def __getattribute__(self, name: str):
        if name == "detail":
            error_type = object.__getattribute__(self, "failure_type")
            raise error_type("synthetic slot access failure")
        return object.__getattribute__(self, name)


@dataclass
class IOCWithRaisingDataclassField:
    indicator: str = "updates.example"
    validation_status: str = "valid"
    reputation_status: str = "unknown"
    risk_classification: str = "unknown"
    source: str = "synthetic fixture"
    available: str = "accessible dataclass field"
    detail: str = "unavailable synthetic field"

    def __getattribute__(self, name: str):
        if name == "detail":
            raise AttributeError("synthetic dataclass field access failure")
        return object.__getattribute__(self, name)


class RawInheritedSlotBase:
    __slots__ = ("base_value",)


class RawSlotAttributeFailure(RawInheritedSlotBase):
    __slots__ = ("visible", "missing_by_attribute_error", "missing_by_value_error")

    def __init__(self) -> None:
        self.base_value = "inherited synthetic value"
        self.visible = "visible synthetic value"
        self.missing_by_attribute_error = "not printed"
        self.missing_by_value_error = "not printed"

    def __getattribute__(self, name: str):
        if name == "missing_by_attribute_error":
            raise AttributeError("synthetic declared slot failure")
        if name == "missing_by_value_error":
            raise ValueError("synthetic second slot failure")
        return object.__getattribute__(self, name)


class SpecialAttributeError(AttributeError):
    pass


class SpecialRuntimeError(RuntimeError):
    pass


class RawSlotWithAccessibleSibling:
    __slots__ = ("visible", "hidden")

    def __init__(self) -> None:
        self.visible = "accessible sibling"
        self.hidden = "synthetic inaccessible value"


class RawSpecialAttributeSlot(RawSlotWithAccessibleSibling):
    __slots__ = ()

    def __getattribute__(self, name: str):
        if name == "hidden":
            raise SpecialAttributeError("synthetic slot failure")
        return object.__getattribute__(self, name)


class RawSpecialRuntimeSlot(RawSlotWithAccessibleSibling):
    __slots__ = ()

    def __getattribute__(self, name: str):
        if name == "hidden":
            raise SpecialRuntimeError("synthetic slot failure")
        return object.__getattribute__(self, name)


class RawSingleAttributeError:
    __slots__ = ("visible", "hidden")

    def __init__(self) -> None:
        self.visible = "accessible sibling"
        self.hidden = "private synthetic value"

    def __getattribute__(self, name: str):
        if name == "hidden":
            raise AttributeError("synthetic hidden slot failure")
        return object.__getattribute__(self, name)


class RawDeclaredSlot:
    __slots__ = ("declared",)

    def __init__(self) -> None:
        self.declared = "declared synthetic value"


@dataclass
class RawDataclassAttributeError:
    visible: str = "accessible dataclass value"
    hidden: str = "not printed"

    def __getattribute__(self, name: str):
        if name == "hidden":
            raise AttributeError("synthetic dataclass field failure")
        return object.__getattribute__(self, name)


class RawComputedProperty:
    def __init__(self) -> None:
        self.visible = "ordinary instance value"
        self.property_calls = 0

    @property
    def computed(self):
        self.property_calls += 1
        raise RuntimeError("computed property should not be invoked")


class AlertCorrelationTests(unittest.TestCase):
    def test_failed_logons_followed_by_success(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:20Z"),
                   security(4625, "2026-01-01T10:00:40Z"), security(4624, "2026-01-01T10:01:00Z")]
        cases = correlate(normalized(*records))
        self.assertEqual(len(cases), 1)
        self.assertIn("Repeated failed logons followed", cases[0].detection_pattern)
        self.assertEqual(len(cases[0].related_events), 4)
        self.assertEqual(cases[0].confidence, "medium")
        self.assertIn("not proof", cases[0].confidence_explanation)

    def test_successful_logon_followed_by_unusual_process(self) -> None:
        records = [security(4624, "2026-01-01T10:00:00Z"),
            sysmon(1, "2026-01-01T10:01:30Z", Image=r"C:\Windows\explorer.exe", ProcessId="100"),
            sysmon(1, "2026-01-01T10:02:00Z", Image=r"C:\Users\analyst\AppData\Local\Temp\tool.exe", ParentImage=r"C:\Windows\explorer.exe")]
        cases = correlate(normalized(*records))
        self.assertEqual(len(cases), 1)
        self.assertIn("unusual process creation", cases[0].detection_pattern)
        self.assertTrue(any("user-writable" in evidence for evidence in cases[0].evidence))
        self.assertEqual(len(cases[0].related_events), 3)

    def test_parent_image_match_is_contextual_not_confirmed_lineage(self) -> None:
        records = [security(4624, "2026-01-01T10:00:00Z"),
            sysmon(1, "2026-01-01T10:00:30Z", Image=r"C:\Windows\explorer.exe", ProcessId="100"),
            sysmon(1, "2026-01-01T10:01:00Z", Image=r"C:\Users\analyst\AppData\Local\Temp\tool.exe",
                   ParentImage=r"C:\Windows\explorer.exe", ProcessId="200")]
        case = correlate(normalized(*records))[0]
        evidence = "\n".join(case.evidence).casefold()
        self.assertIn("contextual evidence only", evidence)
        self.assertIn("not confirmed process lineage", evidence)
        self.assertTrue(any("not confirmed" in item.casefold() and "process lineage" in item.casefold()
                            for item in case.missing_evidence))

    def test_network_connection_matches_valid_ioc(self) -> None:
        event = sysmon(3, "2026-01-01T10:00:00Z", Image=r"C:\Windows\example.exe", DestinationIp="203.0.113.66")
        cases = correlate(normalized(event), [ioc("203.0.113.66", "IPv4")])
        self.assertEqual(len(cases), 1)
        self.assertIn("Network connection", cases[0].detection_pattern)
        self.assertTrue(any("No lookup was performed" in item for item in cases[0].evidence))

    def test_dns_query_matches_available_ioc(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        cases = correlate(normalized(event), [ioc("updates.example")])
        self.assertEqual(len(cases), 1)
        self.assertIn("DNS query", cases[0].detection_pattern)

    def test_event_time_window_and_identity_boundaries(self) -> None:
        base = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:20:00Z")]
        self.assertFalse(correlate(normalized(*base)))
        diff_account = [security(4625, "2026-01-01T10:00:00Z", user="other"),
                        security(4625, "2026-01-01T10:00:10Z", user="other"),
                        security(4625, "2026-01-01T10:00:20Z", user="other"),
                        security(4624, "2026-01-01T10:00:30Z", user="analyst")]
        self.assertFalse(correlate(normalized(*diff_account)))
        diff_computer = [security(4625, "2026-01-01T10:00:00Z", computer="LAB-B"),
                         security(4625, "2026-01-01T10:00:10Z", computer="LAB-B"),
                         security(4625, "2026-01-01T10:00:20Z", computer="LAB-B"),
                         security(4624, "2026-01-01T10:00:30Z", computer="LAB-A")]
        self.assertFalse(correlate(normalized(*diff_computer)))

    def test_failed_to_success_requires_source_ip_match_when_both_are_present(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z", ip="203.0.113.10"),
                   security(4625, "2026-01-01T10:00:10Z", ip="203.0.113.10"),
                   security(4625, "2026-01-01T10:00:20Z", ip="203.0.113.10"),
                   security(4624, "2026-01-01T10:00:30Z", ip="203.0.113.11")]
        self.assertFalse(correlate(normalized(*records)))

    def test_missing_success_source_ip_is_reported_without_claiming_ip_match(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z", ip="203.0.113.10"),
                   security(4625, "2026-01-01T10:00:10Z", ip="203.0.113.10"),
                   security(4625, "2026-01-01T10:00:20Z", ip="203.0.113.10"),
                   security(4624, "2026-01-01T10:00:30Z", ip="-")]
        case = correlate(normalized(*records))[0]
        self.assertTrue(any("Source-IP continuity could not be established" in item
                            for item in case.missing_evidence))
        self.assertIn("continuity could not be established", case.evidence[0])
        self.assertNotIn("matching source IP", case.evidence[0])

    def test_time_window_end_boundary_is_inclusive(self) -> None:
        records = [security(4625, "2026-01-01T10:00:20Z"),
                   security(4625, "2026-01-01T10:00:25Z"),
                   security(4625, "2026-01-01T10:00:29Z"),
                   security(4624, "2026-01-01T10:00:30Z")]
        config = CorrelationConfig(failed_to_success_window=timedelta(seconds=10))
        self.assertTrue(correlate(normalized(*records), config=config))

    def test_timezone_offsets_are_compared_as_utc(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z"),
                   security(4625, "2026-01-01T15:30:05+05:30"),
                   security(4625, "2026-01-01T04:00:10-06:00"),
                   security(4624, "2026-01-01T10:00:20Z")]
        config = CorrelationConfig(failed_to_success_window=timedelta(seconds=20))
        self.assertTrue(correlate(normalized(*records), config=config))

    def test_logon_process_outside_window_does_not_correlate(self) -> None:
        records = [security(4624, "2026-01-01T10:00:00Z"),
            sysmon(1, "2026-01-01T10:20:00Z", Image=r"C:\Users\analyst\AppData\Local\Temp\tool.exe")]
        self.assertFalse(correlate(normalized(*records)))

    def test_missing_timestamps_and_hosts_block_cases(self) -> None:
        bad_time = [security(4625, ""), security(4625, ""), security(4625, ""), security(4624, "")]
        self.assertFalse(correlate(normalized(*bad_time)))
        no_host = [security(4625, f"2026-01-01T10:00:0{i}Z") for i in range(3)]
        no_host.append(security(4624, "2026-01-01T10:00:05Z"))
        for row in no_host: row.pop("computer")
        self.assertFalse(correlate(normalized(*no_host)))

    def test_report_exposes_collision_diagnostics_without_a_case(self) -> None:
        first = security(4625, "2026-01-01T10:00:00Z")
        second = security(4625, "2026-01-01T10:00:01Z")
        for row in (first, second):
            row.update({"channel": "Security", "record_id": "711"})
        report = correlate(analyze_records([first, second]))
        self.assertIsInstance(report, CorrelationReport)
        self.assertEqual(report.cases, [])
        self.assertTrue(any("Source identity collision" in item for item in report.diagnostics))
        self.assertEqual(report.skipped_events, [])

    def test_report_exposes_missing_timestamp_and_host_skips_without_cases(self) -> None:
        missing_time = security(4625, "")
        missing_host = security(4625, "2026-01-01T10:00:00Z")
        missing_host.pop("computer")
        report = correlate(analyze_records([missing_time, missing_host]))
        self.assertFalse(report.cases)
        self.assertEqual(len(report.skipped_events), 2)
        self.assertTrue(any("timestamp" in item.casefold() for item in report.diagnostics))
        self.assertTrue(any("computer identity" in item.casefold() for item in report.diagnostics))
        self.assertEqual(len({item["event_index"] for item in report.skipped_events}), 2)

    def test_required_account_network_and_dns_fields_are_reported_as_skips(self) -> None:
        rows = [
            security(4625, "2026-01-01T10:00:00Z", user=""),
            security(4624, "2026-01-01T10:00:01Z", user=""),
            sysmon(1, "2026-01-01T10:00:02Z", user="", Image=r"C:\Users\analyst\AppData\Local\Temp\tool.exe"),
            sysmon(3, "2026-01-01T10:00:03Z", DestinationIp=""),
            sysmon(22, "2026-01-01T10:00:04Z", QueryName=""),
        ]
        report = correlate(analyze_records(rows))
        self.assertEqual(len(report), 0)
        self.assertEqual(len(report.skipped_events), 5)
        reasons = [item["reason"].casefold() for item in report.skipped_events]
        self.assertIn("username/account", reasons[0])
        self.assertIn("username/account", reasons[1])
        self.assertIn("username/account", reasons[2])
        self.assertIn("destination ip", reasons[3])
        self.assertIn("dns query", reasons[4])
        exclusion_diagnostics = [item for item in report.diagnostics if "excluded from correlation" in item]
        self.assertEqual(len(exclusion_diagnostics), 5)
        self.assertTrue(all("maliciousness verdict" in issue for issue in exclusion_diagnostics))

    def test_ordinary_ioc_nonmatch_does_not_create_a_skipped_event_warning(self) -> None:
        event = sysmon(3, "2026-01-01T10:00:00Z", DestinationIp="203.0.113.9")
        event.update({"channel": "Microsoft-Windows-Sysmon/Operational", "record_id": "748"})
        report = correlate(analyze_records([event]), [ioc("203.0.113.10")])
        self.assertEqual(report, [])
        self.assertEqual(report.skipped_events, [])
        self.assertFalse(any("excluded from correlation" in issue for issue in report.diagnostics))

    def test_missing_username_for_success_matching_two_patterns_has_one_skip_entry(self) -> None:
        rows = [security(4625, "2026-01-01T10:00:00Z"),
                security(4625, "2026-01-01T10:00:10Z"),
                security(4625, "2026-01-01T10:00:20Z"),
                security(4624, "2026-01-01T10:00:30Z", user=""),
                sysmon(1, "2026-01-01T10:00:31Z", Image=r"C:\Users\analyst\AppData\Local\Temp\tool.exe")]
        report = correlate(analyze_records(rows))
        success_skips = [item for item in report.skipped_events if item["event_id"] == 4624]
        self.assertEqual(len(success_skips), 1)
        self.assertIn("username/account", success_skips[0]["reason"])
        self.assertEqual(sum("normalized position 3" in issue for issue in report.diagnostics), 1)

    def test_report_keeps_list_compatibility_and_exposes_cases_and_diagnostics(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                   security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        report = correlate(normalized(*records))
        self.assertIsInstance(report, list)
        self.assertIs(report.cases, report)
        self.assertEqual(len(report.cases), 1)
        self.assertIsInstance(report.diagnostics, list)
        self.assertIsInstance(report[:], list)
        self.assertEqual(report[0], report.cases[0])
        self.assertEqual(bool(report), True)

    def test_report_metadata_accessors_return_defensive_copies(self) -> None:
        row = security(4625, "")
        report = correlate(analyze_records([row]))
        expected_diagnostics = report.diagnostics
        expected_skips = report.skipped_events
        report.diagnostics.append("caller mutation")
        report.skipped_events[0]["reason"] = "caller mutation"
        self.assertEqual(report.diagnostics, expected_diagnostics)
        self.assertEqual(report.skipped_events, expected_skips)
        # Case list mutation remains ordinary list behavior and does not rewrite
        # the immutable-in-practice metadata snapshot for the original run.
        report.clear()
        self.assertEqual(report.cases, [])
        self.assertEqual(report.diagnostics, expected_diagnostics)

    def test_empty_input_returns_empty_report_and_diagnostics(self) -> None:
        report = correlate(analyze_records([]))
        self.assertEqual(report.cases, [])
        self.assertEqual(report.diagnostics, [])
        self.assertEqual(report.skipped_events, [])

    def test_exact_duplicate_source_record_ingestion_is_deduplicated(self) -> None:
        duplicate = security(4625, "2026-01-01T10:00:00Z")
        duplicate["channel"] = "Security"
        duplicate["record_id"] = "501"
        records = [duplicate, dict(duplicate), dict(duplicate), security(4624, "2026-01-01T10:00:10Z")]
        records[-1]["channel"] = "Security"
        records[-1]["record_id"] = "502"
        self.assertFalse(correlate(normalized(*records)))

    def test_same_source_identity_and_equivalent_normalized_content_deduplicates(self) -> None:
        first = security(4625, "2026-01-01T10:00:00Z", computer="LAB-A", user="analyst")
        first.update({"channel": "Security", "record_id": "701"})
        first["event_data"]["LogonType"] = 2
        equivalent = {"SOURCE": "microsoft-windows-security-auditing", "EVENT_ID": "04625",
            "TIMESTAMP": "2026-01-01T12:00:00+02:00", "COMPUTER": "lab-a",
            "CHANNEL": "security", "RECORD_ID": "00701",
            "EVENT_DATA": {"targetusername": "ANALYST", "IpAddress": "203.0.113.10", "logonType": "02"}}
        prepared, _, issues, _ = _prepare(analyze_records([first, equivalent]))
        self.assertEqual(len(prepared), 1)
        self.assertFalse(any("identity collision" in issue for issue in issues))
        self.assertEqual(prepared[0].provenance_status, "ambiguous-equivalent")
        self.assertIsNone(prepared[0].original_record)
        self.assertEqual(len(prepared[0].original_candidates), 2)

    def test_same_identity_different_logon_type_preserves_records_and_reports_collision(self) -> None:
        first = security(4625, "2026-01-01T10:00:00Z")
        second = security(4625, "2026-01-01T10:00:00Z")
        for record, logon_type in ((first, 2), (second, 10)):
            record.update({"channel": "Security", "record_id": "721"})
            record["event_data"]["LogonType"] = logon_type
        third = security(4625, "2026-01-01T10:00:01Z")
        third.update({"channel": "Security", "record_id": "722"})
        success = security(4624, "2026-01-01T10:00:02Z")
        success.update({"channel": "Security", "record_id": "723"})
        report = correlate(analyze_records([first, second, third, success]))
        self.assertEqual(len(report), 1)
        failures = [item for item in report[0].related_events if item["event"]["event_id"] == 4625]
        self.assertEqual(len(failures), 3)
        self.assertTrue(any("Source identity collision" in issue for issue in report.diagnostics))
        ambiguous = [item for item in failures if item["provenance_status"] == "ambiguous"]
        self.assertEqual(len(ambiguous), 2)
        self.assertTrue(all(item["original_record"] is None for item in ambiguous))
        self.assertEqual(len(ambiguous[0]["original_record_candidates"]), 2)

    def test_same_identity_different_process_guid_preserves_both(self) -> None:
        records = [sysmon(1, "2026-01-01T10:00:00Z", Image=r"C:\Windows\tool.exe", ProcessId="15", ProcessGuid="{A}"),
                   sysmon(1, "2026-01-01T10:00:00Z", Image=r"C:\Windows\tool.exe", ProcessId="15", ProcessGuid="{B}")]
        for record in records:
            record.update({"channel": "Microsoft-Windows-Sysmon/Operational", "record_id": "731"})
        prepared, _, diagnostics, _ = _prepare(analyze_records(records))
        self.assertEqual(len(prepared), 2)
        self.assertTrue(any("Source identity collision" in issue for issue in diagnostics))

    def test_same_identity_different_unknown_raw_field_preserves_both(self) -> None:
        first = security(4625, "2026-01-01T10:00:00Z")
        second = security(4625, "2026-01-01T10:00:00Z")
        for record, value in ((first, "alpha"), (second, "beta")):
            record.update({"channel": "Security", "record_id": "741"})
            record["event_data"]["CustomSecurityField"] = value
        prepared, _, diagnostics, _ = _prepare(analyze_records([first, second]))
        self.assertEqual(len(prepared), 2)
        self.assertTrue(any("Source identity collision" in issue for issue in diagnostics))

    def test_conflicting_xml_scalar_wrapper_values_are_not_deduplicated(self) -> None:
        wrapped = security(4625, "2026-01-01T10:00:00Z")
        scalar = security(4625, "2026-01-01T10:00:00Z")
        for record in (wrapped, scalar):
            record.update({"channel": "Security", "record_id": "742"})
        wrapped["event_data"]["LogonType"] = {"#text": "3", "text": "10"}
        scalar["event_data"]["LogonType"] = "10"
        prepared, _, diagnostics, _ = _prepare(analyze_records([wrapped, scalar]))
        self.assertEqual(len(prepared), 2)
        self.assertTrue(any("Source identity collision" in item for item in diagnostics))
        self.assertFalse(any("harmless formatting" in item for item in diagnostics))

    def test_unambiguous_xml_scalar_wrappers_match_scalar_values(self) -> None:
        cases = [
            ({"#text": "10"}, "10"),
            ({"#text": "10", "text": "10"}, "10"),
        ]
        for wrapper, scalar_value in cases:
            with self.subTest(wrapper=wrapper):
                first = security(4625, "2026-01-01T10:00:00Z")
                second = security(4625, "2026-01-01T10:00:00Z")
                for record in (first, second):
                    record.update({"channel": "Security", "record_id": "743"})
                first["event_data"]["LogonType"] = wrapper
                second["event_data"]["LogonType"] = scalar_value
                prepared, _, diagnostics, _ = _prepare(analyze_records([first, second]))
                self.assertEqual(len(prepared), 1)
                self.assertFalse(any("Source identity collision" in item for item in diagnostics))

    def test_xml_wrapper_unknown_fields_are_retained_and_nested_conflicts_detected(self) -> None:
        pairs = [
            ({"#text": "10", "custom": "keep"}, "10"),
            ({"outer": {"ProcessGuid": {"#text": "{A}", "text": "{B}"}}},
             {"outer": {"ProcessGuid": "{B}"}}),
        ]
        for left_value, right_value in pairs:
            with self.subTest(left=left_value):
                first = security(4625, "2026-01-01T10:00:00Z")
                second = security(4625, "2026-01-01T10:00:00Z")
                for record in (first, second):
                    record.update({"channel": "Security", "record_id": "744"})
                first["event_data"]["CustomSecurityField"] = left_value
                second["event_data"]["CustomSecurityField"] = right_value
                prepared, _, diagnostics, _ = _prepare(analyze_records([first, second]))
                self.assertEqual(len(prepared), 2)
                self.assertTrue(any("Source identity collision" in item for item in diagnostics))

    def test_raw_container_types_order_and_unknown_values_are_preserved(self) -> None:
        pairs = [
            ([1, 2], (1, 2)),
            ({"nested": [1, (2,)]}, {"nested": [1, [2]]}),
            ([1, 2], [2, 1]),
            ({"custom": None}, {}),
            ({"custom": 1}, {"custom": "1"}),
        ]
        for first_value, second_value in pairs:
            with self.subTest(first=first_value, second=second_value):
                first = security(4625, "2026-01-01T10:00:00Z")
                second = security(4625, "2026-01-01T10:00:00Z")
                for record in (first, second):
                    record.update({"channel": "Security", "record_id": "745"})
                first["custom"] = first_value
                second["custom"] = second_value
                prepared, _, diagnostics, _ = _prepare(analyze_records([first, second]))
                self.assertEqual(len(prepared), 2)
                self.assertTrue(any("Source identity collision" in item for item in diagnostics))

        same_list = security(4625, "2026-01-01T10:00:00Z")
        same_list.update({"channel": "Security", "record_id": "746", "custom": [1, {"x": None}]})
        duplicate = {**same_list, "custom": [1, {"x": None}]}
        prepared, _, diagnostics, _ = _prepare(analyze_records([same_list, duplicate]))
        self.assertEqual(len(prepared), 1)
        self.assertFalse(any("Source identity collision" in item for item in diagnostics))

    def test_unsupported_custom_values_are_not_stringified_for_deduplication(self) -> None:
        class CustomValue:
            def __init__(self, value: str) -> None:
                self.value = value

            def __str__(self) -> str:
                return "same display value"

        first = security(4625, "2026-01-01T10:00:00Z")
        second = security(4625, "2026-01-01T10:00:00Z")
        for record in (first, second):
            record.update({"channel": "Security", "record_id": "747"})
        first["custom"] = CustomValue("alpha")
        second["custom"] = CustomValue("beta")
        prepared, _, diagnostics, _ = _prepare(analyze_records([first, second]))
        self.assertEqual(len(prepared), 2)
        self.assertTrue(any("Source identity collision" in item for item in diagnostics))
        self.assertNotEqual(_canonical_raw_payload(first), _canonical_raw_payload(second))

    def test_same_source_identity_with_different_timestamp_is_preserved_and_reported(self) -> None:
        first = security(4625, "2026-01-01T10:00:00Z")
        second = security(4625, "2026-01-01T10:00:01Z")
        for record in (first, second):
            record.update({"channel": "Security", "record_id": "702"})
        prepared, _, issues, _ = _prepare(analyze_records([first, second]))
        self.assertEqual(len(prepared), 2)
        self.assertTrue(any("identity collision" in issue and "preserved" in issue for issue in issues))
        self.assertNotEqual(prepared[0].references, prepared[1].references)
        third = security(4625, "2026-01-01T10:00:02Z")
        success = security(4624, "2026-01-01T10:00:03Z")
        third.update({"channel": "Security", "record_id": "703"})
        success.update({"channel": "Security", "record_id": "704"})
        case = correlate(analyze_records([first, second, third, success]))[0]
        self.assertTrue(any("identity collision" in issue for issue in case.source_issues))

    def test_same_source_identity_with_different_username_or_ip_is_preserved(self) -> None:
        cases = [
            (security(4625, "2026-01-01T10:00:00Z", user="analyst"),
             security(4625, "2026-01-01T10:00:00Z", user="other")),
            (security(4625, "2026-01-01T10:00:00Z", ip="203.0.113.10"),
             security(4625, "2026-01-01T10:00:00Z", ip="203.0.113.11")),
        ]
        for first, second in cases:
            with self.subTest(first=first, second=second):
                for record in (first, second):
                    record.update({"channel": "Security", "record_id": "703"})
                prepared, _, issues, _ = _prepare(analyze_records([first, second]))
                self.assertEqual(len(prepared), 2)
                self.assertTrue(any("identity collision" in issue for issue in issues))

    def test_same_source_identity_with_different_event_ids_is_preserved(self) -> None:
        first = security(4625, "2026-01-01T10:00:00Z")
        second = security(4624, "2026-01-01T10:00:00Z")
        for record in (first, second):
            record.update({"channel": "Security", "record_id": "704"})
        prepared, _, issues, _ = _prepare(analyze_records([first, second]))
        self.assertEqual(len(prepared), 2)
        self.assertTrue(any("identity collision" in issue for issue in issues))

    def test_different_record_ids_preserve_equivalent_events(self) -> None:
        first = security(4625, "2026-01-01T10:00:00Z")
        second = dict(first)
        first.update({"channel": "Security", "record_id": "705"})
        second.update({"channel": "Security", "record_id": "706"})
        prepared, _, issues, _ = _prepare(analyze_records([first, second]))
        self.assertEqual(len(prepared), 2)
        self.assertFalse(any("identity collision" in issue for issue in issues))

    def test_source_identity_extraction_accepts_case_variants_and_event_shapes(self) -> None:
        first = {
            "WIN": {"SYSTEM": {"PROVIDER": {"NAME": "Microsoft-Windows-Security-Auditing"},
                "EventID": 4625, "TimeCreated": {"SystemTime": "2026-01-01T10:00:00Z"},
                "Computer": "LAB-A", "Channel": "Security", "eventRecordID": "707"},
                "EVENTDATA": {"TargetUserName": "analyst", "IpAddress": "203.0.113.10"}}
        }
        second = {
            "event": {"system": {"provider": {"name": "Microsoft-Windows-Security-Auditing"},
                "eventId": 4625, "timeCreated": {"systemTime": "2026-01-01T10:00:00+00:00"},
                "computer": "lab-a", "channel": "security", "EventRecordID": "00707"},
                "eventData": {"TargetUserName": "ANALYST", "IpAddress": "203.0.113.10"}}
        }
        third = {
            "EVENT": {"SYSTEM": {"PROVIDER": {"NAME": "Microsoft-Windows-Security-Auditing"},
                "eventID": 4625, "TIMECREATED": {"SYSTEMTIME": "2026-01-01T10:00:00Z"},
                "COMPUTER": "LAB-A", "CHANNEL": "Security", "EVENTRECORDID": "707"},
                "EVENTDATA": {"TargetUserName": "analyst", "IpAddress": "203.0.113.10"}}
        }
        report = analyze_records([first, second, third])
        self.assertEqual(len(report.events), 3)
        identities = [_source_identity(raw, event)
                      for raw, event in zip(report.original_records, report.events)]
        self.assertEqual(len(set(identities)), 1)
        prepared, _, _, _ = _prepare(report)
        self.assertEqual(len(prepared), 1)

    def test_distinct_record_ids_preserve_identical_normalized_events(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z") for _ in range(3)]
        for index, record in enumerate(records, start=501):
            record["channel"] = "Security"
            record["record_id"] = str(index)
        records.append(security(4624, "2026-01-01T10:00:10Z"))
        records[-1]["channel"] = "Security"
        records[-1]["record_id"] = "504"
        case = correlate(analyze_records(records))[0]
        failed_related = [related for related in case.related_events if related["event"]["event_id"] == 4625]
        self.assertEqual(len(failed_related), 3)

    def test_missing_record_ids_are_not_deduplicated(self) -> None:
        failures = [security(4625, "2026-01-01T10:00:00Z") for _ in range(3)]
        records = failures + [security(4624, "2026-01-01T10:00:10Z")]
        case = correlate(analyze_records(records))[0]
        failed_related = [related for related in case.related_events if related["event"]["event_id"] == 4625]
        self.assertEqual(len(failed_related), 3)

    def test_missing_or_invalid_ioc_results_do_not_correlate(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        self.assertFalse(correlate(normalized(event)))
        self.assertFalse(correlate(normalized(event), [ioc("updates.example", validation="invalid")]))

    def test_incomplete_and_conflicting_evidence_is_not_overstated(self) -> None:
        event = sysmon(3, "2026-01-01T10:00:00Z", DestinationIp="203.0.113.66")
        case = correlate(normalized(event), [ioc("203.0.113.66", "IPv4", status="unknown")])[0]
        self.assertIn("IOC observation time", case.missing_evidence[0])
        self.assertEqual(case.confidence, "medium")
        self.assertNotIn("malicious", case.detection_pattern.casefold())

    def test_conflicting_ioc_results_are_not_emitted_as_duplicate_case_ids(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        cases = correlate(normalized(event), [ioc("updates.example", status="synthetic_suspicious"),
                                               ioc("updates.example", status="synthetic_unknown")])
        self.assertEqual(len(cases), 1)
        self.assertEqual(len({case.case_id for case in cases}), len(cases))
        self.assertTrue(any("Conflicting IOC results" in item for item in cases[0].evidence))

    def test_ioc_results_with_same_labels_but_different_counts_conflict_and_remain_visible(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        first = ioc("updates.example", status="suspicious", risk="medium", malicious=1, suspicious=2, harmless=90)
        second = ioc("updates.example", status="suspicious", risk="medium", malicious=30, suspicious=2, harmless=90)
        case = correlate(normalized(event), [first, second])[0]
        self.assertTrue(any("Conflicting IOC results" in line for line in case.evidence))
        rendered = "\n".join(case.evidence)
        self.assertIn('"malicious":1', rendered)
        self.assertIn('"malicious":30', rendered)
        self.assertIn('"harmless":90', rendered)

    def test_ioc_recommendation_and_source_differences_are_preserved_as_conflicts(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        recommendations = [
            ioc("updates.example", status="same", risk="same", source="Source A", recommendation="Review locally"),
            ioc("updates.example", status="same", risk="same", source="Source A", recommendation="Escalate for review"),
        ]
        sources = [
            ioc("updates.example", status="same", risk="same", source="Source A", recommendation="Same"),
            ioc("updates.example", status="same", risk="same", source="Source B", recommendation="Same"),
        ]
        for supplied, expected_fields in ((recommendations, ("Review locally", "Escalate for review")),
                                          (sources, ("Source A", "Source B"))):
            with self.subTest(expected_fields=expected_fields):
                case = correlate(normalized(event), supplied)[0]
                rendered = "\n".join(case.evidence)
                self.assertTrue(any("Conflicting IOC results" in line for line in case.evidence))
                for value in expected_fields:
                    self.assertIn(value, rendered)

    def test_identical_duplicate_ioc_results_are_each_preserved_without_conflict(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        supplied = ioc("updates.example", malicious=3, harmless=8)
        case = correlate(normalized(event), [supplied, supplied])[0]
        result_evidence = [line for line in case.evidence if line.startswith("Supplied IOC result")]
        self.assertEqual(len(result_evidence), 2)
        self.assertEqual(result_evidence[0], result_evidence[1])
        self.assertFalse(any("Conflicting IOC results" in line for line in case.evidence))

    def test_multiple_indicators_and_events_produce_one_case_per_indicator_event(self) -> None:
        records = [sysmon(22, "2026-01-01T10:00:00Z", QueryName="one.example"),
                   sysmon(22, "2026-01-01T10:01:00Z", QueryName="two.example")]
        supplied = [ioc("one.example", source="Source A", status="one"),
                    ioc("one.example", source="Source B", status="two"),
                    ioc("two.example", status="unknown")]
        cases = correlate(normalized(*records), supplied)
        self.assertEqual(len(cases), 2)
        self.assertEqual(len({case.case_id for case in cases}), 2)
        self.assertEqual(sum(any("Conflicting IOC results" in line for line in case.evidence) for case in cases), 1)

    def test_partial_ioc_mapping_does_not_gain_invented_fields(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        result = {"indicator": "updates.example", "validation_status": "valid", "source": "Synthetic"}
        case = correlate(normalized(event), [result])[0]
        result_line = next(line for line in case.evidence if line.startswith("Supplied IOC result"))
        self.assertIn('"source":"Synthetic"', result_line)
        self.assertNotIn("reputation_status", result_line)

    def test_ioc_status_and_risk_casing_differences_are_not_conflicts(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        variants = [
            [ioc("updates.example", status="suspicious", risk="medium"),
             ioc("updates.example", status="SUSPICIOUS", risk="medium")],
            [ioc("updates.example", status="suspicious", risk="medium"),
             ioc("updates.example", status="suspicious", risk="MEDIUM")],
        ]
        for supplied in variants:
            with self.subTest(supplied=supplied):
                case = correlate(normalized(event), supplied)[0]
                self.assertFalse(any("Conflicting IOC results" in item for item in case.evidence))
                results = [item for item in case.evidence if item.startswith("Supplied IOC result")]
                parsed = [json.loads(item.split(": ", 1)[1]) for item in results]
                self.assertEqual([item["reputation_status"] for item in parsed],
                                 [result.reputation_status for result in supplied])
                self.assertEqual([item["risk_classification"] for item in parsed],
                                 [result.risk_classification for result in supplied])

    def test_nested_mapping_and_list_ioc_evidence_is_preserved_recursively(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        result = {"indicator": "updates.example", "validation_status": "valid", "source": "Synthetic",
                  "details": {"counts": {"malicious": 2, "harmless": 9},
                              "notes": ["offline", {"recommendation": "review source"}]}}
        case = correlate(normalized(event), [result])[0]
        line = next(item for item in case.evidence if item.startswith("Supplied IOC result"))
        rendered = json.loads(line.split(": ", 1)[1])
        self.assertEqual(rendered["details"]["counts"], {"malicious": 2, "harmless": 9})
        self.assertEqual(rendered["details"]["notes"][1]["recommendation"], "review source")

    def test_dataclass_and_ordinary_object_ioc_results_keep_nested_attributes(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        dataclass_result = DataclassIOCResult("updates.example", "valid", "unknown", "unknown",
            "Dataclass fixture", "review", IOCDetail(5, "dataclass note"))
        ordinary_result = SimpleNamespace(indicator="updates.example", validation_status="valid",
            reputation_status="unknown", risk_classification="unknown", source="Object fixture",
            investigation_recommendation="review", detail=OrdinaryIOCDetail())
        cases = correlate(normalized(event), [dataclass_result, ordinary_result])
        self.assertEqual(len(cases), 1)
        evidence_lines = [item for item in cases[0].evidence if item.startswith("Supplied IOC result")]
        dataclass_json = json.loads(evidence_lines[0].split(": ", 1)[1])
        object_json = json.loads(evidence_lines[1].split(": ", 1)[1])
        self.assertEqual(dataclass_json["detail"]["$fields"]["count"], 5)
        self.assertEqual(dataclass_json["detail"]["$fields"]["note"], "dataclass note")
        self.assertEqual(object_json["detail"]["$attributes"]["counts"]["malicious"], 4)
        self.assertEqual(object_json["detail"]["$attributes"]["notes"], ["synthetic", "nested"])

    def test_unsupported_and_circular_ioc_values_are_explicit_and_do_not_crash(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        unsupported = {"indicator": "updates.example", "validation_status": "valid", "extra": UnsupportedIOCValue()}
        circular: dict[str, object] = {"label": "synthetic"}
        circular["self"] = circular
        cyclic_result = {"indicator": "updates.example", "validation_status": "valid", "extra": circular}
        case = correlate(normalized(event), [unsupported, cyclic_result])[0]
        rendered = "\n".join(case.evidence)
        self.assertIn("unsupported value type", rendered)
        self.assertIn("circular reference", rendered)
        self.assertNotIn("must-not-be-used-as-evidence", rendered)

    def test_cases_preserve_source_references_and_raw_records(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                   security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        report = normalized(*records)
        case = correlate(report)[0]
        self.assertEqual(case.source_records, records)
        self.assertTrue(all(item["source_references"] for item in case.related_events))

    def test_case_id_is_stable_for_identical_ordered_input(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                   security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        first = correlate(normalized(*records))[0].case_id
        second = correlate(normalized(*records))[0].case_id
        self.assertEqual(first, second)

    def test_raw_source_references_account_for_unsupported_records(self) -> None:
        records = [{"source": "unsupported", "event_id": 777}] + [
            security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
            security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        case = correlate(analyze_records(records))[0]
        originals = [item["original_record"] for item in case.related_events]
        self.assertTrue(all(original["event_id"] in (4624, 4625) for original in originals))

    def test_multiple_supported_records_keep_correct_original_associations(self) -> None:
        records = [security(9999, "2026-01-01T09:59:00Z"), None, security(4625, "2026-01-01T10:00:00Z"),
                   {"source": "unknown", "event_id": 99}, security(4625, "2026-01-01T10:00:10Z"),
                   security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        case = correlate(analyze_records(records))[0]
        originals = [item["original_record"] for item in case.related_events]
        self.assertEqual(len(originals), 4)
        self.assertTrue(all(original in records for original in originals))
        self.assertEqual(sum(issue.startswith("Analyzer input issue:") for issue in case.source_issues), 3)
        self.assertTrue(any("Reliable source identity unavailable" in issue for issue in case.source_issues))

    def test_out_of_order_batch_with_unsupported_rows_preserves_exact_original_mapping(self) -> None:
        records = [{"source": "unsupported", "event_id": 777},
                   security(4624, "2026-01-01T10:00:30Z", user="analyst"),
                   {"source": "unsupported", "event_id": 999},
                   security(4625, "2026-01-01T10:00:20Z", user="analyst"),
                   None,
                   security(4625, "2026-01-01T10:00:00Z", user="analyst"),
                   security(4625, "2026-01-01T10:00:10Z", user="analyst"),
                   {"source": "unsupported", "event_id": 888}]
        for index, record in enumerate(records):
            if isinstance(record, dict) and record.get("event_id") in (4624, 4625):
                record["channel"] = "Security"
                record["record_id"] = str(800 + index)
        case = correlate(analyze_records(records))[0]
        self.assertEqual(len(case.source_records), len(records))
        self.assertEqual(len(case.source_issues), 4)
        for item in case.related_events:
            original = item["original_record"]
            event = item["event"]
            self.assertEqual(event["timestamp"], original["timestamp"])
            self.assertEqual(event["event_id"], original["event_id"])
            self.assertEqual(event["username"], original["event_data"]["TargetUserName"])

    def test_reordered_normalized_events_keep_unique_original_associations(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                   security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        for index, row in enumerate(records, start=900):
            row.update({"channel": "Security", "record_id": str(index)})
        report = analyze_records(records)
        report.events.reverse()
        cases = correlate(report)
        self.assertEqual(len(cases), 1)
        for item in cases[0].related_events:
            self.assertEqual(item["provenance_status"], "matched")
            self.assertEqual(item["event"]["timestamp"], item["original_record"]["timestamp"])

    def test_duplicate_fingerprint_with_distinct_originals_reports_ambiguity(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z") for _ in range(3)]
        for index, row in enumerate(records, start=930):
            row.update({"channel": "Security", "record_id": str(index)})
            row["event_data"]["LogonType"] = index - 929
        success = security(4624, "2026-01-01T10:00:01Z")
        success.update({"channel": "Security", "record_id": "934"})
        report = analyze_records(records + [success])
        report.events.reverse()
        cases = correlate(report)
        self.assertEqual(len(cases), 1)
        failed = [item for item in cases[0].related_events if item["event"]["event_id"] == 4625]
        self.assertEqual(len(failed), 3)
        self.assertTrue(all(item["original_record"] is None for item in failed))
        self.assertTrue(all(item["provenance_status"] == "ambiguous" for item in failed))
        self.assertTrue(all(len(item["original_record_candidates"]) == 3 for item in failed))
        self.assertTrue(any("Provenance ambiguity" in item for item in cases.diagnostics))

    def test_duplicate_source_events_are_deduplicated_without_losing_raw_record_set(self) -> None:
        duplicate = security(4625, "2026-01-01T10:00:00Z")
        duplicate.update({"channel": "Security", "record_id": "941"})
        records = [duplicate, dict(duplicate)]
        for index, stamp in enumerate(("2026-01-01T10:00:05Z", "2026-01-01T10:00:10Z", "2026-01-01T10:00:15Z"), start=942):
            row = security(4625, stamp)
            row.update({"channel": "Security", "record_id": str(index)})
            records.append(row)
        success = security(4624, "2026-01-01T10:00:20Z")
        success.update({"channel": "Security", "record_id": "945"})
        records.append(success)
        case = correlate(analyze_records(records))[0]
        failed = [item for item in case.related_events if item["event"]["event_id"] == 4625]
        self.assertEqual(len(failed), 4)
        self.assertEqual(len(case.source_records), 6)

    def test_distinct_original_record_ids_are_not_collapsed_as_duplicates(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z") for _ in range(3)]
        for index, record in enumerate(records):
            record["record_id"] = index + 1
        records.append(security(4624, "2026-01-01T10:00:10Z"))
        case = correlate(analyze_records(records))[0]
        failed_related = [related for related in case.related_events if related["event"]["event_id"] == 4625]
        self.assertEqual(len(failed_related), 3)

    def test_case_id_is_stable_when_source_records_are_reordered(self) -> None:
        records = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                   security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        for index, record in enumerate(records, start=601):
            record["channel"] = "Security"
            record["record_id"] = str(index)
        ordered_id = correlate(analyze_records(records))[0].case_id
        reordered_id = correlate(analyze_records([records[2], records[0], records[3], records[1]]))[0].case_id
        self.assertEqual(ordered_id, reordered_id)

    def test_text_and_json_case_reports(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        cases = correlate(normalized(event), [ioc("updates.example")])
        self.assertEqual(json.loads(format_json(cases))["disclaimer"], DISCLAIMER)
        self.assertIn(cases[0].case_id, format_text(cases))

    def test_formatters_include_report_metadata_without_repeating_case_issues(self) -> None:
        rows = [security(4625, "2026-01-01T10:00:00Z"),
                security(4625, "2026-01-01T10:00:10Z"),
                security(4625, "2026-01-01T10:00:20Z"),
                security(4624, "2026-01-01T10:00:30Z")]
        rows.insert(0, {"source": "unsupported", "event_id": 777})
        report = correlate(analyze_records(rows))
        parsed = json.loads(format_json(report))
        self.assertEqual(len(parsed["cases"]), 1)
        self.assertTrue(parsed["diagnostics"])
        self.assertEqual(parsed["skipped_events"], [])
        self.assertIn("source_issues", parsed["cases"][0])
        self.assertEqual(parsed["cases"][0]["source_issues"], parsed["diagnostics"])
        self.assertIn("Diagnostics (", format_text(report))
        self.assertNotIn("source_issues", format_text(report))

    def test_formatters_render_empty_reports_with_diagnostics_and_skips(self) -> None:
        collision_a = security(4625, "2026-01-01T10:00:00Z")
        collision_b = security(4625, "2026-01-01T10:00:01Z")
        for record in (collision_a, collision_b):
            record.update({"channel": "Security", "record_id": "750"})
        report = correlate(analyze_records([collision_a, collision_b]))
        parsed = json.loads(format_json(report))
        self.assertEqual(parsed["cases"], [])
        self.assertTrue(any("Source identity collision" in item for item in parsed["diagnostics"]))
        self.assertIn("Diagnostics (1):", format_text(report))

        skipped = correlate(analyze_records([security(4625, "")]))
        skipped_json = json.loads(format_json(skipped))
        self.assertEqual(skipped_json["cases"], [])
        self.assertEqual(len(skipped_json["skipped_events"]), 1)
        self.assertIn("Skipped events (1):", format_text(skipped))
        self.assertIn("timestamp", format_text(skipped).casefold())

    def test_ordinary_list_formatting_keeps_legacy_shape(self) -> None:
        report = correlate(normalized(sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")),
                           [ioc("updates.example")])
        ordinary_list = list(report)
        parsed = json.loads(format_json(ordinary_list))
        self.assertEqual(set(parsed), {"disclaimer", "cases"})
        self.assertIn("source_issues", parsed["cases"][0])
        self.assertNotIn("Diagnostics (", format_text(ordinary_list))

    def test_json_serializes_custom_and_dataclass_source_evidence_without_mutation(self) -> None:
        rows = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        nested = RawSourceObject({"numbers": [1, None, "two"]})
        record = RawSourceDataclass("synthetic dataclass", nested)
        rows[0]["custom_dataclass"] = record
        rows[0]["custom_object"] = RawSourceObject({"inner": RawSourceObject("value")})
        before = copy.deepcopy({"nested": nested.value, "label": record.label})

        document = json.loads(format_json(correlate(analyze_records(rows))))
        serialized = document["cases"][0]["source_records"][0]
        self.assertEqual(serialized["custom_dataclass"]["$type"].endswith("RawSourceDataclass"), True)
        self.assertEqual(serialized["custom_dataclass"]["$fields"]["label"], "synthetic dataclass")
        self.assertEqual(serialized["custom_dataclass"]["$fields"]["nested"]["$attributes"]["value"]["numbers"],
                         [1, None, "two"])
        self.assertEqual(serialized["custom_object"]["$attributes"]["value"]["inner"]["$attributes"]["value"],
                         "value")
        self.assertEqual({"nested": nested.value, "label": record.label}, before)

    def test_json_serializes_circular_dictionary_list_and_custom_object(self) -> None:
        circular_dict: dict[str, object] = {}
        circular_dict["self"] = circular_dict
        circular_list: list[object] = []
        circular_list.append(circular_list)
        circular_object = RawSourceObject(None)
        circular_object.value = circular_object
        original_links = (circular_dict["self"] is circular_dict,
                          circular_list[0] is circular_list,
                          circular_object.value is circular_object)

        for custom_value in (circular_dict, circular_list, circular_object):
            with self.subTest(value_type=type(custom_value).__name__):
                rows = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                        security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
                rows[0]["cyclic_evidence"] = custom_value
                document = json.loads(format_json(correlate(analyze_records(rows))))
                source_record = document["cases"][0]["source_records"][0]
                value = source_record["cyclic_evidence"]

                def has_cycle_marker(item: object) -> bool:
                    if isinstance(item, dict):
                        return (item.get("$serialization_marker") == "circular_reference"
                                or any(has_cycle_marker(child) for child in item.values()))
                    if isinstance(item, list):
                        return any(has_cycle_marker(child) for child in item)
                    return False

                self.assertTrue(has_cycle_marker(value))
        self.assertEqual(original_links, (True, True, True))

    def test_json_marks_unsupported_source_values_and_preserves_shared_references(self) -> None:
        shared = RawSourceObject({"value": "shared synthetic object"})
        rows = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:10Z"),
                security(4625, "2026-01-01T10:00:20Z"), security(4624, "2026-01-01T10:00:30Z")]
        rows[0]["unsupported"] = UnsupportedRawValue()
        rows[0]["shared_a"] = shared
        rows[0]["shared_b"] = shared
        rows[1]["ordinary_json"] = {"nested": [1, 2.5, True, None, "text"]}
        before = copy.deepcopy(shared.value)

        document = json.loads(format_json(correlate(analyze_records(rows))))
        first, second = document["cases"][0]["source_records"][:2]
        self.assertEqual(first["unsupported"]["$serialization_marker"], "unsupported_value")
        self.assertTrue(first["unsupported"]["$type"].endswith("UnsupportedRawValue"))
        self.assertEqual(first["shared_a"], first["shared_b"])
        self.assertNotIn("circular_reference", json.dumps(first["shared_a"]))
        self.assertEqual(second["ordinary_json"], {"nested": [1, 2.5, True, None, "text"]})
        self.assertEqual(shared.value, before)

    def test_report_snapshot_is_stable_after_case_and_list_mutations(self) -> None:
        initial_case = InvestigationCase(
            "SOC-INITIAL", "synthetic", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00",
            [], [], [], [], [], [], [], "low", "synthetic", source_issues=["captured at creation"])
        report = CorrelationReport([initial_case], diagnostics=["run diagnostic"],
                                   skipped_events=[{"event_index": 4, "reason": "missing timestamp"}])
        snapshot_diagnostics = report.diagnostics
        snapshot_skips = report.skipped_events
        self.assertEqual(snapshot_diagnostics, ["run diagnostic", "captured at creation"])

        initial_case.source_issues.append("changed after creation")
        mutated_diagnostics = report.diagnostics
        mutated_diagnostics.append("returned-copy edit")
        mutated_skips = report.skipped_events
        mutated_skips[0]["reason"] = "returned-copy edit"
        self.assertEqual(report.diagnostics, snapshot_diagnostics)
        self.assertEqual(report.skipped_events, snapshot_skips)
        changed_text = format_text(report)
        self.assertNotIn("- changed after creation", changed_text.split("Cases:", 1)[-1].split("Skipped events", 1)[0])
        self.assertIn("Case source issue: changed after creation", changed_text)

        added_case = InvestigationCase(
            "SOC-ADDED", "synthetic", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00",
            [], [], [], [], [], [], [], "low", "synthetic", source_issues=["added after creation"])
        report.append(added_case)
        added_json = json.loads(format_json(report))
        self.assertEqual(added_json["diagnostics"], snapshot_diagnostics)
        self.assertIn("changed after creation", added_json["cases"][0]["source_issues"])
        self.assertIn("added after creation", added_json["cases"][1]["source_issues"])
        added_text = format_text(report)
        self.assertIn("Case source issue: changed after creation", added_text)
        self.assertIn("Case source issue: added after creation", added_text)
        self.assertNotIn("- changed after creation", added_text.split("Skipped events", 1)[0])

        report.pop(0)
        removed_json = json.loads(format_json(report))
        self.assertEqual(len(removed_json["cases"]), 1)
        self.assertEqual(removed_json["diagnostics"], snapshot_diagnostics)
        self.assertEqual(removed_json["skipped_events"], snapshot_skips)
        removed_text = format_text(report)
        self.assertIn("Diagnostics (2):", removed_text)
        self.assertNotIn("SOC-INITIAL", removed_text)
        report.clear()
        empty_json = json.loads(format_json(report))
        self.assertEqual(empty_json["cases"], [])
        self.assertEqual(empty_json["diagnostics"], snapshot_diagnostics)
        self.assertEqual(empty_json["skipped_events"], snapshot_skips)
        empty_text = format_text(report)
        self.assertIn("Cases: 0", empty_text)
        self.assertIn("captured at creation", empty_text)
        self.assertIn("missing timestamp", empty_text)

    def test_deep_raw_source_evidence_is_valid_json_with_explicit_limit_markers(self) -> None:
        def wrapped_case(raw: object) -> InvestigationCase:
            return InvestigationCase(
                "SOC-DEPTH", "synthetic depth probe", "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00", [], [], [], [], [], [], [], "low",
                "Synthetic serialization test only.", source_records=[raw])

        def find_markers(value: object) -> list[dict[str, object]]:
            found: list[dict[str, object]] = []
            pending = [value]
            while pending:
                current = pending.pop()
                if isinstance(current, dict):
                    if "$serialization_marker" in current:
                        found.append(current)
                    pending.extend(current.values())
                elif isinstance(current, list):
                    pending.extend(current)
            return found

        nested_list: object = "leaf"
        nested_mapping: object = "leaf"
        mixed: object = "leaf"
        for index in range(1200):
            nested_list = [nested_list]
            nested_mapping = {"level": nested_mapping}
            mixed = [mixed] if index % 2 == 0 else {"level": mixed}

        shared = {"synthetic": [1, 2, 3]}
        deep_chain: object = "leaf"
        for _ in range(1200):
            deep_chain = [deep_chain]
        circular_deep: list[object] = [deep_chain]
        circular_deep.append(circular_deep)
        record = {"left": shared, "right": shared, "deep": circular_deep}

        for name, raw in (("1200 lists", nested_list), ("1200 mappings", nested_mapping),
                          ("mixed nesting", mixed)):
            with self.subTest(shape=name):
                text = format_json([wrapped_case(raw)])
                document = json.loads(text)
                self.assertIn("maximum_depth_exceeded", text)
                self.assertIn('"$max_depth": 128', text)
                markers = find_markers(document["cases"][0]["source_records"][0])
                self.assertTrue(any(item["$serialization_marker"] == "maximum_depth_exceeded"
                                    for item in markers))

        text = format_json([wrapped_case(record)])
        document = json.loads(text)
        serialized = document["cases"][0]["source_records"][0]
        self.assertEqual(serialized["left"], serialized["right"])
        self.assertNotIn("circular_reference", json.dumps(serialized["left"]))
        self.assertIn("maximum_depth_exceeded", text)
        self.assertIn("circular_reference", text)
        self.assertIs(record["left"], shared)
        self.assertIs(record["right"], shared)
        self.assertIs(circular_deep[1], circular_deep)

    def test_raw_source_attribute_errors_are_marked_without_losing_siblings(self) -> None:
        def wrapped_case(raw: object) -> InvestigationCase:
            return InvestigationCase(
                "SOC-SLOTS", "synthetic slot probe", "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00", [], [], [], [], [], [], [], "low",
                "Synthetic serialization test only.", source_records=[raw])

        raw = RawSlotAttributeFailure()
        original_visible = object.__getattribute__(raw, "visible")
        original_base = object.__getattribute__(raw, "base_value")
        document = json.loads(format_json([wrapped_case(raw)]))
        source = document["cases"][0]["source_records"][0]
        self.assertEqual(source["$attributes"]["visible"], original_visible)
        self.assertEqual(source["$attributes"]["base_value"], original_base)
        self.assertEqual(source["$attribute_errors"]["missing_by_attribute_error"]["$serialization_marker"],
                         "attribute_unavailable")
        self.assertEqual(source["$attribute_errors"]["missing_by_attribute_error"]["$field"],
                         "missing_by_attribute_error")
        self.assertEqual(source["$attribute_errors"]["missing_by_attribute_error"]["$error_type"],
                         "builtins.AttributeError")
        self.assertEqual(source["$attribute_errors"]["missing_by_value_error"]["$error_type"],
                         "builtins.ValueError")
        self.assertTrue(source["$attribute_errors"]["missing_by_attribute_error"]["$type"].endswith(
            "RawSlotAttributeFailure"))
        self.assertIs(object.__getattribute__(raw, "visible"), original_visible)

        declared = json.loads(format_json([wrapped_case(RawDeclaredSlot())]))
        declared_source = declared["cases"][0]["source_records"][0]
        self.assertEqual(declared_source["$attributes"]["declared"], "declared synthetic value")
        self.assertNotIn("attribute_unavailable", json.dumps(declared_source))
        self.assertNotIn("missing", json.dumps(declared_source))

        dataclass_source = json.loads(format_json([wrapped_case(RawDataclassAttributeError())]))
        dataclass_value = dataclass_source["cases"][0]["source_records"][0]
        self.assertEqual(dataclass_value["$fields"]["visible"], "accessible dataclass value")
        self.assertEqual(dataclass_value["$fields"]["hidden"]["$serialization_marker"],
                         "attribute_unavailable")
        self.assertEqual(dataclass_value["$fields"]["hidden"]["$error_type"], "builtins.AttributeError")

        nested = RawSourceObject(RawSingleAttributeError())
        nested_json = json.loads(format_json([wrapped_case({"nested": nested})]))
        nested_value = nested_json["cases"][0]["source_records"][0]["nested"]["$attributes"]["value"]
        self.assertEqual(nested_value["$attributes"]["visible"], "accessible sibling")
        self.assertEqual(nested_value["$attribute_errors"]["hidden"]["$serialization_marker"],
                         "attribute_unavailable")

        computed = RawComputedProperty()
        computed_json = json.loads(format_json([wrapped_case(computed)]))
        computed_value = computed_json["cases"][0]["source_records"][0]
        self.assertEqual(computed_value["$attributes"]["visible"], "ordinary instance value")
        self.assertEqual(computed.property_calls, 0)

    def test_slot_markers_preserve_exact_exception_types(self) -> None:
        def wrapped_case(raw: object) -> InvestigationCase:
            return InvestigationCase(
                "SOC-ERROR-TYPE", "synthetic exception probe", "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00", [], [], [], [], [], [], [], "low",
                "Synthetic serialization test only.", source_records=[raw])

        cases = (
            (RawSingleAttributeError(), AttributeError),
            (RawSpecialAttributeSlot(), SpecialAttributeError),
            (RawSpecialRuntimeSlot(), SpecialRuntimeError),
        )
        for raw, exception_type in cases:
            with self.subTest(exception_type=exception_type.__name__):
                source = json.loads(format_json([wrapped_case(raw)]))["cases"][0]["source_records"][0]
                marker = source["$attribute_errors"]["hidden"]
                self.assertEqual(marker["$serialization_marker"], "attribute_unavailable")
                self.assertEqual(marker["$type"], f"{type(raw).__module__}.{type(raw).__qualname__}")
                self.assertEqual(marker["$field"], "hidden")
                self.assertEqual(marker["$error_type"],
                                 f"{exception_type.__module__}.{exception_type.__qualname__}")
                self.assertEqual(source["$attributes"]["visible"], "accessible sibling")
                json.loads(format_json([wrapped_case(raw)]))

    def test_text_reports_disclose_raw_source_serialization_limitations(self) -> None:
        def case(case_id: str, raw: object) -> InvestigationCase:
            return InvestigationCase(case_id, "synthetic", "t", "t", [], [], [], [],
                                     ["synthetic case evidence"], [], [], "low", "not a verdict",
                                     source_records=[raw])

        deep: object = "private synthetic leaf"
        for _ in range(1200):
            deep = {"level": [deep]}
        circular: dict[str, object] = {}
        circular["self"] = circular
        mixed = {"deep": deep, "slot": RawSingleAttributeError(),
                 "cycle": circular, "unsupported": {"synthetic-set-value"}}
        cases = [case("SOC-LIMIT-MULTI", mixed), case("SOC-LIMIT-UNSUPPORTED", {1, 2})]
        text = format_text(CorrelationReport(cases))
        self.assertIn("Original source evidence limitations", text)
        self.assertIn("SOC-LIMIT-MULTI", text)
        self.assertIn("maximum_depth_exceeded", text)
        self.assertIn("attribute_unavailable", text)
        self.assertIn("circular_reference", text)
        self.assertIn("unsupported_value", text)
        self.assertIn("SOC-LIMIT-UNSUPPORTED", text)
        self.assertNotIn("private synthetic leaf", text)
        limitation_lines = [line for line in text.splitlines() if line.startswith("- Case SOC-LIMIT-")]
        self.assertEqual(len(limitation_lines), len(set(limitation_lines)))

        plain = case("SOC-NO-LIMIT", {"synthetic": "ordinary"})
        plain_text = format_text(CorrelationReport([plain]))
        self.assertNotIn("Original source evidence limitations", plain_text)
        ordinary_list_text = format_text([plain])
        self.assertNotIn("Original source evidence limitations", ordinary_list_text)
        self.assertNotIn("Diagnostics (", ordinary_list_text)
        self.assertIn("SOC-NO-LIMIT", ordinary_list_text)
        list_with_limit = format_text([case("SOC-LIST-LIMIT", deep)])
        self.assertIn("SOC-LIST-LIMIT", list_with_limit)
        self.assertIn("maximum_depth_exceeded", list_with_limit)
        self.assertNotIn("Diagnostics (", list_with_limit)

    def test_deep_ioc_evidence_is_preserved_with_explicit_depth_marker(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        nested: object = "synthetic leaf"
        for index in range(1200):
            nested = {"level": [nested]} if index % 2 else [nested]
        shared = {"synthetic": "shared IOC evidence"}
        nested_cycle: list[object] = [nested]
        nested_cycle.append(nested_cycle)
        nested = {"left": shared, "right": shared, "deep_cycle": nested_cycle}
        result = DataclassIOCResult("updates.example", "valid", "unknown", "unknown",
                                    "synthetic source", "synthetic recommendation",
                                    IOCDetail(7, "synthetic detail"))
        # Attach deep evidence without changing the caller's object during correlation.
        result.detail = nested
        original_detail = result.detail
        cases = correlate(normalized(event), [result])
        self.assertEqual(len(cases), 1)
        evidence_text = "\n".join(cases[0].evidence)
        self.assertIn("maximum_depth_exceeded", evidence_text)
        self.assertIn('"$max_depth":128', evidence_text)
        supplied = next(item for item in cases[0].evidence if item.startswith("Supplied IOC result"))
        supplied_payload = json.loads(supplied.split(": ", 1)[1])
        self.assertEqual(supplied_payload["detail"]["left"], supplied_payload["detail"]["right"])
        self.assertNotIn("circular reference", json.dumps(supplied_payload["detail"]["left"]))
        self.assertIn("circular reference", json.dumps(supplied_payload["detail"]["deep_cycle"]))
        self.assertTrue(any("maximum serialization depth" in item for item in cases[0].evidence))
        self.assertIs(result.detail, original_detail)
        self.assertEqual(json.loads(format_json(cases))["cases"][0]["case_id"], cases[0].case_id)

    def test_ioc_attribute_failures_are_marked_without_aborting_case_generation(self) -> None:
        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        slot = IOCWithRaisingSlot({"hidden": "do not mutate"}, ValueError)
        dataclass_result = IOCWithRaisingDataclassField()
        dict_result = IOCWithRaisingDict({"hidden": "untouched"})
        before_slot_detail = object.__getattribute__(slot, "detail")
        before_dict_detail = object.__getattribute__(dict_result, "detail")

        for name, result, expected_field, expected_error in (
            ("raising __dict__", dict_result, "__dict__", "RuntimeError"),
            ("raising slot", slot, "detail", "ValueError"),
            ("raising dataclass field", dataclass_result, "detail", "AttributeError"),
        ):
            with self.subTest(access=name):
                cases = correlate(normalized(event), [result])
                self.assertEqual(len(cases), 1)
                evidence_text = "\n".join(cases[0].evidence)
                self.assertIn("attribute_unavailable", evidence_text)
                self.assertIn(expected_field, evidence_text)
                self.assertIn(expected_error, evidence_text)
                self.assertIn(type(result).__name__, evidence_text)

        slot_cases = correlate(normalized(event), [slot])
        slot_text = "\n".join(slot_cases[0].evidence)
        self.assertIn("retained synthetic detail", slot_text)
        self.assertIs(object.__getattribute__(slot, "detail"), before_slot_detail)
        self.assertIs(object.__getattribute__(dict_result, "detail"), before_dict_detail)

    def test_inaccessible_required_ioc_field_does_not_abort_other_ioc_results(self) -> None:
        class RequiredFieldUnavailable:
            __slots__ = ("indicator", "validation_status")

            def __init__(self) -> None:
                self.indicator = "updates.example"
                self.validation_status = "valid"

            def __getattribute__(self, name: str):
                if name == "validation_status":
                    raise ValueError("synthetic required field unavailable")
                return object.__getattribute__(self, name)

        event = sysmon(22, "2026-01-01T10:00:00Z", QueryName="updates.example")
        report = correlate(normalized(event), [RequiredFieldUnavailable(), ioc("updates.example")])
        self.assertEqual(len(report), 1)
        self.assertTrue(any("validation_status was inaccessible (ValueError)" in item
                            for item in report.diagnostics))
        self.assertTrue(any("No lookup was performed" in item for item in report[0].evidence))

    def test_configurable_windows(self) -> None:
        config = CorrelationConfig(failed_to_success_window=timedelta(seconds=30))
        records = [security(4625, "2026-01-01T10:00:00Z"), security(4625, "2026-01-01T10:00:05Z"),
                   security(4625, "2026-01-01T10:00:10Z"), security(4624, "2026-01-01T10:00:40Z")]
        self.assertFalse(correlate(normalized(*records), config=config))

    def test_out_of_order_event_batch_is_time_sorted_for_correlation(self) -> None:
        records = [security(4624, "2026-01-01T10:00:30Z"),
                   security(4625, "2026-01-01T10:00:20Z"),
                   security(4625, "2026-01-01T10:00:00Z"),
                   security(4625, "2026-01-01T10:00:10Z")]
        case = correlate(normalized(*records))[0]
        related_times = [item["event"]["timestamp"] for item in case.related_events]
        self.assertEqual(related_times, sorted(related_times))


if __name__ == "__main__":
    unittest.main()
