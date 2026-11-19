from __future__ import annotations

import json
import unittest
from datetime import timedelta

from windows_event_analyzer.analyzer import EventInputError, analyze_json, analyze_records
from windows_event_analyzer.formatting import DISCLAIMER, format_json, format_text


def security_event(event_id: int, username: str = "synthetic.user", source_ip: str = "203.0.113.25") -> dict[str, object]:
    return {
        "source": "Microsoft-Windows-Security-Auditing",
        "event_id": event_id,
        "timestamp": "2026-01-01T10:00:00Z",
        "computer": "SYNTHETIC-WIN11",
        "event_data": {"TargetUserName": username, "IpAddress": source_ip},
    }


def sysmon_event(event_id: int, data: dict[str, object]) -> dict[str, object]:
    return {
        "source": "Microsoft-Windows-Sysmon/Operational",
        "event_id": event_id,
        "timestamp": "2026-01-01T10:01:00Z",
        "computer": "SYNTHETIC-WIN11",
        "event_data": data,
    }


class WindowsEventAnalyzerTests(unittest.TestCase):
    def test_all_supported_event_types_normalize(self) -> None:
        records = [
            security_event(4624), security_event(4625),
            sysmon_event(1, {"Image": r"C:\Windows\System32\example.exe", "ProcessId": "100", "ParentImage": r"C:\Windows\explorer.exe", "CommandLine": "example --test"}),
            sysmon_event(3, {"Image": r"C:\Windows\System32\example.exe", "ProcessId": "101", "SourceIp": "192.0.2.10", "DestinationIp": "8.8.8.8"}),
            sysmon_event(22, {"Image": r"C:\Windows\System32\example.exe", "QueryName": "host.example"}),
        ]
        report = analyze_records(records)
        self.assertEqual(report.input_record_count, 5)
        self.assertEqual(len(report.events), 5)
        self.assertEqual([event.event_id for event in report.events], [4624, 4625, 1, 3, 22])
        self.assertEqual(report.events[2].process_name, "example.exe")
        self.assertEqual(report.events[2].process_id, "100")
        self.assertEqual(report.events[2].parent_process, r"C:\Windows\explorer.exe")
        self.assertEqual(report.events[4].dns_query, "host.example")

    def test_wazuh_and_event_viewer_shapes(self) -> None:
        wazuh = {
            "win": {
                "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon/Operational", "computer": "SYNTHETIC-WIN11", "systemTime": "2026-01-01T10:02:00Z"},
                "eventdata": {"Image": r"C:\Windows\example.exe", "ProcessId": "0x44", "CommandLine": "example --synthetic"},
            }
        }
        event_viewer = {
            "Event": {
                "System": {
                    "Provider": {"@Name": "Microsoft-Windows-Security-Auditing"},
                    "EventID": {"#text": "4624"},
                    "TimeCreated": {"@SystemTime": "2026-01-01T10:03:00Z"},
                    "Computer": "SYNTHETIC-WIN11",
                },
                "EventData": {"Data": [
                    {"@Name": "TargetUserName", "#text": "synthetic.user"},
                    {"@Name": "IpAddress", "#text": "198.51.100.20"},
                ]},
            }
        }
        report = analyze_records([wazuh, event_viewer])
        self.assertEqual(len(report.events), 2)
        self.assertEqual(report.events[0].process_id, "0x44")
        self.assertEqual(report.events[1].username, "synthetic.user")
        self.assertEqual(report.events[1].source_ip, "198.51.100.20")
        self.assertEqual(report.events[1].timestamp, "2026-01-01T10:03:00Z")

    def test_repeated_failed_logons_require_host_user_and_source_match(self) -> None:
        matching = [security_event(4625) for _ in range(3)]
        report = analyze_records(matching)
        self.assertTrue(all(any("Repeated failed-logon heuristic" in item for item in event.observations) for event in report.events))
        self.assertTrue(all(any("Failed logon observed" in item for item in event.observations) for event in report.events))

        incomplete = [security_event(4625, username="", source_ip="") for _ in range(5)]
        report = analyze_records(incomplete)
        self.assertFalse(any("Repeated failed logons" in item for event in report.events for item in event.observations))

    def test_missing_computer_identity_skips_correlation_and_preserves_events(self) -> None:
        records = [security_event(4625) for _ in range(4)]
        for record in records:
            record.pop("computer")
        report = analyze_records(records)
        self.assertEqual(len(report.events), 4)
        self.assertEqual(report.original_records, records)
        for event in report.events:
            self.assertTrue(any("computer/hostname identity is missing" in item for item in event.observations))
            self.assertFalse(any("Repeated failed-logon heuristic" in item for item in event.observations))

    def test_known_computer_identity_still_correlates(self) -> None:
        records = [security_event(4625) for _ in range(3)]
        report = analyze_records(records)
        self.assertTrue(all(any("Repeated failed-logon heuristic" in item for item in event.observations)
                            for event in report.events))

    def test_failures_within_window_and_threshold_boundary(self) -> None:
        records = [security_event(4625) for _ in range(3)]
        records[0]["timestamp"] = "2026-01-01T10:00:00Z"
        records[1]["timestamp"] = "2026-01-01T10:00:05Z"
        records[2]["timestamp"] = "2026-01-01T10:00:10Z"
        report = analyze_records(records, failed_logon_threshold=3, failed_logon_window=timedelta(seconds=10))
        self.assertTrue(all(any("threshold 3" in item for item in event.observations) for event in report.events))

    def test_failures_spread_outside_window_do_not_correlate(self) -> None:
        records = [security_event(4625) for _ in range(3)]
        for record, timestamp in zip(records, ("10:00:00", "10:00:06", "10:00:12")):
            record["timestamp"] = "2026-01-01T" + timestamp + "Z"
        report = analyze_records(records, 3, timedelta(seconds=10))
        self.assertFalse(any("Repeated failed-logon heuristic" in item for event in report.events for item in event.observations))

    def test_different_accounts_and_source_ips_are_separate_groups(self) -> None:
        records = [security_event(4625), security_event(4625, username="other.user"),
                   security_event(4625, source_ip="203.0.113.26")]
        report = analyze_records(records, 3, timedelta(minutes=5))
        self.assertFalse(any("Repeated failed-logon heuristic" in item for event in report.events for item in event.observations))

    def test_missing_and_invalid_timestamps_never_correlate(self) -> None:
        missing = security_event(4625)
        missing.pop("timestamp")
        invalid = security_event(4625)
        invalid["timestamp"] = "not-a-time"
        naive = security_event(4625)
        naive["timestamp"] = "2026-01-01T10:00:00"
        records = [missing, invalid, naive]
        report = analyze_records(records, 3, timedelta(minutes=1))
        all_observations = [item for event in report.events for item in event.observations]
        self.assertFalse(any("Repeated failed-logon heuristic" in item for item in all_observations))
        self.assertTrue(any("timestamp is missing" in item for item in all_observations))
        self.assertTrue(any("invalid or timezone-naive" in item for item in all_observations))

    def test_mixed_timezone_offsets_compare_as_utc(self) -> None:
        records = [security_event(4625) for _ in range(3)]
        records[0]["timestamp"] = "2026-01-01T10:00:00Z"
        records[1]["timestamp"] = "2026-01-01T15:30:05+05:30"
        records[2]["timestamp"] = "2026-01-01T04:00:10-06:00"
        report = analyze_records(records, 3, timedelta(seconds=10))
        self.assertTrue(all(any("Repeated failed-logon heuristic" in item for item in event.observations)
                            for event in report.events))

    def test_out_of_order_events_are_sorted_for_correlation(self) -> None:
        records = [security_event(4625) for _ in range(3)]
        records[0]["timestamp"] = "2026-01-01T10:00:10Z"
        records[1]["timestamp"] = "2026-01-01T10:00:00Z"
        records[2]["timestamp"] = "2026-01-01T10:00:05Z"
        report = analyze_records(records, 3, timedelta(seconds=10))
        self.assertTrue(all(any("Repeated failed-logon heuristic" in item for item in event.observations)
                            for event in report.events))

    def test_invalid_source_ip_is_not_a_grouping_key(self) -> None:
        records = [security_event(4625, username="", source_ip="not-an-ip") for _ in range(3)]
        report = analyze_records(records, 3, timedelta(minutes=1))
        self.assertFalse(any("Repeated failed-logon heuristic" in item for event in report.events for item in event.observations))

    def test_invalid_configuration_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            analyze_records([], failed_logon_threshold=0)
        with self.assertRaises(ValueError):
            analyze_records([], failed_logon_window=timedelta(0))

    def test_original_records_are_preserved_without_mutation(self) -> None:
        source = [security_event(4625), {"source": "unsupported", "event_id": 99}]
        before = json.loads(json.dumps(source))
        report = analyze_records(source)
        self.assertEqual(source, before)
        self.assertEqual(report.original_records, before)

    def test_process_context_observations_are_heuristic(self) -> None:
        event = sysmon_event(1, {
            "Image": r"C:\Users\synthetic.user\AppData\Local\Temp\pwsh.exe",
            "ParentImage": r"C:\Program Files\Example\WINWORD.EXE",
            "ProcessId": "7",
            "CommandLine": "pwsh.exe -NoProfile",
        })
        report = analyze_records(event)
        observations = report.events[0].observations
        self.assertTrue(any("user-writable" in item for item in observations))
        self.assertTrue(any("Office application launched" in item for item in observations))

    def test_external_network_observation_excludes_reserved_address(self) -> None:
        external = analyze_records(sysmon_event(3, {"DestinationIp": "8.8.8.8"}))
        reserved = analyze_records(sysmon_event(3, {"DestinationIp": "203.0.113.8"}))
        self.assertTrue(any("globally routable" in item for item in external.events[0].observations))
        self.assertFalse(any("globally routable" in item for item in reserved.events[0].observations))

    def test_destination_ip_classification_covers_special_and_global_categories(self) -> None:
        cases = (
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("10.20.30.40", "private"),
            ("fc00::1", "private"),
            ("169.254.10.20", "link-local"),
            ("fe80::1", "link-local"),
            ("224.0.0.252", "IPv4 multicast"),
            ("239.1.2.3", "IPv4 multicast"),
            ("ff02::fb", "IPv6 multicast"),
            ("0.0.0.0", "unspecified"),
            ("::", "unspecified"),
            ("100.64.0.1", "reserved/special-purpose"),
            ("192.0.2.10", "reserved/special-purpose"),
            ("198.18.0.1", "reserved/special-purpose"),
            ("203.0.113.8", "reserved/special-purpose"),
            ("240.0.0.1", "reserved/special-purpose"),
            ("2001:db8::1", "reserved/special-purpose"),
            ("3fff::1", "reserved/special-purpose"),
            ("8.8.8.8", "globally routable unicast"),
            ("2001:4860:4860::8888", "globally routable unicast"),
            ("192.0.0.9", "globally routable unicast"),
            ("2001:1::1", "globally routable unicast"),
            ("2001:3::1", "globally routable unicast"),
        )
        for address, expected_type in cases:
            with self.subTest(address=address):
                report = analyze_records(sysmon_event(3, {"DestinationIp": address}))
                observations = report.events[0].observations
                self.assertTrue(any(expected_type in item for item in observations), observations)
                if "multicast" in expected_type:
                    self.assertTrue(
                        any("does not determine whether the activity is benign or malicious" in item for item in observations)
                    )
                if expected_type != "globally routable unicast":
                    self.assertFalse(any("globally routable unicast" in item for item in observations))

    def test_multicast_classification_does_not_change_event_fields_or_assess_intent(self) -> None:
        record = sysmon_event(
            3,
            {
                "DestinationIp": "224.0.0.252",
                "Image": r"C:\Windows\System32\svchost.exe",
                "ProcessId": "2200",
            },
        )
        event = analyze_records(record).events[0]
        self.assertEqual(event.destination_ip, "224.0.0.252")
        self.assertEqual(event.process_path, r"C:\Windows\System32\svchost.exe")
        self.assertEqual(event.process_id, "2200")
        self.assertTrue(any("IPv4 multicast" in item for item in event.observations))
        self.assertFalse(any("benign" in item and "does not determine" not in item for item in event.observations))
        self.assertFalse(any("malicious" in item and "does not determine" not in item for item in event.observations))

    def test_dns_heuristics_flag_selected_shapes_only(self) -> None:
        unusual = analyze_records(sysmon_event(22, {"QueryName": "one.two.three.four.five.six.example"}))
        ordinary = analyze_records(sysmon_event(22, {"QueryName": "updates.example"}))
        self.assertTrue(any("many subdomain labels" in item for item in unusual.events[0].observations))
        self.assertFalse(ordinary.events[0].observations)

    def test_missing_optional_fields_and_malformed_records_are_safe(self) -> None:
        report = analyze_records({"source": "Sysmon", "event_id": 1})
        self.assertEqual(len(report.events), 1)
        self.assertIsNone(report.events[0].process_path)
        self.assertEqual(report.events[0].observations, [])

        named_only = analyze_records(sysmon_event(1, {"ProcessName": "example.exe"}))
        self.assertEqual(named_only.events[0].process_name, "example.exe")
        self.assertIsNone(named_only.events[0].process_path)

        report = analyze_records([security_event(9999), None, {"event_id": "bad"}])
        self.assertEqual(report.input_record_count, 3)
        self.assertEqual(report.events, [])
        self.assertEqual(len(report.issues), 3)

    def test_malformed_json_and_wrong_top_level_types(self) -> None:
        with self.assertRaises(EventInputError):
            analyze_json("{broken json")
        with self.assertRaises(EventInputError):
            analyze_json("42")
        with self.assertRaises(EventInputError):
            analyze_records(42)

    def test_summary_formats_include_non_verdict_disclaimer(self) -> None:
        report = analyze_records(sysmon_event(22, {"QueryName": "one.two.three.four.five.six.example"}))
        as_json = json.loads(format_json(report))
        self.assertEqual(as_json["supported_event_count"], 1)
        self.assertEqual(as_json["disclaimer"], DISCLAIMER)
        self.assertIn(DISCLAIMER, format_text(report))


if __name__ == "__main__":
    unittest.main()
