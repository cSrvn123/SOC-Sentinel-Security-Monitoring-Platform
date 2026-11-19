from __future__ import annotations

import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import call, patch

from windows_event_analyzer.analyzer import analyze_records
from windows_event_analyzer.collector import (
    EventLogCollectionError,
    _query_channel,
    _read_stdout_bounded,
    _rendered_xml_records,
    collect_local_events,
)


def _event_xml(
    event_id: int = 4624,
    *,
    provider: str = "Microsoft-Windows-Security-Auditing",
    channel: str = "Security",
    record_id: int = 101,
    timestamp: str = "2026-01-01T10:00:00.000Z",
    event_data: str = '<Data Name="TargetUserName">demo.user</Data><Data Name="IpAddress">192.0.2.12</Data>',
) -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="{timestamp}"/><EventRecordID>{record_id}</EventRecordID>'
        f'<Channel>{channel}</Channel><Computer>SYNTHETIC-HOST</Computer></System>'
        f'<EventData>{event_data}</EventData></Event>'
    )


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        timeout_once: bool = False,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = returncode
        self.timeout_once = timeout_once
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        if self.timeout_once and timeout is not None:
            self.timeout_once = False
            raise subprocess.TimeoutExpired("wevtutil", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class WindowsEventCollectorTests(unittest.TestCase):
    def test_fixed_channels_and_event_ids_are_queried_in_order(self) -> None:
        record = {"Event": {"System": {"EventID": {"#text": "4624"}}}}
        with (
            patch("windows_event_analyzer.collector._wevtutil_path", return_value=Path("wevtutil.exe")),
            patch(
                "windows_event_analyzer.collector._query_channel",
                side_effect=[([record], ()), ([], ())],
            ) as query,
        ):
            batch = collect_local_events(hours_back=2, max_events_per_channel=7)

        self.assertEqual(
            query.call_args_list,
            [
                call(Path("wevtutil.exe"), "Security", (4624, 4625), 2, 7),
                call(Path("wevtutil.exe"), "Microsoft-Windows-Sysmon/Operational", (1, 3, 22), 2, 7),
            ],
        )
        self.assertEqual(batch.records, (record,))
        self.assertEqual(batch.issues, ())

    def test_lookback_and_record_limits_are_validated_before_platform_access(self) -> None:
        invalid_values = (
            {"hours_back": 0}, {"hours_back": 25}, {"hours_back": True},
            {"max_events_per_channel": 0}, {"max_events_per_channel": 101},
            {"max_events_per_channel": False},
        )
        with patch("windows_event_analyzer.collector._wevtutil_path") as get_path:
            for kwargs in invalid_values:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    collect_local_events(**kwargs)
            get_path.assert_not_called()

    def test_safe_arguments_include_fixed_query_and_disable_shell(self) -> None:
        process = _FakeProcess(stdout=b"")
        with patch("windows_event_analyzer.collector.subprocess.Popen", return_value=process) as popen:
            records, issues = _query_channel(
                Path(r"C:\Windows\System32\wevtutil.exe"), "Security", (4624, 4625), 2, 7
            )

        self.assertEqual(records, [])
        self.assertEqual(issues, ())
        args, kwargs = popen.call_args
        self.assertEqual(args[0], [
            r"C:\Windows\System32\wevtutil.exe",
            "qe",
            "Security",
            "/q:*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 7200000]]]",
            "/rd:true",
            "/c:7",
            "/f:RenderedXml",
        ])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertIs(kwargs["stderr"], subprocess.PIPE)
        self.assertIs(kwargs["shell"], False)

    def test_sysmon_query_uses_only_supported_event_ids_and_requested_bounds(self) -> None:
        process = _FakeProcess(stdout=b"")
        with patch("windows_event_analyzer.collector.subprocess.Popen", return_value=process) as popen:
            records, issues = _query_channel(
                Path("wevtutil.exe"), "Microsoft-Windows-Sysmon/Operational", (1, 3, 22), 1, 9
            )
        self.assertEqual(records, [])
        self.assertEqual(issues, ())
        args = popen.call_args.args[0]
        self.assertEqual(
            args[3],
            "/q:*[System[(EventID=1 or EventID=3 or EventID=22) and TimeCreated[timediff(@SystemTime) <= 3600000]]]",
        )
        self.assertIn("/c:9", args)
        self.assertFalse(popen.call_args.kwargs["shell"])

    def test_valid_xml_maps_to_records_accepted_by_analyzer(self) -> None:
        records, issues = _rendered_xml_records(_event_xml().encode("utf-8"), "Security")
        report = analyze_records(records)

        self.assertEqual(issues, ())
        self.assertEqual(len(records), 1)
        self.assertEqual(report.input_record_count, 1)
        self.assertEqual(len(report.events), 1)
        event = report.events[0]
        self.assertEqual(event.event_source, "Windows Security")
        self.assertEqual(event.event_id, 4624)
        self.assertEqual(event.timestamp, "2026-01-01T10:00:00.000Z")
        self.assertEqual(event.computer, "SYNTHETIC-HOST")
        self.assertEqual(event.username, "demo.user")
        self.assertEqual(event.source_ip, "192.0.2.12")
        self.assertIn("_rendered_event_xml", report.original_records[0])

    def test_sysmon_xml_maps_to_analyzer_fields(self) -> None:
        xml = _event_xml(
            3,
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            event_data=(
                '<Data Name="Image">C:\\Windows\\example.exe</Data>'
                '<Data Name="ProcessId">44</Data><Data Name="DestinationIp">203.0.113.7</Data>'
            ),
        )
        records, issues = _rendered_xml_records(xml.encode(), "Microsoft-Windows-Sysmon/Operational")
        report = analyze_records(records)

        self.assertEqual(issues, ())
        self.assertEqual(len(report.events), 1)
        self.assertEqual(report.events[0].event_source, "Sysmon")
        self.assertEqual(report.events[0].destination_ip, "203.0.113.7")
        self.assertEqual(report.events[0].process_id, "44")

    def test_empty_output_returns_no_records_or_issues(self) -> None:
        self.assertEqual(_rendered_xml_records(b" \r\n", "Security"), ([], ()))

    def test_malformed_xml_is_a_safe_collection_error(self) -> None:
        with self.assertRaisesRegex(EventLogCollectionError, "malformed event XML"):
            _rendered_xml_records(b"<Event><System>", "Security")

    def test_event_without_system_returns_diagnostic(self) -> None:
        records, issues = _rendered_xml_records(b"<EventBatch><Event><EventData/></Event></EventBatch>", "Security")
        self.assertEqual(records, [])
        self.assertEqual(issues, ("Security: skipped an Event record without its System element.",))

    def test_mixed_valid_and_malformed_event_preserves_valid_record(self) -> None:
        xml = f"<EventBatch>{_event_xml(record_id=1)}<Event><EventData/></Event>{_event_xml(record_id=2)}</EventBatch>"
        records, issues = _rendered_xml_records(xml.encode(), "Security")
        self.assertEqual(len(records), 2)
        self.assertEqual([item["Event"]["System"]["EventRecordID"] for item in records], ["1", "2"])
        self.assertEqual(len(issues), 1)
        self.assertIn("without its System element", issues[0])
        self.assertNotIn("demo.user", issues[0])

    def test_stdout_is_retained_only_to_limit_and_oversize_is_detected(self) -> None:
        stream = io.BytesIO(b"x" * 100)
        killed: list[bool] = []
        retained, exceeded, error = _read_stdout_bounded(stream, 16, lambda: killed.append(True))
        self.assertEqual(len(retained), 16)
        self.assertTrue(exceeded)
        self.assertIsNone(error)
        self.assertEqual(killed, [True])
        self.assertTrue(stream.closed)

    def test_exact_stdout_limit_is_accepted_without_killing_process(self) -> None:
        stream = io.BytesIO(b"x" * 16)
        killed: list[bool] = []
        retained, exceeded, error = _read_stdout_bounded(stream, 16, lambda: killed.append(True))
        self.assertEqual(len(retained), 16)
        self.assertFalse(exceeded)
        self.assertIsNone(error)
        self.assertEqual(killed, [])

    def test_oversized_subprocess_output_becomes_channel_issue_not_partial_parse(self) -> None:
        process = _FakeProcess(stdout=b"<EventBatch>" + b"x" * 100)
        with (
            patch("windows_event_analyzer.collector._MAX_XML_BYTES_PER_CHANNEL", 16),
            patch("windows_event_analyzer.collector.subprocess.Popen", return_value=process),
        ):
            records, issues = _query_channel(Path("wevtutil.exe"), "Security", (4624, 4625), 1, 3)
        self.assertEqual(records, [])
        self.assertEqual(len(issues), 1)
        self.assertIn("exceeded the 16-byte response limit", issues[0])
        self.assertIn("output was discarded", issues[0])
        self.assertTrue(process.killed)

    def test_timeout_kills_query_and_returns_channel_issue(self) -> None:
        process = _FakeProcess(timeout_once=True)
        with patch("windows_event_analyzer.collector.subprocess.Popen", return_value=process):
            records, issues = _query_channel(Path("wevtutil.exe"), "Security", (4624,), 1, 1)
        self.assertEqual(records, [])
        self.assertIn("timed out", issues[0])
        self.assertTrue(process.killed)

    def test_popen_error_is_reported_without_exposing_exception_text(self) -> None:
        with patch(
            "windows_event_analyzer.collector.subprocess.Popen",
            side_effect=OSError("sensitive local path detail"),
        ):
            records, issues = _query_channel(Path("wevtutil.exe"), "Security", (4624,), 1, 1)
        self.assertEqual(records, [])
        self.assertEqual(issues, ("Security: the Windows event-query utility could not be started.",))

    def test_access_denied_is_clear_and_missing_channel_remains_generic(self) -> None:
        responses = (
            (5, b"Access is denied: private user details"),
            (15007, b"The specified channel could not be found: private path"),
        )
        for exit_code, stderr in responses:
            with self.subTest(exit_code=exit_code):
                process = _FakeProcess(stderr=stderr, returncode=exit_code)
                with patch("windows_event_analyzer.collector.subprocess.Popen", return_value=process):
                    records, issues = _query_channel(Path("wevtutil.exe"), "Security", (4624,), 1, 1)
                self.assertEqual(records, [])
                if exit_code == 5:
                    self.assertEqual(
                        issues,
                        ("Security: access denied; Windows permissions require an elevated launch to read this channel.",),
                    )
                else:
                    self.assertEqual(issues, (f"Security: query failed with Windows utility exit code {exit_code}.",))
                self.assertNotIn("private", issues[0])

    def test_access_denied_security_does_not_hide_success_from_sysmon(self) -> None:
        record = {"Event": {"System": {"EventID": {"#text": "1"}}}}
        with (
            patch("windows_event_analyzer.collector._wevtutil_path", return_value=Path("wevtutil.exe")),
            patch(
                "windows_event_analyzer.collector._query_channel",
                side_effect=[
                    ([], ("Security: access denied; Windows permissions require an elevated launch to read this channel.",)),
                    ([record], ()),
                ],
            ),
        ):
            batch = collect_local_events()
        self.assertEqual(batch.records, (record,))
        self.assertEqual(
            batch.issues,
            ("Security: access denied; Windows permissions require an elevated launch to read this channel.",),
        )
        self.assertEqual(len(batch.channels_queried), 2)
        self.assertEqual(batch.access_denied_channels, ("Security",))

    def test_english_access_denied_message_is_recognized_without_exposing_stderr(self) -> None:
        process = _FakeProcess(stderr=b"Access is denied: private details", returncode=1)
        with patch("windows_event_analyzer.collector.subprocess.Popen", return_value=process):
            _records, issues = _query_channel(Path("wevtutil.exe"), "Sysmon", (1,), 1, 1)
        self.assertIn("access denied", issues[0])
        self.assertIn("elevated launch", issues[0])
        self.assertNotIn("private", issues[0])


if __name__ == "__main__":
    unittest.main()
