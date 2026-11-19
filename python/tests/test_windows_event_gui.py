from __future__ import annotations

import subprocess
import unittest
import copy
from types import SimpleNamespace
from unittest.mock import Mock, patch

from windows_event_analyzer import gui
from windows_event_analyzer.collector import LocalEventBatch


class _FakeText:
    def __init__(self) -> None:
        self.content = ""
        self.configure_calls: list[dict[str, object]] = []

    def configure(self, **kwargs: object) -> None:
        self.configure_calls.append(kwargs)

    def delete(self, _start: str, _end: str) -> None:
        self.content = ""

    def insert(self, _index: str, content: str) -> None:
        self.content = content

    def tag_configure(self, *_args: object, **_kwargs: object) -> None:
        pass

    def tag_add(self, *_args: object) -> None:
        pass


class _FakeEventTree:
    def __init__(self, selected: str = "0") -> None:
        self.selected = selected
        self.inserted: list[dict[str, object]] = []

    def get_children(self) -> tuple[()]:
        return ()

    def insert(self, *args: object, **kwargs: object) -> None:
        self.inserted.append(kwargs)

    def selection(self) -> tuple[str, ...]:
        return (self.selected,) if self.selected else ()


def _event_record(event_id: int, data: dict[str, str], *, record_id: str = "301") -> dict[str, object]:
    source = "Microsoft-Windows-Sysmon" if event_id in {1, 3, 22} else "Microsoft-Windows-Security-Auditing"
    return {
        "Event": {
            "System": {
                "Provider": {"@Name": source},
                "EventID": {"#text": str(event_id)},
                "TimeCreated": {"@SystemTime": "2026-11-18T07:48:44.000Z"},
                "Computer": "SYNTHETIC-HOST",
                "EventRecordID": record_id,
                "Channel": "Microsoft-Windows-Sysmon/Operational" if source.endswith("Sysmon") else "Security",
            },
            "EventData": {
                "Data": [{"@Name": name, "#text": value} for name, value in data.items()]
            },
        },
        "_collection_channel": "Microsoft-Windows-Sysmon/Operational" if source.endswith("Sysmon") else "Security",
        "_rendered_event_xml": f"<Event><System><EventID>{event_id}</EventID></System></Event>",
    }


def _gui_for_report(report: object, selected: str = "0") -> gui.EventReviewApp:
    app = object.__new__(gui.EventReviewApp)
    app._analysis = report
    app.events = _FakeEventTree(selected)
    app.details = _FakeText()
    return app


class WindowsEventGuiElevationTests(unittest.TestCase):
    def test_elevation_request_targets_local_pyw_with_quoted_arguments(self) -> None:
        executable = r"C:\Python 3\pythonw.exe"
        argv = [r"D:\SOC Sentinel\SOC-Sentinel-Local-Events.pyw", "--profile", "analyst test"]
        expected_parameters = subprocess.list2cmdline(argv)
        with (
            patch.object(gui.sys, "platform", "win32"),
            patch.object(gui.sys, "executable", executable),
            patch.object(gui.sys, "argv", argv),
            patch("windows_event_analyzer.gui._shell_execute_runas", return_value=33) as shell_execute,
        ):
            result = gui.relaunch_current_application_as_administrator()

        self.assertEqual(result, 33)
        shell_execute.assert_called_once_with(executable, expected_parameters, r"D:\SOC Sentinel")

    def test_elevation_request_rejects_unc_and_non_pyw_entry_points(self) -> None:
        with self.assertRaises(ValueError):
            gui._build_elevation_request(
                r"C:\Python\pythonw.exe",
                [r"\\server\share\SOC-Sentinel-Local-Events.pyw"],
            )
        with self.assertRaises(ValueError):
            gui._build_elevation_request(
                r"C:\Python\pythonw.exe",
                [r"D:\SOC Sentinel\gui.py"],
            )
        with self.assertRaises(ValueError):
            gui._build_elevation_request(
                r"C:\Python\pythonw.exe",
                [r"D:\SOC Sentinel\another-app.pyw"],
            )

    def test_shell_execute_uses_runas_through_mock_without_triggering_uac(self) -> None:
        shell32 = SimpleNamespace(ShellExecuteW=Mock(return_value=41))
        with (
            patch.object(gui.sys, "platform", "win32"),
            patch.object(gui.ctypes, "WinDLL", return_value=shell32, create=True) as load_library,
        ):
            result = gui._shell_execute_runas(
                r"C:\Python\pythonw.exe",
                r'"D:\SOC Sentinel\SOC-Sentinel-Local-Events.pyw"',
                r"D:\SOC Sentinel",
            )

        self.assertEqual(result, 41)
        load_library.assert_called_once_with("shell32", use_last_error=True)
        shell32.ShellExecuteW.assert_called_once_with(
            None,
            "runas",
            r"C:\Python\pythonw.exe",
            r'"D:\SOC Sentinel\SOC-Sentinel-Local-Events.pyw"',
            r"D:\SOC Sentinel",
            1,
        )

    def test_user_declining_confirmation_never_requests_elevation(self) -> None:
        app = object.__new__(gui.EventReviewApp)
        app._batch = LocalEventBatch((), ("Security: access denied",), ("Security",), ("Security",))
        app.root = SimpleNamespace()
        with (
            patch("windows_event_analyzer.gui.messagebox.askyesno", return_value=False),
            patch("windows_event_analyzer.gui.relaunch_current_application_as_administrator") as relaunch,
        ):
            app._relaunch_as_administrator()
        relaunch.assert_not_called()

    def test_confirmed_elevation_request_closes_original_window_only_on_success(self) -> None:
        app = object.__new__(gui.EventReviewApp)
        app._batch = LocalEventBatch((), ("Sysmon: access denied",), ("Sysmon",), ("Sysmon",))
        app.root = SimpleNamespace(destroy=Mock())
        with (
            patch("windows_event_analyzer.gui.messagebox.askyesno", return_value=True),
            patch("windows_event_analyzer.gui.relaunch_current_application_as_administrator", return_value=33) as relaunch,
        ):
            app._relaunch_as_administrator()
        relaunch.assert_called_once_with()
        app.root.destroy.assert_called_once_with()

    def test_elevation_is_not_available_off_windows(self) -> None:
        with patch.object(gui.sys, "platform", "linux"), self.assertRaises(OSError):
            gui.relaunch_current_application_as_administrator()

    def test_partial_collection_keeps_successful_channel_events_visible(self) -> None:
        event = SimpleNamespace(
            timestamp="2026-01-01T10:00:00Z",
            event_source="Sysmon",
            event_id=1,
            computer="SYNTHETIC-HOST",
            username="analyst",
            observations=("Process creation",),
            event_type="Process creation",
        )
        app = object.__new__(gui.EventReviewApp)
        app._batch = LocalEventBatch(
            ({"Event": {}},),
            ("Security: access denied; Windows permissions require an elevated launch to read this channel.",),
            ("Security", "Microsoft-Windows-Sysmon/Operational"),
            ("Security",),
        )
        app._analysis = SimpleNamespace(events=(event,), issues=("Collection issue: Security denied",))
        app.events = _FakeEventTree()
        app.details = SimpleNamespace(configure=Mock(), delete=Mock())
        app.export_button = SimpleNamespace(configure=Mock())
        app.admin_button = SimpleNamespace(configure=Mock())
        app.status = SimpleNamespace(set=Mock())

        app._populate_events()

        self.assertEqual(len(app.events.inserted), 1)
        self.assertIn("Process creation", app.events.inserted[0]["values"])
        app.admin_button.configure.assert_called_once_with(state="normal")
        self.assertIn("access denied", app.status.set.call_args.args[0])

    def test_sysmon_event_3_displays_structured_connection_and_process_fields(self) -> None:
        from windows_event_analyzer.analyzer import analyze_records

        raw = _event_record(
            3,
            {
                "Protocol": "UDP",
                "Initiated": "true",
                "SourceIp": "192.168.1.75",
                "SourceHostname": "SYNTHETIC-CLIENT",
                "SourcePort": "50512",
                "SourcePortName": "ephemeral",
                "DestinationIp": "224.0.0.252",
                "DestinationHostname": "",
                "DestinationPort": "5355",
                "DestinationPortName": "llmnr",
                "Image": r"C:\Windows\System32\svchost.exe",
                "ProcessId": "2200",
                "ProcessGuid": "{SYNTHETIC-GUID}",
                "User": r"NT AUTHORITY\NETWORK SERVICE",
            },
        )
        report = analyze_records([raw])
        app = _gui_for_report(report)
        app._event_record_indices = report.event_record_indices

        app._show_selected()

        details = app.details.content
        for expected in (
            "Connection",
            "Timestamp (source value, preserved): 2026-11-18T07:48:44.000Z",
            "Timestamp (UTC): 2026-11-18T07:48:44.000Z",
            "Timestamp (local):",
            "Protocol: UDP",
            "Initiated: true",
            "Source IP: 192.168.1.75",
            "Source hostname: SYNTHETIC-CLIENT",
            "Source port: 50512",
            "Source port name: ephemeral",
            "Destination IP: 224.0.0.252",
            "Destination port: 5355",
            "Destination port name: llmnr",
            "Process image/path: C:\\Windows\\System32\\svchost.exe",
            "Process ID: 2200",
            "Process GUID: {SYNTHETIC-GUID}",
            "User: NT AUTHORITY\\NETWORK SERVICE",
            "Source address: private",
            "Destination address: IPv4 multicast",
            "Raw Evidence (preserved source record)",
            '"EventRecordID": "301"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, details)
        self.assertNotIn("globally routable", details)
        self.assertIn("Address type is context only", details)

    def test_ipv6_source_and_destination_classifications_are_displayed(self) -> None:
        from windows_event_analyzer.analyzer import analyze_records

        raw = _event_record(3, {"SourceIp": "fe80::1", "DestinationIp": "ff02::fb"})
        report = analyze_records([raw])
        app = _gui_for_report(report)
        app._event_record_indices = report.event_record_indices

        app._show_selected()

        self.assertIn("Source address: link-local", app.details.content)
        self.assertIn("Destination address: IPv6 multicast", app.details.content)

    def test_missing_fields_and_unrelated_same_pid_do_not_fabricate_process_context(self) -> None:
        from windows_event_analyzer.analyzer import analyze_records

        network = _event_record(3, {"Image": r"C:\Windows\System32\svchost.exe", "ProcessId": "2200", "DestinationIp": "224.0.0.252"})
        separate_process = _event_record(
            1,
            {
                "Image": r"C:\Windows\System32\svchost.exe",
                "ProcessId": "2200",
                "ParentImage": r"C:\Windows\explorer.exe",
                "CommandLine": "svchost.exe -k netsvcs",
            },
            record_id="302",
        )
        report = analyze_records([network, separate_process])
        app = _gui_for_report(report, selected="0")
        app._event_record_indices = report.event_record_indices

        app._show_selected()

        self.assertIn("Parent image: Not present in event", app.details.content)
        self.assertIn("Command line: Not present in event", app.details.content)
        self.assertNotIn("explorer.exe", app.details.content)
        self.assertNotIn("-k netsvcs", app.details.content)
        self.assertIn("Destination port: Not present in event", app.details.content)

    def test_event_supplied_parent_and_command_line_are_shown_without_inference(self) -> None:
        from windows_event_analyzer.analyzer import analyze_records

        raw = _event_record(
            3,
            {
                "DestinationIp": "8.8.8.8",
                "ParentImage": r"C:\Windows\explorer.exe",
                "CommandLine": "example.exe --test",
            },
        )
        report = analyze_records([raw])
        app = _gui_for_report(report)
        app._event_record_indices = report.event_record_indices

        app._show_selected()

        self.assertIn("Parent image: C:\\Windows\\explorer.exe", app.details.content)
        self.assertIn("Command line: example.exe --test", app.details.content)

    def test_selected_event_details_refresh_and_non_network_display_remains_available(self) -> None:
        from windows_event_analyzer.analyzer import analyze_records

        network = _event_record(3, {"DestinationIp": "224.0.0.252", "DestinationPort": "5355"})
        security = _event_record(4624, {"TargetUserName": "synthetic.user", "IpAddress": "192.0.2.5"}, record_id="303")
        process = _event_record(1, {"Image": r"C:\Windows\example.exe", "ProcessId": "44"}, record_id="304")
        report = analyze_records([network, security, process])
        app = _gui_for_report(report, selected="0")
        app._event_record_indices = report.event_record_indices

        app._show_selected()
        self.assertIn("Destination port: 5355", app.details.content)
        app.events.selected = "1"
        app._show_selected()
        self.assertIn("Event ID: 4624", app.details.content)
        self.assertIn("User: synthetic.user", app.details.content)
        self.assertNotIn("Destination port", app.details.content)
        app.events.selected = "2"
        app._show_selected()
        self.assertIn("Event ID: 1", app.details.content)
        self.assertIn("Image: C:\\Windows\\example.exe", app.details.content)

    def test_raw_event_evidence_is_preserved_and_long_values_are_not_truncated(self) -> None:
        from windows_event_analyzer.analyzer import analyze_records

        long_command = "tool.exe " + "x" * 12000
        raw = _event_record(3, {"DestinationIp": "8.8.8.8", "CommandLine": long_command})
        before = copy.deepcopy(raw)
        report = analyze_records([raw])
        app = _gui_for_report(report)
        app._event_record_indices = report.event_record_indices

        app._show_selected()

        self.assertEqual(raw, before)
        self.assertEqual(report.original_records[0], before)
        self.assertIn(long_command, app.details.content)
        self.assertEqual(app.details.configure_calls[-1], {"state": "disabled"})

    def test_source_record_index_remains_correct_after_unsupported_input(self) -> None:
        from windows_event_analyzer.analyzer import analyze_records

        raw = _event_record(3, {"DestinationIp": "224.0.0.252"}, record_id="305")
        report = analyze_records([{"source": "unsupported", "event_id": 999}, raw])
        app = _gui_for_report(report)
        app._event_record_indices = report.event_record_indices

        app._show_selected()

        self.assertEqual(report.event_record_indices, [1])
        self.assertIn('"EventRecordID": "305"', app.details.content)


if __name__ == "__main__":
    unittest.main()
