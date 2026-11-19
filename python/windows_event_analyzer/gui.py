"""Small Tkinter screen for on-demand local Windows event review."""

from __future__ import annotations

import ctypes
import json
import ntpath
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .analyzer import AnalysisReport, analyze_records, classify_ip_address
from .collector import LocalEventBatch, collect_local_events
from .formatting import format_json


_DETAIL_FIELDS = (
    ("Time", "timestamp"),
    ("Computer", "computer"),
    ("Source", "event_source"),
    ("Event ID", "event_id"),
    ("Event", "event_type"),
    ("User", "username"),
    ("Source IP", "source_ip"),
    ("Destination IP", "destination_ip"),
    ("Process", "process_name"),
    ("Image", "process_path"),
    ("Process ID", "process_id"),
    ("Parent image", "parent_process"),
    ("Command line", "command_line"),
    ("DNS query", "dns_query"),
)
_MISSING = "Not present in event"
_FIELD_KEY_RE = re.compile(r"[^a-z0-9]")
_DETAIL_SECTION_HEADINGS = (
    "Connection",
    "Process",
    "Address Classification",
    "Analyzer observations",
    "Raw Evidence (preserved source record)",
)


def _mapping_get(value: object, *names: str) -> object | None:
    if not isinstance(value, Mapping):
        return None
    normalized = {_FIELD_KEY_RE.sub("", str(key).casefold()): item for key, item in value.items()}
    for name in names:
        result = normalized.get(_FIELD_KEY_RE.sub("", name.casefold()))
        if result is not None:
            return result
    return None


def _event_data_fields(record: object) -> dict[str, object]:
    event_root = _mapping_get(record, "Event") or record
    event_data = _mapping_get(event_root, "EventData", "Data")
    if event_data is None:
        win = _mapping_get(record, "win")
        event_data = _mapping_get(win, "eventdata", "data")
    fields: dict[str, object] = {}
    if isinstance(event_data, Mapping):
        items = _mapping_get(event_data, "Data")
        if isinstance(items, list):
            for item in items:
                name = _mapping_get(item, "Name", "@Name")
                value = _mapping_get(item, "#text", "Value", "Data")
                if isinstance(name, str) and value is not None:
                    fields[_FIELD_KEY_RE.sub("", name.casefold())] = value
        else:
            for name, value in event_data.items():
                if isinstance(name, str) and name.casefold() != "data":
                    fields[_FIELD_KEY_RE.sub("", name.casefold())] = value
    return fields


def _record_field(record: object, fields: Mapping[str, object], *names: str) -> str:
    for name in names:
        key = _FIELD_KEY_RE.sub("", name.casefold())
        value = fields.get(key)
        if value is None:
            continue
        if isinstance(value, Mapping):
            nested = _mapping_get(value, "#text", "text", "value", "@SystemTime", "SystemTime")
            value = nested
        if value is None or isinstance(value, (list, dict)):
            continue
        rendered = str(value).strip()
        if rendered and rendered != "-":
            return rendered
    return _MISSING


def _record_timestamp(record: object) -> str:
    event_root = _mapping_get(record, "Event") or record
    system = _mapping_get(event_root, "System") or _mapping_get(_mapping_get(record, "win"), "system")
    time_created = _mapping_get(system, "TimeCreated", "SystemTime")
    value = _mapping_get(time_created, "SystemTime", "@SystemTime")
    if value is None and isinstance(time_created, str):
        value = time_created
    if value is None:
        return _MISSING
    rendered = str(value).strip()
    return rendered if rendered and rendered != "-" else _MISSING


def _timestamp_lines(value: str) -> list[tuple[str, str]]:
    if value == _MISSING:
        return [("Timestamp (source value)", _MISSING), ("Timestamp (UTC)", _MISSING), ("Timestamp (local)", _MISSING)]
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timestamp has no timezone")
        utc_time = parsed.astimezone(timezone.utc)
        local_time = parsed.astimezone()
    except (ValueError, OverflowError):
        return [
            ("Timestamp (source value, preserved)", value),
            ("Timestamp (UTC)", "Cannot derive UTC: source timezone is missing or invalid"),
            ("Timestamp (local)", "Cannot derive local time: source timezone is missing or invalid"),
        ]
    utc_text = value if utc_time == parsed else utc_time.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return [
        ("Timestamp (source value, preserved)", value),
        ("Timestamp (UTC)", utc_text),
        ("Timestamp (local)", local_time.isoformat(timespec="microseconds") + f" [{local_time.tzname() or 'local timezone'}]"),
    ]


def _format_network_event_details(event: object, original_record: object | None) -> str:
    fields = _event_data_fields(original_record) if original_record is not None else {}
    lines = ["Connection"]
    lines.extend(f"  {label}: {value}" for label, value in _timestamp_lines(
        _record_timestamp(original_record) if original_record is not None else _MISSING
    ))
    connection_fields = (
        ("Protocol", ("Protocol",)),
        ("Initiated", ("Initiated",)),
        ("Source IP", ("SourceIp", "SourceAddress")),
        ("Source hostname", ("SourceHostname",)),
        ("Source port", ("SourcePort",)),
        ("Source port name", ("SourcePortName",)),
        ("Destination IP", ("DestinationIp", "DestinationAddress")),
        ("Destination hostname", ("DestinationHostname",)),
        ("Destination port", ("DestinationPort",)),
        ("Destination port name", ("DestinationPortName",)),
    )
    for label, names in connection_fields:
        lines.append(f"  {label}: {_record_field(original_record, fields, *names) if original_record is not None else _MISSING}")

    lines.append("\nProcess")
    process_fields = (
        ("Process image/path", ("Image",)),
        ("Process ID", ("ProcessId", "ProcessID")),
        ("Process GUID", ("ProcessGuid",)),
        ("User", ("User",)),
        ("Parent image", ("ParentImage",)),
        ("Command line", ("CommandLine",)),
    )
    for label, names in process_fields:
        lines.append(f"  {label}: {_record_field(original_record, fields, *names) if original_record is not None else _MISSING}")

    lines.append("\nAddress Classification")
    for label, names in (("Source address", ("SourceIp", "SourceAddress")), ("Destination address", ("DestinationIp", "DestinationAddress"))):
        value = _record_field(original_record, fields, *names) if original_record is not None else _MISSING
        classification = _MISSING if value == _MISSING else classify_ip_address(value)
        lines.append(f"  {label}: {classification or 'Unrecognized IP address format' if value != _MISSING else _MISSING}")
    lines.append("  Address type is context only; it is not a benign or malicious verdict.")

    observations = getattr(event, "observations", ())
    lines.append("\nAnalyzer observations")
    lines.extend(f"  - {item}" for item in observations) if observations else lines.append("  No configured heuristic signal for this event.")

    lines.append("\nRaw Evidence (preserved source record)")
    if original_record is None:
        lines.append("  Source record could not be associated unambiguously with this event.")
    else:
        try:
            lines.append(json.dumps(original_record, ensure_ascii=False, indent=2))
        except (TypeError, ValueError):
            lines.append("  Source record is retained in memory but contains values that cannot be rendered as JSON.")
    return "\n".join(lines)


class EventReviewApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SOC Sentinel — Local Windows Event Review")
        self.root.geometry("1240x840")
        self.root.minsize(980, 640)
        self._results: queue.Queue[tuple[str, Any, Any]] = queue.Queue()
        self._analysis: AnalysisReport | None = None
        self._batch: LocalEventBatch | None = None
        self._busy = False

        container = ttk.Frame(root, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(
            container,
            text="Local, read-only review. Nothing is sent over the network or saved unless you choose Export JSON.",
            wraplength=1100,
        ).pack(fill="x", pady=(0, 10))
        ttk.Label(
            container,
            text=(
                "This is an on-demand snapshot, not continuous monitoring. Event data can contain sensitive "
                "user, host, process, and command-line details."
            ),
            wraplength=1100,
        ).pack(fill="x", pady=(0, 12))

        controls = ttk.Frame(container)
        controls.pack(fill="x", pady=(0, 10))
        ttk.Label(controls, text="Look back (hours):").pack(side="left")
        self.hours = tk.IntVar(value=1)
        ttk.Spinbox(controls, from_=1, to=24, width=5, textvariable=self.hours).pack(side="left", padx=(6, 16))
        ttk.Label(controls, text="Maximum per channel:").pack(side="left")
        self.limit = tk.IntVar(value=50)
        ttk.Spinbox(controls, from_=1, to=100, width=5, textvariable=self.limit).pack(side="left", padx=(6, 16))
        self.collect_button = ttk.Button(controls, text="Collect and analyze", command=self._start_collection)
        self.collect_button.pack(side="left")
        self.export_button = ttk.Button(controls, text="Export JSON…", command=self._export_json, state="disabled")
        self.export_button.pack(side="left", padx=(8, 0))
        self.admin_button = ttk.Button(
            controls,
            text="Relaunch as administrator…",
            command=self._relaunch_as_administrator,
            state="disabled",
        )
        self.admin_button.pack(side="left", padx=(8, 0))
        self.clear_button = ttk.Button(controls, text="Clear view", command=self._clear_view)
        self.clear_button.pack(side="left", padx=(8, 0))

        self.status = tk.StringVar(value="Ready. Collection starts only when you click Collect and analyze.")
        ttk.Label(container, textvariable=self.status, wraplength=1100).pack(fill="x", pady=(0, 10))

        split = ttk.Panedwindow(container, orient="vertical")
        split.pack(fill="both", expand=True)
        events_frame = ttk.Frame(split)
        details_frame = ttk.Frame(split)
        split.add(events_frame, weight=3)
        split.add(details_frame, weight=2)

        columns = ("time", "source", "event_id", "computer", "user", "summary")
        self.events = ttk.Treeview(events_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "time": ("Time", 185),
            "source": ("Source", 115),
            "event_id": ("ID", 55),
            "computer": ("Computer", 170),
            "user": ("User", 160),
            "summary": ("Event / observation", 420),
        }
        for key, (label, width) in headings.items():
            self.events.heading(key, text=label)
            self.events.column(key, width=width, minwidth=50, stretch=key == "summary")
        scroll = ttk.Scrollbar(events_frame, orient="vertical", command=self.events.yview)
        self.events.configure(yscrollcommand=scroll.set)
        self.events.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.events.bind("<<TreeviewSelect>>", self._show_selected)

        ttk.Label(details_frame, text="Selected event details").pack(anchor="w", pady=(8, 4))
        self.details = tk.Text(details_frame, height=16, wrap="word", state="disabled")
        detail_scroll = ttk.Scrollbar(details_frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=detail_scroll.set)
        self.details.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")

        self.root.after(100, self._poll_results)

    def _start_collection(self) -> None:
        if self._busy:
            return
        try:
            hours = self.hours.get()
            limit = self.limit.get()
            if isinstance(hours, bool) or not 1 <= hours <= 24:
                raise ValueError("Look-back hours must be between 1 and 24.")
            if isinstance(limit, bool) or not 1 <= limit <= 100:
                raise ValueError("Maximum events per channel must be between 1 and 100.")
        except (tk.TclError, ValueError) as exc:
            messagebox.showerror("Invalid collection range", str(exc), parent=self.root)
            return

        self._reset_results()
        self._busy = True
        self.collect_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.admin_button.configure(state="disabled")
        self.clear_button.configure(state="disabled")
        self.status.set("Querying local Security and Sysmon event channels…")

        def worker() -> None:
            try:
                batch = collect_local_events(hours_back=hours, max_events_per_channel=limit)
                analysis = analyze_records(batch.records)
                analysis.issues.extend(f"Collection issue: {issue}" for issue in batch.issues)
                self._results.put(("success", batch, analysis))
            except Exception as exc:  # Show a generic UI error; never echo record contents.
                self._results.put(("error", type(exc).__name__, None))

        threading.Thread(target=worker, name="soc-sentinel-local-collection", daemon=True).start()

    def _poll_results(self) -> None:
        try:
            kind, first, second = self._results.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_results)
            return
        self._busy = False
        self.collect_button.configure(state="normal")
        self.clear_button.configure(state="normal")
        if kind == "error":
            self.admin_button.configure(state="disabled")
            self.status.set("Collection or analysis failed. No event contents were written to disk.")
            messagebox.showerror(
                "Collection failed",
                f"The local collection could not be completed ({first}). Check Windows channel availability and account permissions.",
                parent=self.root,
            )
        else:
            self._batch = first
            self._analysis = second
            self._populate_events()
        self.root.after(100, self._poll_results)

    def _populate_events(self) -> None:
        assert self._batch is not None and self._analysis is not None
        self._event_record_indices = list(getattr(self._analysis, "event_record_indices", ()))
        if len(self._event_record_indices) != len(self._analysis.events):
            self._event_record_indices = [None] * len(self._analysis.events)
        children = self.events.get_children()
        if children:
            self.events.delete(*children)
        for index, event in enumerate(self._analysis.events):
            summary = event.observations[0] if event.observations else event.event_type
            self.events.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    event.timestamp or "",
                    event.event_source,
                    event.event_id,
                    event.computer or "",
                    event.username or "",
                    self._short(summary),
                ),
            )
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.configure(state="disabled")
        if self._analysis.events:
            self.export_button.configure(state="normal")
        if self._batch.access_denied_channels:
            self.admin_button.configure(state="normal")

        status = (
            f"Collected {len(self._batch.records)} record(s); analyzed "
            f"{len(self._analysis.events)} supported event(s); "
            f"{len(self._analysis.issues) - len(self._batch.issues)} analyzer input issue(s); "
            f"{len(self._batch.issues)} channel issue(s)."
        )
        if self._batch.issues:
            status += " Channel issues: " + " ".join(self._batch.issues)
        elif not self._batch.records:
            status += " No matching events were found in the selected time window."
        self.status.set(status)

    @staticmethod
    def _short(value: str, limit: int = 150) -> str:
        return value if len(value) <= limit else value[: limit - 1] + "…"

    def _show_selected(self, _event: object = None) -> None:
        if self._analysis is None:
            return
        selection = self.events.selection()
        if not selection:
            self._write_details("No event selected.")
            return
        index = int(selection[0])
        if not 0 <= index < len(self._analysis.events):
            self._write_details("No event selected.")
            return
        event = self._analysis.events[index]
        if event.event_source == "Sysmon" and event.event_id == 3:
            record = self._original_record_for_event(index)
            content = _format_network_event_details(event, record)
        else:
            lines = [f"{label}: {getattr(event, attribute) or _MISSING}" for label, attribute in _DETAIL_FIELDS]
            lines.append("Observations:")
            if event.observations:
                lines.extend(f"  • {item}" for item in event.observations)
            else:
                lines.append("  No configured heuristic signal for this event.")
            content = "\n".join(lines)
        self._write_details(content)

    def _original_record_for_event(self, event_index: int) -> object | None:
        if self._analysis is None:
            return None
        indices = getattr(self, "_event_record_indices", ())
        if not 0 <= event_index < len(indices):
            return None
        record_index = indices[event_index]
        if isinstance(record_index, bool) or not isinstance(record_index, int):
            return None
        if not 0 <= record_index < len(self._analysis.original_records):
            return None
        return self._analysis.original_records[record_index]

    def _write_details(self, content: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", content)
        self.details.tag_configure("section_heading", font=("TkDefaultFont", 10, "bold"))
        for heading in _DETAIL_SECTION_HEADINGS:
            offset = content.find(heading)
            if offset >= 0:
                self.details.tag_add(
                    "section_heading",
                    f"1.0+{offset}c",
                    f"1.0+{offset + len(heading)}c",
                )
        self.details.configure(state="disabled")

    def _export_json(self) -> None:
        if self._analysis is None:
            return
        accepted = messagebox.askyesno(
            "Sensitive event data",
            "The JSON includes retained source event records and may contain usernames, hostnames, IPs, or command lines. Save only to an approved location. Continue?",
            parent=self.root,
        )
        if not accepted:
            return
        output = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save event analysis JSON",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
            initialfile="soc-sentinel-event-analysis.json",
        )
        if not output:
            return
        try:
            Path(output).write_text(format_json(self._analysis), encoding="utf-8")
        except OSError:
            messagebox.showerror("Save failed", "The JSON report could not be saved to that location.", parent=self.root)
            return
        self.status.set(f"Analysis JSON saved to the selected location: {Path(output).name}")

    def _relaunch_as_administrator(self) -> None:
        if not self._batch or not self._batch.access_denied_channels:
            return
        channels = ", ".join(self._batch.access_denied_channels)
        accepted = messagebox.askyesno(
            "Request elevated launch",
            f"Windows denied access to: {channels}. Relaunch SOC Sentinel as administrator?\n\n"
            "Windows will display a User Account Control prompt. This only retries the same read-only, "
            "filtered event queries; it does not change log permissions, clear logs, or change audit policy. "
            "Continue only if you trust this local project code.",
            parent=self.root,
        )
        if not accepted:
            return
        try:
            result = relaunch_current_application_as_administrator()
        except (OSError, RuntimeError, ValueError):
            messagebox.showerror(
                "Administrator relaunch unavailable",
                "SOC Sentinel could not safely prepare an elevated relaunch. Start the .pyw application "
                "manually as administrator if you choose to retry.",
                parent=self.root,
            )
            return
        if result > 32:
            self.root.destroy()
        else:
            messagebox.showerror(
                "Administrator relaunch failed",
                "Windows did not start the elevated application. The current read-only view remains open.",
                parent=self.root,
            )

    def _clear_view(self) -> None:
        self._reset_results()
        self.status.set("View cleared. Windows event logs were not changed.")

    def _reset_results(self) -> None:
        children = self.events.get_children()
        if children:
            self.events.delete(*children)
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.configure(state="disabled")
        self._analysis = None
        self._batch = None
        self.export_button.configure(state="disabled")
        self.admin_button.configure(state="disabled")


def main() -> None:
    """Start the local event review window."""

    if sys_platform_is_windows():
        root = tk.Tk()
        EventReviewApp(root)
        root.mainloop()
        return
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Windows required",
        "Live collection reads local Windows event channels and is available only on Windows.",
        parent=root,
    )
    root.destroy()


def sys_platform_is_windows() -> bool:
    return sys.platform == "win32"


def _build_elevation_request(executable: str, argv: list[str]) -> tuple[str, str, str]:
    """Build a constrained ShellExecute request for this local ``.pyw`` app."""
    def is_local_absolute(path: str) -> bool:
        drive, _tail = ntpath.splitdrive(path)
        return (
            "\x00" not in path
            and bool(drive)
            and not drive.startswith("\\\\")
            and ntpath.isabs(path)
        )

    if not isinstance(executable, str) or not is_local_absolute(executable) or not executable.lower().endswith(".exe"):
        raise ValueError("The Python executable must be an absolute local Windows executable path.")
    if not isinstance(argv, list) or not argv or not isinstance(argv[0], str):
        raise ValueError("The current application script could not be identified.")
    script = argv[0]
    if (
        not is_local_absolute(script)
        or ntpath.basename(script).casefold() != "soc-sentinel-local-events.pyw"
    ):
        raise ValueError("Elevated relaunch is supported only for the local SOC Sentinel .pyw entry point.")
    if any(not isinstance(argument, str) for argument in argv):
        raise ValueError("Application arguments must be strings.")
    parameters = subprocess.list2cmdline(argv)
    if len(parameters) > 32767:
        raise ValueError("The current application arguments exceed the Windows launch limit.")
    return executable, parameters, ntpath.dirname(script)


def _shell_execute_runas(executable: str, parameters: str, working_directory: str) -> int:
    """Ask Windows ShellExecuteW to launch the existing app with the runas verb."""
    if not sys_platform_is_windows():
        raise OSError("Administrator relaunch is available only on Windows.")
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("Windows ShellExecute is unavailable in this environment.")
    try:
        shell32 = win_dll("shell32", use_last_error=True)
        shell_execute = shell32.ShellExecuteW
        shell_execute.argtypes = (
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
        )
        shell_execute.restype = ctypes.c_void_p
        result = shell_execute(None, "runas", executable, parameters, working_directory, 1)
    except (AttributeError, OSError) as exc:
        raise OSError("Windows ShellExecute failed.") from exc
    return int(result or 0)


def relaunch_current_application_as_administrator() -> int:
    """Explicitly relaunch the current local ``.pyw`` app using Windows UAC."""
    if not sys_platform_is_windows():
        raise OSError("Administrator relaunch is available only on Windows.")
    executable, parameters, working_directory = _build_elevation_request(sys.executable, list(sys.argv))
    return _shell_execute_runas(executable, parameters, working_directory)
