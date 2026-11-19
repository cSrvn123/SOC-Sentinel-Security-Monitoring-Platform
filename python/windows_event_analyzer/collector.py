"""Read a bounded set of recent local Windows Security and Sysmon events.

Collection is on-demand and read-only. It uses the Windows ``wevtutil`` query
utility with fixed channels and event-ID filters; event content is never
executed. The returned records use the Event Viewer XML shape accepted by
``analyze_records`` and retain a rendered XML copy for evidence review.
"""

from __future__ import annotations

import ctypes
import locale
import os
import re
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class EventLogCollectionError(RuntimeError):
    """Safe collection error that does not include event contents."""


@dataclass(frozen=True)
class LocalEventBatch:
    """Events and channel-level issues from one explicit local collection."""

    records: tuple[dict[str, Any], ...]
    issues: tuple[str, ...]
    channels_queried: tuple[str, ...]
    access_denied_channels: tuple[str, ...] = ()


_CHANNELS = (
    ("Security", (4624, 4625)),
    ("Microsoft-Windows-Sysmon/Operational", (1, 3, 22)),
)
_MIN_HOURS = 1
_MAX_HOURS = 24
_MIN_EVENTS = 1
_MAX_EVENTS_PER_CHANNEL = 100
_MAX_XML_BYTES_PER_CHANNEL = 8 * 1024 * 1024
_PIPE_READ_CHUNK_BYTES = 64 * 1024
_MAX_STDERR_BYTES = 8 * 1024
_QUERY_TIMEOUT_SECONDS = 20
_XML_DECLARATION = re.compile(r"^\s*<\?xml[^?]*\?>", re.IGNORECASE)


def _wevtutil_path() -> Path:
    if os.name != "nt":
        raise EventLogCollectionError("Local Windows Event Log collection is available only on Windows.")
    try:
        get_system_directory = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
        get_system_directory.argtypes = (ctypes.c_wchar_p, ctypes.c_uint)
        get_system_directory.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_system_directory(buffer, len(buffer))
    except (AttributeError, OSError) as exc:
        raise EventLogCollectionError("Unable to locate the Windows system event-query utility.") from exc
    if not length or length >= len(buffer):
        raise EventLogCollectionError("Unable to locate the Windows system event-query utility.")
    executable = Path(buffer.value) / "wevtutil.exe"
    if not executable.is_file():
        raise EventLogCollectionError("The Windows event-query utility is unavailable.")
    return executable


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _direct_child(element: ET.Element, name: str) -> ET.Element | None:
    return next((child for child in element if _local_name(child.tag) == name), None)


def _rendered_xml_records(output: bytes | bytearray, channel: str) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    if len(output) > _MAX_XML_BYTES_PER_CHANNEL:
        raise EventLogCollectionError(f"The {channel} query exceeded the response-size limit.")
    if not output.strip():
        return [], ()
    try:
        if output.startswith((b"\xff\xfe", b"\xfe\xff")):
            rendered = output.decode("utf-16")
        elif output[:4] in (b"<\x00?\x00", b"\x00<\x00?"):
            rendered = output.decode("utf-16-le" if output[0] == 0x3C else "utf-16-be")
        else:
            try:
                rendered = output.decode("utf-8-sig")
            except UnicodeDecodeError:
                rendered = output.decode(locale.getpreferredencoding(False))
    except (LookupError, UnicodeDecodeError) as exc:
        raise EventLogCollectionError(f"The {channel} query returned unsupported XML encoding.") from exc
    rendered = _XML_DECLARATION.sub("", rendered, count=1)
    lowered = rendered.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise EventLogCollectionError(f"The {channel} query returned unsupported XML declarations.")
    try:
        batch = ET.fromstring(f"<EventBatch>{rendered}</EventBatch>")
    except ET.ParseError as exc:
        raise EventLogCollectionError(f"The {channel} query returned malformed event XML.") from exc

    event_elements: list[ET.Element] = []
    issues: list[str] = []
    for child in batch:
        child_name = _local_name(child.tag)
        if child_name == "Event":
            event_elements.append(child)
        elif child_name in {"Events", "EventBatch"}:
            for nested in child:
                if _local_name(nested.tag) == "Event":
                    event_elements.append(nested)
                else:
                    issues.append(f"{channel}: skipped an XML element that was not an Event record.")
        else:
            issues.append(f"{channel}: skipped an XML element that was not an Event record.")

    records: list[dict[str, Any]] = []
    for event in event_elements:
        system = _direct_child(event, "System")
        if system is None:
            issues.append(f"{channel}: skipped an Event record without its System element.")
            continue
        provider = _direct_child(system, "Provider")
        event_id = _direct_child(system, "EventID")
        time_created = _direct_child(system, "TimeCreated")
        computer = _direct_child(system, "Computer")
        channel_node = _direct_child(system, "Channel")
        record_id = _direct_child(system, "EventRecordID")

        system_record: dict[str, Any] = {
            "Provider": {"@Name": provider.get("Name", "") if provider is not None else ""},
            "EventID": {"#text": event_id.text or "" if event_id is not None else ""},
            "TimeCreated": {"@SystemTime": time_created.get("SystemTime", "") if time_created is not None else ""},
            "Computer": computer.text or "" if computer is not None else "",
            "Channel": channel_node.text or "" if channel_node is not None else channel,
            "EventRecordID": record_id.text or "" if record_id is not None else "",
        }

        event_data_node = _direct_child(event, "EventData")
        data_items: list[dict[str, str]] = []
        if event_data_node is not None:
            for item in event_data_node:
                if _local_name(item.tag) == "Data":
                    data_items.append({"@Name": item.get("Name", ""), "#text": item.text or ""})

        event_record: dict[str, Any] = {
            "System": system_record,
            "EventData": {"Data": data_items},
        }
        user_data_node = _direct_child(event, "UserData")
        if user_data_node is not None:
            event_record["UserDataXml"] = ET.tostring(user_data_node, encoding="unicode")
        records.append(
            {
                "Event": event_record,
                "_collection_channel": channel,
                "_rendered_event_xml": ET.tostring(event, encoding="unicode"),
            }
        )
    return records, tuple(issues)


def _read_stdout_bounded(
    stream: Any,
    limit: int,
    stop_process: Any,
) -> tuple[bytearray, bool, BaseException | None]:
    """Retain at most ``limit`` stdout bytes while draining the pipe.

    One additional byte is read only to distinguish exact-limit output from
    oversized output; it is never appended to the retained buffer. After
    overflow, the process is stopped and the pipe is closed without buffering
    the remaining output.
    """

    retained = bytearray(limit)
    view = memoryview(retained)
    used = 0
    try:
        while used < limit:
            read_size = min(_PIPE_READ_CHUNK_BYTES, limit - used)
            count = stream.readinto(view[used : used + read_size])
            if not count:
                break
            used += count
    except Exception as exc:
        del view
        del retained[used:]
        try:
            stop_process()
        except OSError:
            pass
        try:
            stream.close()
        except OSError:
            pass
        return retained, False, exc

    del view
    if used == limit:
        try:
            overflow = bool(stream.read(1))
        except Exception as exc:
            del retained[used:]
            try:
                stop_process()
            except OSError:
                pass
            try:
                stream.close()
            except OSError:
                pass
            return retained, False, exc
        if overflow:
            try:
                stop_process()
            except OSError:
                pass
            try:
                stream.close()
            except OSError:
                pass
            return retained, True, None
    del retained[used:]
    return retained, False, None


def _drain_stderr(stream: Any) -> bytes:
    """Drain stderr while retaining only a small prefix for safe classification."""
    retained = bytearray()
    try:
        while True:
            chunk = stream.read(_PIPE_READ_CHUNK_BYTES)
            if not chunk:
                break
            room = _MAX_STDERR_BYTES - len(retained)
            if room > 0:
                retained.extend(chunk[:room])
    except Exception:
        # The exit code remains available even if the diagnostic pipe fails.
        return bytes(retained)
    return bytes(retained)


def _is_access_denied(returncode: int | None, stderr: bytes) -> bool:
    """Recognize access denial by stable Windows codes or a narrow English fallback.

    Windows error text is localized. Unrecognized localized messages remain
    generic; this function deliberately does not guess from other wording.
    """
    if returncode in {5, 0x80070005, -2147024891}:
        return True
    # The fallback handles common wevtutil output on systems that return a
    # generic process status. Removing NULs also covers UTF-16 ASCII text.
    text = stderr.replace(b"\x00", b"").decode("ascii", errors="ignore").casefold()
    return "access is denied" in text or "access denied" in text


def _query_channel(
    executable: Path,
    channel: str,
    event_ids: tuple[int, ...],
    hours_back: int,
    max_events: int,
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    milliseconds = hours_back * 60 * 60 * 1000
    id_condition = " or ".join(f"EventID={event_id}" for event_id in event_ids)
    query = f"*[System[({id_condition}) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]"
    args = [
        str(executable), "qe", channel, f"/q:{query}", "/rd:true",
        f"/c:{max_events}", "/f:RenderedXml",
    ]
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        return [], (f"{channel}: the Windows event-query utility could not be started.",)

    if process.stdout is None or process.stderr is None:
        try:
            process.kill()
        except OSError:
            pass
        return [], (f"{channel}: the Windows event-query utility did not provide output pipes.",)

    stdout_state: dict[str, Any] = {"data": bytearray(), "exceeded": False, "error": None}
    stderr_state: dict[str, bytes] = {"data": b""}

    def read_stdout() -> None:
        data, exceeded, error = _read_stdout_bounded(
            process.stdout,
            _MAX_XML_BYTES_PER_CHANNEL,
            process.kill,
        )
        stdout_state.update(data=data, exceeded=exceeded, error=error)

    def read_stderr() -> None:
        stderr_state["data"] = _drain_stderr(process.stderr)

    stdout_thread = threading.Thread(target=read_stdout, name="wevtutil-stdout-reader", daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, name="wevtutil-stderr-drainer", daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        process.wait(timeout=_QUERY_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
    stdout_thread.join()
    stderr_thread.join()

    if timed_out:
        return [], (f"{channel}: query timed out after {_QUERY_TIMEOUT_SECONDS} seconds.",)
    if stdout_state["error"] is not None:
        return [], (f"{channel}: failed while reading query output.",)
    if stdout_state["exceeded"]:
        return [], (f"{channel}: query exceeded the {_MAX_XML_BYTES_PER_CHANNEL}-byte response limit; output was discarded.",)
    if process.returncode:
        if _is_access_denied(process.returncode, stderr_state["data"]):
            return [], (
                f"{channel}: access denied; Windows permissions require an elevated launch to read this channel.",
            )
        # Never show raw stderr: it may be localized or contain sensitive context.
        return [], (f"{channel}: query failed with Windows utility exit code {process.returncode}.",)
    try:
        records, issues = _rendered_xml_records(stdout_state["data"], channel)
        return records, issues
    except EventLogCollectionError as exc:
        return [], (f"{channel}: {exc}",)


def collect_local_events(hours_back: int = 1, max_events_per_channel: int = 50) -> LocalEventBatch:
    """Collect recent supported event IDs from fixed local Windows channels.

    The function performs bounded, read-only queries of the Security channel
    (4624/4625) and Sysmon Operational channel (1/3/22). It makes no network
    requests, does not change log configuration, and does not execute event
    command-line content. Access depends on the current Windows account's
    channel permissions; it never requests elevation.
    """

    if isinstance(hours_back, bool) or not isinstance(hours_back, int) or not _MIN_HOURS <= hours_back <= _MAX_HOURS:
        raise ValueError(f"hours_back must be an integer from {_MIN_HOURS} to {_MAX_HOURS}.")
    if (
        isinstance(max_events_per_channel, bool)
        or not isinstance(max_events_per_channel, int)
        or not _MIN_EVENTS <= max_events_per_channel <= _MAX_EVENTS_PER_CHANNEL
    ):
        raise ValueError(f"max_events_per_channel must be an integer from {_MIN_EVENTS} to {_MAX_EVENTS_PER_CHANNEL}.")

    executable = _wevtutil_path()
    records: list[dict[str, Any]] = []
    issues: list[str] = []
    access_denied: list[str] = []
    queried = tuple(channel for channel, _event_ids in _CHANNELS)
    for channel, event_ids in _CHANNELS:
        channel_records, channel_issues = _query_channel(
            executable, channel, event_ids, hours_back, max_events_per_channel
        )
        records.extend(channel_records)
        issues.extend(channel_issues)
        if any(issue.startswith(f"{channel}: access denied;") for issue in channel_issues):
            access_denied.append(channel)
    return LocalEventBatch(tuple(records), tuple(issues), queried, tuple(access_denied))
