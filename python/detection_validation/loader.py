"""Read-only structural validation for the supported Detection 001 XML rule.

This module only parses XML and checks a deliberately narrow rule structure. It
does not execute regular expressions, commands, payloads, Wazuh, or external
resources. A structural PASS is not a Python approximation or Wazuh validation.
"""

from __future__ import annotations

import ntpath
import os
from pathlib import Path
import xml.etree.ElementTree as ET

from .models import RuleMetadata, StructuralStatus, StructuralValidationResult

_MAX_XML_BYTES = 1_048_576
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_LOCAL_DRIVE_TYPES = {2, 3, 5, 6}  # removable, fixed, CD-ROM, RAM disk
_EXPECTED_ROOT_GROUP = "windows,sysmon,sysmon_process-anomalies,"
_EXPECTED_CHILD_GROUP = "powershell,process_creation,"
_EXPECTED_RULE_ID = "100100"
_EXPECTED_RULE_LEVEL = "10"
_EXPECTED_PARENT_GROUP = "sysmon_event1"
_EXPECTED_DESCRIPTION = (
    "Suspicious PowerShell encoded-command invocation attempt detected; "
    "investigation is required."
)
_EXPECTED_MITRE_ID = "T1059.001"
_EXPECTED_FIELDS = {
    "win.eventdata.image": (
        "pcre2",
        r"(?i)(?:^|\\)(?:powershell|pwsh)\.exe$",
    ),
    "win.eventdata.commandLine": (
        "pcre2",
        r'(?i)^\s*(?:"[^"]+"|\S+)\s+(?:(?:-(?:noprofile|noninteractive|nologo|sta|mta)\s+)|(?:-(?:executionpolicy|inputformat|outputformat|configurationname|version|windowstyle)\s+\S+\s+))*-(?:encodedcommand|enc)(?=\s|$)',
    ),
}
_EXPECTED_RULE_CHILDREN = {
    "if_group",
    "field",
    "description",
    "mitre",
    "group",
}
_EXPECTED_RULE_CHILD_ORDER = (
    "if_group",
    "field",
    "field",
    "description",
    "mitre",
    "group",
)
_EXPECTED_FIELD_ORDER = tuple(_EXPECTED_FIELDS)


def _error_result(status: StructuralStatus, message: str) -> StructuralValidationResult:
    return StructuralValidationResult(status=status, errors=(message,))


def _get_windows_drive_type(root: str) -> int | None:
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        return int(get_drive_type(root))
    except Exception:
        return None


def _get_windows_attributes(path: str) -> int | None:
    """Read attributes for a path component without opening its target."""

    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_attributes = kernel32.GetFileAttributesW
        get_attributes.argtypes = [ctypes.c_wchar_p]
        get_attributes.restype = ctypes.c_uint
        attributes = int(get_attributes(path))
    except Exception:
        return None
    return None if attributes == 0xFFFFFFFF else attributes


def _safe_local_path(path: str | Path) -> tuple[Path | None, str | None]:
    """Check path components for network drives and reparse points before open.

    Windows components are inspected in order with GetFileAttributesW, which
    reports the reparse-point attributes of the link itself. The walk stops at
    the first missing, inaccessible, or reparse component and never queries a
    descendant through a component already identified as a reparse point. This
    is a pre-open check, not an atomic handle-relative open: a concurrent actor
    able to replace path components between checking and opening could create a
    time-of-check/time-of-use race. Other operating systems fail closed because
    this module does not have an equivalent local-volume/reparse check there.
    """

    try:
        raw_path = os.fspath(path)
    except (TypeError, ValueError):
        return None, "XML path must be a local filesystem path."
    if not isinstance(raw_path, str):
        return None, "XML path must be a text path."
    if raw_path.startswith(("\\\\", "//")):
        return None, "Network/UNC XML paths are unsupported."

    if os.name == "nt":
        try:
            current_directory = os.getcwd()
        except OSError:
            return None, "Unable to establish the current local directory."
        if current_directory.startswith(("\\\\", "//")):
            return None, "A network current directory is unsupported."

        drive = ntpath.splitdrive(raw_path)[0]
        if not drive:
            drive = ntpath.splitdrive(current_directory)[0]
        if not drive:
            return None, "Unable to establish a local drive for the XML path."
        drive_type = _get_windows_drive_type(drive + "\\")
        if drive_type == 4:  # DRIVE_REMOTE
            return None, "Mapped network-drive XML paths are unsupported."
        if drive_type is None or drive_type not in _LOCAL_DRIVE_TYPES:
            return None, "Unable to establish that the XML path is on a local drive."

        absolute = ntpath.abspath(raw_path)
        absolute_drive, tail = ntpath.splitdrive(absolute)
        if not absolute_drive or absolute_drive.casefold() != drive.casefold():
            return None, "Unable to normalize the XML path to its verified local drive."

        current = absolute_drive + "\\"
        components = [part for part in tail.split("\\") if part]
        paths = [current]
        for component in components:
            current = ntpath.join(current, component)
            paths.append(current)

        for index, component_path in enumerate(paths):
            attributes = _get_windows_attributes(component_path)
            if attributes is None:
                return None, "Unable to verify an XML path component; refusing to open it."
            if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                return None, "Symlink or reparse-point XML paths are unsupported."
            if index < len(paths) - 1 and not attributes & _FILE_ATTRIBUTE_DIRECTORY:
                return None, "A non-directory component appears before the XML file."
        return Path(absolute), None

    return None, "Local path safety validation is supported only on Windows; refusing to open XML."


def _check_attributes(
    element: ET.Element,
    expected: dict[str, str],
    location: str,
    errors: list[str],
) -> None:
    actual = element.attrib
    for name in expected.keys() - actual.keys():
        errors.append(f"{location} is missing required attribute {name!r}.")
    for name in actual.keys() - expected.keys():
        errors.append(f"Unsupported attribute {name!r} on {location}.")
    for name in expected.keys() & actual.keys():
        if actual[name] != expected[name]:
            errors.append(
                f"{location} attribute {name!r} must be {expected[name]!r}; "
                f"found {actual[name]!r}."
            )


def _check_container_text(element: ET.Element, location: str, errors: list[str]) -> None:
    if element.text and element.text.strip():
        errors.append(f"Unsupported text content in {location}.")
    for child in element:
        if child.tail and child.tail.strip():
            errors.append(f"Unsupported text after {child.tag!r} in {location}.")


def _leaf_text(
    element: ET.Element,
    location: str,
    errors: list[str],
    *,
    preserve_whitespace: bool = False,
) -> str:
    if len(element):
        errors.append(f"Unsupported nested element inside {location}.")
    text = element.text or ""
    return text if preserve_whitespace else text.strip()


def _validate_tree(root: ET.Element) -> StructuralValidationResult:
    errors: list[str] = []
    if root.tag != "group":
        return _error_result(
            StructuralStatus.FAIL,
            f"Unsupported root element {root.tag!r}; expected 'group'.",
        )

    _check_attributes(root, {"name": _EXPECTED_ROOT_GROUP}, "root group", errors)
    _check_container_text(root, "root group", errors)
    root_children = list(root)
    if len(root_children) != 1 or any(child.tag != "rule" for child in root_children):
        errors.append("Root group must contain exactly one direct rule element.")
        for child in root_children:
            if child.tag != "rule":
                errors.append(f"Unsupported root child element {child.tag!r}.")
    rules = [child for child in root_children if child.tag == "rule"]
    if len(rules) != 1:
        return StructuralValidationResult(StructuralStatus.FAIL, tuple(errors))

    rule = rules[0]
    _check_attributes(
        rule,
        {"id": _EXPECTED_RULE_ID, "level": _EXPECTED_RULE_LEVEL},
        "rule",
        errors,
    )
    _check_container_text(rule, "rule", errors)

    children = list(rule)
    child_order = tuple(child.tag for child in children)
    if child_order != _EXPECTED_RULE_CHILD_ORDER:
        errors.append(
            "Rule children must use the exact supported Detection 001 sibling order."
        )
    for child in children:
        if child.tag not in _EXPECTED_RULE_CHILDREN:
            errors.append(f"Unsupported rule condition or child element {child.tag!r}.")

    expected_counts = {"if_group": 1, "field": 2, "description": 1, "mitre": 1, "group": 1}
    for tag, count in expected_counts.items():
        actual_count = sum(child.tag == tag for child in children)
        if actual_count < count:
            errors.append(f"Rule is missing required {tag!r} element(s).")
        elif actual_count > count:
            errors.append(f"Rule has duplicate {tag!r} elements; duplicates are unsupported.")

    for condition in (child for child in children if child.tag == "if_group"):
        _check_attributes(condition, {}, "if_group", errors)
        if _leaf_text(condition, "if_group", errors) != _EXPECTED_PARENT_GROUP:
            errors.append(f"if_group must name {_EXPECTED_PARENT_GROUP!r}.")

    seen_fields: set[str] = set()
    field_elements = [child for child in children if child.tag == "field"]
    field_order = tuple(field.get("name") for field in field_elements)
    if field_order != _EXPECTED_FIELD_ORDER:
        errors.append("Rule fields must use the exact supported Detection 001 field order.")
    for field in field_elements:
        field_name = field.get("name")
        if field_name not in _EXPECTED_FIELDS:
            if field_name is None:
                errors.append("Field element is missing its required 'name' attribute.")
            else:
                errors.append(f"Unsupported rule field {field_name!r}.")
            _check_attributes(field, {"name": "", "type": ""}, "field", errors)
            _leaf_text(field, "field", errors)
            continue

        if field_name in seen_fields:
            errors.append(f"Duplicate rule field {field_name!r}.")
        seen_fields.add(field_name)
        expected_type, expected_expression = _EXPECTED_FIELDS[field_name]
        _check_attributes(
            field,
            {"name": field_name, "type": expected_type},
            f"field {field_name!r}",
            errors,
        )
        expression = _leaf_text(
            field,
            f"field {field_name!r}",
            errors,
            preserve_whitespace=True,
        )
        if expression != expected_expression:
            errors.append(f"Regex expression for field {field_name!r} does not match the supported Detection 001 expression.")

    for description in (child for child in children if child.tag == "description"):
        _check_attributes(description, {}, "description", errors)
        if _leaf_text(description, "description", errors) != _EXPECTED_DESCRIPTION:
            errors.append("Required Detection 001 description is missing or differs from the supported description.")

    for group in (child for child in children if child.tag == "group"):
        _check_attributes(group, {}, "rule group", errors)
        if _leaf_text(group, "rule group", errors) != _EXPECTED_CHILD_GROUP:
            errors.append(f"Rule group must be {_EXPECTED_CHILD_GROUP!r}.")

    for mitre in (child for child in children if child.tag == "mitre"):
        _check_attributes(mitre, {}, "mitre", errors)
        _check_container_text(mitre, "mitre", errors)
        mitre_children = list(mitre)
        if len(mitre_children) != 1 or mitre_children[0].tag != "id":
            errors.append("mitre must contain exactly one id element; other constructs are unsupported.")
            continue
        mitre_id = mitre_children[0]
        _check_attributes(mitre_id, {}, "mitre id", errors)
        if _leaf_text(mitre_id, "mitre id", errors) != _EXPECTED_MITRE_ID:
            errors.append(f"MITRE metadata must contain {_EXPECTED_MITRE_ID!r}.")

    if errors:
        return StructuralValidationResult(StructuralStatus.FAIL, tuple(errors))

    metadata = RuleMetadata(
        rule_id=_EXPECTED_RULE_ID,
        level=int(_EXPECTED_RULE_LEVEL),
        required_group=_EXPECTED_PARENT_GROUP,
        field_names=tuple(_EXPECTED_FIELDS),
        description=_EXPECTED_DESCRIPTION,
        mitre_ids=(_EXPECTED_MITRE_ID,),
    )
    return StructuralValidationResult(StructuralStatus.PASS, metadata=metadata)


def validate_detection_001_xml(path: str | Path) -> StructuralValidationResult:
    """Parse and structurally validate one local Detection 001 XML file.

    Malformed or unreadable XML returns ``ERROR``. Valid XML containing a
    different or unsupported rule structure returns ``FAIL``. ``PASS`` means
    only that the exact supported structure was found; it does not establish
    regex equivalence, decoder behavior, or Wazuh rule-engine results.
    Direct rule children and field elements must appear in the exact order used
    by the inspected Detection 001 XML; this is a validator contract, not a
    claim about Wazuh parser order semantics.

    Stable UNC, mapped-drive, and reparse-point paths are rejected before file
    open. Non-Windows platforms fail closed. Callers requiring protection
    against concurrent path replacement must provide an immutable/trusted
    workspace; this path-based API cannot make Windows component checking and
    opening atomic.
    """

    safe_path, path_error = _safe_local_path(path)
    if path_error or safe_path is None:
        return _error_result(StructuralStatus.ERROR, path_error or "XML path could not be verified.")

    try:
        with safe_path.open("rb") as xml_file:
            data = xml_file.read(_MAX_XML_BYTES + 1)
    except (OSError, TypeError, ValueError) as exc:
        return _error_result(
            StructuralStatus.ERROR,
            f"Unable to read XML input ({type(exc).__name__}).",
        )

    if len(data) > _MAX_XML_BYTES:
        return _error_result(StructuralStatus.ERROR, "XML input exceeds the 1 MiB safety limit.")
    if b"\x00" in data:
        return _error_result(
            StructuralStatus.ERROR,
            "XML input with NUL bytes or UTF-16/UTF-32 encoding is unsupported.",
        )

    # ElementTree does not fetch external resources, and rejecting declarations
    # here also prevents entity declarations from being interpreted at all.
    upper_data = data.upper()
    if b"<!DOCTYPE" in upper_data or b"<!ENTITY" in upper_data:
        return _error_result(
            StructuralStatus.ERROR,
            "DTD and entity declarations are unsupported and were not parsed.",
        )

    try:
        root = ET.fromstring(data)
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        return _error_result(
            StructuralStatus.ERROR,
            f"Malformed XML ({type(exc).__name__}).",
        )

    return _validate_tree(root)
