"""Local Python ``re`` approximation for Detection 001 synthetic cases.

This module does not execute PCRE2, a Wazuh decoder, or the Wazuh rule engine.
It evaluates the exact field expressions from a locally read XML tree only
after both the supplied structural result and a fresh validation of those same
XML bytes pass. The supported approximation subset is deliberately narrow:
``(?i)`` only at pattern start, non-capturing groups, positive lookahead,
anchors, alternation, character classes, basic greedy ``*``/``+``/``?``
quantifiers, and escapes for backslash, dot, whitespace, and non-whitespace.
Other extensions are reported as unsupported instead of being translated.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Mapping

from .loader import (
    _MAX_XML_BYTES,
    _safe_local_path,
    _validate_tree,
)
from .models import (
    ApproximationCaseStatus,
    ApproximationObservation,
    ExpectedMatchStatus,
    ExpectedOutcome,
    ObservedApproximationOutcome,
    PerCaseValidationResult,
    RuleMetadata,
    StructuralStatus,
    StructuralValidationResult,
    ValidationCase,
    ValidationReport,
    WazuhEngineStatus,
)

_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_EXPECTED_CASE_IDS = frozenset(
    [f"P{number}" for number in range(1, 7)]
    + [f"N{number}" for number in range(1, 10)]
    + [f"FP{number}" for number in range(1, 4)]
    + [f"L{number}" for number in range(1, 12)]
    + [f"V{number}" for number in range(1, 7)]
    + [f"M{number}" for number in range(1, 4)]
    + [f"I{number}" for number in range(1, 3)]
)
_PYTHON_APPROXIMATION_LIMITATION = (
    "Observed outcomes use Python's standard re module and supplied synthetic "
    "group metadata; they do not establish PCRE2, Wazuh decoder, or Wazuh "
    "rule-engine behavior."
)


class ManifestValidationError(ValueError):
    """The manifest is malformed, incomplete, or contains duplicate data."""


class _UnsupportedExpression(ValueError):
    pass


def _no_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestValidationError(f"Duplicate JSON property {key!r}.")
        result[key] = value
    return result


def _read_local_bytes(path: str | Path, limit: int, label: str) -> bytes:
    safe_path, error = _safe_local_path(path)
    if error or safe_path is None:
        raise ManifestValidationError(error or f"Unable to verify local {label} path.")
    try:
        with safe_path.open("rb") as stream:
            data = stream.read(limit + 1)
    except (OSError, TypeError, ValueError) as exc:
        raise ManifestValidationError(f"Unable to read {label} ({type(exc).__name__}).") from None
    if len(data) > limit:
        raise ManifestValidationError(f"{label.capitalize()} exceeds the {limit}-byte safety limit.")
    return data


def _require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestValidationError(f"{where} must be a JSON object.")
    return value


def _require_keys(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    where: str,
) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ManifestValidationError(
            f"{where} is missing fields: {', '.join(sorted(missing))}."
        )
    if unknown:
        raise ManifestValidationError(
            f"{where} contains unsupported fields: {', '.join(sorted(unknown))}."
        )


def load_manifest(path: str | Path) -> tuple[RuleMetadata, tuple[ValidationCase, ...]]:
    """Load every manifest case in order and validate it through the frozen models.

    Duplicate JSON properties, case IDs, missing fields, unknown fields, and
    unsupported values are rejected. Synthetic events are recursively frozen
    by :class:`ValidationCase`; no input event is modified.
    """

    raw = _read_local_bytes(path, _MAX_MANIFEST_BYTES, "manifest")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestValidationError(f"Malformed manifest ({type(exc).__name__}).") from None

    root = _require_object(document, "manifest")
    _require_keys(root, {"schema_version", "rule", "cases"}, set(), "manifest")
    if root["schema_version"] != "1.0":
        raise ManifestValidationError("Only manifest schema_version '1.0' is supported.")

    rule_data = _require_object(root["rule"], "manifest.rule")
    _require_keys(
        rule_data,
        {
            "path",
            "rule_id",
            "level",
            "required_group",
            "field_names",
            "description",
            "mitre_ids",
        },
        set(),
        "manifest.rule",
    )
    if not isinstance(rule_data["path"], str) or not rule_data["path"].strip():
        raise ManifestValidationError("manifest.rule.path must be a non-empty string.")
    try:
        rule = RuleMetadata(
            rule_id=rule_data["rule_id"],
            level=rule_data["level"],
            required_group=rule_data["required_group"],
            field_names=rule_data["field_names"],
            description=rule_data["description"],
            mitre_ids=rule_data["mitre_ids"],
        )
    except (TypeError, ValueError) as exc:
        raise ManifestValidationError(f"Invalid manifest rule metadata: {exc}") from None

    case_data = root["cases"]
    if not isinstance(case_data, list) or not case_data:
        raise ManifestValidationError("manifest.cases must be a non-empty JSON array.")

    cases: list[ValidationCase] = []
    seen_ids: set[str] = set()
    for index, raw_case in enumerate(case_data):
        where = f"manifest.cases[{index}]"
        item = _require_object(raw_case, where)
        _require_keys(
            item,
            {"case_id", "category", "synthetic_event", "expected", "rationale"},
            {"analyst_review_context"},
            where,
        )
        expected_data = _require_object(item["expected"], f"{where}.expected")
        _require_keys(
            expected_data,
            {"match_status"},
            {"rule_id", "level"},
            f"{where}.expected",
        )
        expected = ExpectedOutcome(
            match_status=expected_data["match_status"],
            rule_id=expected_data.get("rule_id"),
            level=expected_data.get("level"),
        )
        try:
            case = ValidationCase(
                case_id=item["case_id"],
                category=item["category"],
                synthetic_event=item["synthetic_event"],
                expected=expected,
                rationale=item["rationale"],
                analyst_review_context=item.get("analyst_review_context"),
            )
        except (TypeError, ValueError) as exc:
            raise ManifestValidationError(f"Invalid {where}: {exc}") from None
        if case.case_id in seen_ids:
            raise ManifestValidationError(f"Duplicate case ID {case.case_id!r}.")
        seen_ids.add(case.case_id)
        cases.append(case)

    if seen_ids != _EXPECTED_CASE_IDS:
        missing = sorted(_EXPECTED_CASE_IDS - seen_ids)
        unexpected = sorted(seen_ids - _EXPECTED_CASE_IDS)
        details = []
        if missing:
            details.append("missing documented IDs: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected IDs: " + ", ".join(unexpected))
        raise ManifestValidationError(
            "Manifest case inventory is incomplete (" + "; ".join(details) + ")."
        )

    return rule, tuple(cases)


def _validate_python_subset(expression: str) -> None:
    """Reject regex syntax outside the explicitly supported approximation subset."""

    if not isinstance(expression, str):
        raise TypeError("Rule field expression must be a string.")
    index = 0
    in_class = False
    while index < len(expression):
        char = expression[index]
        if char == "\\":
            if index + 1 >= len(expression):
                return  # re.compile reports the malformed trailing escape.
            escaped = expression[index + 1]
            if escaped not in {"\\", ".", "s", "S"}:
                raise _UnsupportedExpression(f"Unsupported regex escape \\{escaped}.")
            index += 2
            continue
        if in_class:
            if char == "[":
                raise _UnsupportedExpression("Nested character classes are unsupported.")
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
            index += 1
            continue
        if char == "(":
            allowed = expression.startswith("(?:", index) or expression.startswith("(?=", index)
            allowed_flags = index == 0 and expression.startswith("(?i)", index)
            if allowed_flags:
                index += 4
                continue
            if allowed:
                index += 3
                continue
            if index + 1 >= len(expression):
                return  # re.compile reports an incomplete group as invalid syntax.
            if expression[index + 1] != "?":
                raise _UnsupportedExpression("Ordinary capturing groups are unsupported.")
            raise _UnsupportedExpression("Unsupported group or PCRE2-specific construct.")
        if char == "." and not in_class:
            raise _UnsupportedExpression("Unescaped wildcard dots are outside the supported subset.")
        if char in "{}":
            raise _UnsupportedExpression("Brace quantifiers are outside the supported subset.")
        if char in "*+?" and index + 1 < len(expression) and expression[index + 1] in "*+?":
            raise _UnsupportedExpression("Lazy and possessive quantifier forms are unsupported.")
        index += 1


def _compile_field_expressions(
    expressions: Mapping[str, str],
) -> dict[str, re.Pattern[str]]:
    compiled: dict[str, re.Pattern[str]] = {}
    for field_name, expression in expressions.items():
        _validate_python_subset(expression)
        try:
            compiled[field_name] = re.compile(expression)
        except re.error as exc:
            raise ValueError(f"Invalid Python regex for {field_name}: {exc.msg}.") from None
    return compiled


def _evaluate_case(
    case: ValidationCase,
    required_group: str,
    expressions: Mapping[str, re.Pattern[str]],
) -> PerCaseValidationResult:
    event = case.synthetic_event
    matched: list[str] = []
    unmatched: list[str] = []

    groups = event.get("groups")
    group_condition = f"if_group={required_group} (synthetic supplied metadata)"
    if isinstance(groups, (list, tuple)) and required_group in groups:
        matched.append(group_condition)
    else:
        unmatched.append(group_condition)

    for field_name, pattern in expressions.items():
        condition = f"field:{field_name}"
        value = event.get(field_name)
        if not isinstance(value, str):
            unmatched.append(condition + " (missing or non-string)")
            continue
        if pattern.search(value) is not None:
            matched.append(condition)
        else:
            unmatched.append(condition)

    observation = (
        ApproximationObservation.MATCH
        if not unmatched
        else ApproximationObservation.NO_MATCH
    )
    observed = ObservedApproximationOutcome(
        observation=observation,
        matched_conditions=tuple(matched),
        unmatched_conditions=tuple(unmatched),
        detail=(
            "All required conditions matched under Python re."
            if observation is ApproximationObservation.MATCH
            else "One or more required group or field conditions did not match under Python re."
        ),
    )
    status = (
        ApproximationCaseStatus.PASS
        if case.expected.match_status is (
            ExpectedMatchStatus.MATCH
            if observation is ApproximationObservation.MATCH
            else ExpectedMatchStatus.NO_MATCH
        )
        else ApproximationCaseStatus.FAIL
    )
    return PerCaseValidationResult(case.case_id, case.expected, observed, status)


def _not_run_result(case: ValidationCase, detail: str) -> PerCaseValidationResult:
    observed = ObservedApproximationOutcome(
        ApproximationObservation.NOT_RUN,
        detail=detail,
    )
    return PerCaseValidationResult(
        case.case_id, case.expected, observed, ApproximationCaseStatus.NOT_RUN
    )


def _unavailable_results(
    cases: tuple[ValidationCase, ...],
    observation: ApproximationObservation,
    status: ApproximationCaseStatus,
    detail: str,
) -> tuple[PerCaseValidationResult, ...]:
    observed = ObservedApproximationOutcome(observation, detail=detail)
    return tuple(
        PerCaseValidationResult(case.case_id, case.expected, observed, status)
        for case in cases
    )


def _rule_bytes_validation(path: str | Path) -> tuple[StructuralValidationResult, ET.Element | None]:
    safe_path, error = _safe_local_path(path)
    if error or safe_path is None:
        return (
            StructuralValidationResult(
                StructuralStatus.ERROR,
                errors=(error or "Unable to verify local XML path.",),
            ),
            None,
        )
    try:
        with safe_path.open("rb") as stream:
            data = stream.read(_MAX_XML_BYTES + 1)
    except (OSError, TypeError, ValueError) as exc:
        return StructuralValidationResult(
            StructuralStatus.ERROR,
            errors=(f"Unable to read XML input ({type(exc).__name__}).",),
        ), None
    if len(data) > _MAX_XML_BYTES:
        return StructuralValidationResult(
            StructuralStatus.ERROR, errors=("XML input exceeds the 1 MiB safety limit.",)
        ), None
    if b"\x00" in data:
        return StructuralValidationResult(
            StructuralStatus.ERROR,
            errors=("XML input with NUL bytes or UTF-16/UTF-32 encoding is unsupported.",),
        ), None
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        return StructuralValidationResult(
            StructuralStatus.ERROR,
            errors=("DTD and entity declarations are unsupported and were not parsed.",),
        ), None
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        return StructuralValidationResult(
            StructuralStatus.ERROR, errors=(f"Malformed XML ({type(exc).__name__}).",)
        ), None
    return _validate_tree(root), root


def run_manifest_approximation(
    manifest_path: str | Path,
    rule_xml_path: str | Path,
    structural_validation: StructuralValidationResult,
) -> ValidationReport:
    """Evaluate every manifest case using Python ``re`` after structural PASS.

    A non-PASS supplied structural result produces a full set of explicit
    per-case ``NOT_RUN`` results without opening the XML path. For a supplied
    PASS, this function validates the exact bounded XML bytes it reads before
    extracting conditions, preventing stale structural metadata from being
    treated as validation of different file contents.
    """

    if not isinstance(structural_validation, StructuralValidationResult):
        raise TypeError("structural_validation must be a StructuralValidationResult.")
    manifest_rule, cases = load_manifest(manifest_path)
    limitations = [_PYTHON_APPROXIMATION_LIMITATION]

    if structural_validation.status is not StructuralStatus.PASS:
        detail = (
            "Approximation was not run because the supplied structural validation "
            f"status is {structural_validation.status.value}."
        )
        results = tuple(_not_run_result(case, detail) for case in cases)
        return ValidationReport(
            manifest_rule,
            cases,
            structural_validation,
            results,
            WazuhEngineStatus.NOT_RUN,
            limitations=tuple(limitations),
        )
    if structural_validation.metadata is None:
        raise ValueError("A structural PASS must include validated rule metadata.")

    current_validation, root = _rule_bytes_validation(rule_xml_path)
    if current_validation.status is not StructuralStatus.PASS or root is None:
        detail = "Approximation was not run because current XML bytes did not pass structural validation."
        results = tuple(_not_run_result(case, detail) for case in cases)
        return ValidationReport(
            manifest_rule,
            cases,
            current_validation,
            results,
            WazuhEngineStatus.NOT_RUN,
            limitations=tuple(limitations),
        )

    actual_rule = current_validation.metadata
    if actual_rule is None:
        raise ValueError("Fresh structural PASS did not provide rule metadata.")
    if actual_rule != structural_validation.metadata:
        detail = (
            "Approximation was not run because the supplied structural result "
            "does not describe the current rule metadata."
        )
        results = tuple(_not_run_result(case, detail) for case in cases)
        return ValidationReport(
            actual_rule,
            cases,
            current_validation,
            results,
            WazuhEngineStatus.NOT_RUN,
            limitations=tuple(limitations),
        )
    if actual_rule != manifest_rule:
        detail = (
            "Approximation was not run because manifest rule metadata differs "
            "from the structurally validated XML."
        )
        results = tuple(_not_run_result(case, detail) for case in cases)
        return ValidationReport(
            actual_rule,
            cases,
            current_validation,
            results,
            WazuhEngineStatus.NOT_RUN,
            limitations=tuple(limitations),
        )

    rule_element = next(child for child in root if child.tag == "rule")
    expressions = {
        child.get("name"): child.text or ""
        for child in rule_element
        if child.tag == "field"
    }
    try:
        compiled = _compile_field_expressions(expressions)
    except _UnsupportedExpression as exc:
        detail = f"Python approximation unsupported: {exc}"
        results = _unavailable_results(
            cases,
            ApproximationObservation.UNSUPPORTED,
            ApproximationCaseStatus.UNSUPPORTED,
            detail,
        )
    except (TypeError, ValueError) as exc:
        detail = f"Python approximation expression error: {exc}"
        results = _unavailable_results(
            cases,
            ApproximationObservation.ERROR,
            ApproximationCaseStatus.ERROR,
            detail,
        )
    else:
        results = tuple(_evaluate_case(case, actual_rule.required_group, compiled) for case in cases)

    return ValidationReport(
        actual_rule,
        cases,
        current_validation,
        results,
        WazuhEngineStatus.NOT_RUN,
        limitations=tuple(limitations),
    )


