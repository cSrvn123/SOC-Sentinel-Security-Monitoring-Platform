"""Deterministic JSON and Markdown formatting for validation reports.

Formatting is deliberately passive: it serializes the supplied model and never
loads a manifest, evaluates expressions, invokes Wazuh, or deploys a rule.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from enum import Enum
from typing import Any

from .models import (
    ApproximationCaseStatus,
    ApproximationObservation,
    CaseCategory,
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

_CATEGORY_TYPES = (CaseCategory,)
_EXPECTED_STATUS_TYPES = (ExpectedMatchStatus,)
_STRUCTURAL_STATUS_TYPES = (StructuralStatus,)
_APPROXIMATION_OBSERVATION_TYPES = (ApproximationObservation,)
_APPROXIMATION_CASE_STATUS_TYPES = (ApproximationCaseStatus,)
_WAZUH_STATUS_TYPES = (WazuhEngineStatus,)
_JSON_SAFE_ENUM_TYPES = (
    *_CATEGORY_TYPES,
    *_EXPECTED_STATUS_TYPES,
    *_STRUCTURAL_STATUS_TYPES,
    *_APPROXIMATION_OBSERVATION_TYPES,
    *_APPROXIMATION_CASE_STATUS_TYPES,
    *_WAZUH_STATUS_TYPES,
)

_LAYER_EXPLANATIONS = {
    "structural_validation": (
        "Checks XML syntax and the supported Detection 001 structure only."
    ),
    "python_approximation": (
        "Uses Python re against synthetic inputs; Python re is not PCRE2 and "
        "does not establish Wazuh decoder behavior."
    ),
    "wazuh_rule_engine": (
        "Represents only a genuine Wazuh rule-engine run; NOT_RUN means no such "
        "validation is reported."
    ),
}


def _qualified_type(value: Any) -> str:
    value_type = type(value)
    module = value_type.__module__
    name = value_type.__qualname__
    return f"{module}.{name}"


def _json_value(value: Any, path: str = "$", active: set[int] | None = None) -> Any:
    """Convert supported JSON values without generic object introspection.

    Only built-in JSON scalars, known workflow enums, mappings with exact
    string keys, and built-in lists/tuples are accepted. Dataclasses are
    serialized by explicit model-specific functions below. Cycles and
    unsupported values are rejected with their path rather than dropped.
    """

    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{path}: non-finite floats are not valid JSON values.")
        return value
    if isinstance(value, Enum):
        if type(value) not in _JSON_SAFE_ENUM_TYPES:
            raise TypeError(f"{path}: unsupported enum type {_qualified_type(value)}.")
        return _json_value(value.value, f"{path}.value", active)

    if active is None:
        active = set()
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise ValueError(f"{path}: circular mapping is not supported.")
        active.add(identity)
        try:
            converted: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise TypeError(f"{path}: mapping keys must be built-in strings.")
                converted[key] = _json_value(item, f'{path}[{json.dumps(key)}]', active)
            return converted
        finally:
            active.remove(identity)

    if type(value) in (tuple, list):
        identity = id(value)
        if identity in active:
            raise ValueError(f"{path}: circular sequence is not supported.")
        active.add(identity)
        try:
            return [
                _json_value(item, f"{path}[{index}]", active)
                for index, item in enumerate(value)
            ]
        finally:
            active.remove(identity)

    raise TypeError(f"{path}: unsupported JSON value type {_qualified_type(value)}.")


def _enum_field(value: Enum) -> str:
    if type(value) not in _JSON_SAFE_ENUM_TYPES or type(value.value) is not str:
        raise TypeError(f"Unsupported workflow enum value of type {_qualified_type(value)}.")
    return value.value


def _rule_payload(rule: RuleMetadata) -> dict[str, Any]:
    if type(rule) is not RuleMetadata:
        raise TypeError("rule must be an exact RuleMetadata instance.")
    return {
        "rule_id": _json_value(rule.rule_id, "$.rule.rule_id"),
        "level": _json_value(rule.level, "$.rule.level"),
        "required_group": _json_value(rule.required_group, "$.rule.required_group"),
        "field_names": _json_value(rule.field_names, "$.rule.field_names"),
        "description": _json_value(rule.description, "$.rule.description"),
        "mitre_ids": _json_value(rule.mitre_ids, "$.rule.mitre_ids"),
    }


def _expected_payload(expected: ExpectedOutcome, path: str) -> dict[str, Any]:
    if type(expected) is not ExpectedOutcome:
        raise TypeError(f"{path}: expected an exact ExpectedOutcome instance.")
    return {
        "match_status": _enum_field(expected.match_status),
        "rule_id": _json_value(expected.rule_id, f"{path}.rule_id"),
        "level": _json_value(expected.level, f"{path}.level"),
    }


def _case_payload(case: ValidationCase, index: int) -> dict[str, Any]:
    if type(case) is not ValidationCase:
        raise TypeError("case must be an exact ValidationCase instance.")
    path = f"$.cases[{index}]"
    return {
        "case_id": _json_value(case.case_id, f"{path}.case_id"),
        "category": _enum_field(case.category),
        "synthetic_event": _json_value(case.synthetic_event, f"{path}.synthetic_event"),
        "expected": _expected_payload(case.expected, f"{path}.expected"),
        "rationale": _json_value(case.rationale, f"{path}.rationale"),
        "analyst_review_context": _json_value(
            case.analyst_review_context,
            f"{path}.analyst_review_context",
        ),
    }


def _structural_payload(result: StructuralValidationResult) -> dict[str, Any]:
    if type(result) is not StructuralValidationResult:
        raise TypeError("structural_validation must be an exact StructuralValidationResult instance.")
    return {
        "status": _enum_field(result.status),
        "errors": _json_value(result.errors, "$.structural_validation.errors"),
        "warnings": _json_value(result.warnings, "$.structural_validation.warnings"),
        "metadata": None if result.metadata is None else _rule_payload(result.metadata),
    }


def _approximation_result_payload(result: PerCaseValidationResult, index: int) -> dict[str, Any]:
    if type(result) is not PerCaseValidationResult:
        raise TypeError("approximation result must be an exact PerCaseValidationResult instance.")
    observed = result.observed
    path = f"$.approximation_results[{index}]"
    if type(observed) is not ObservedApproximationOutcome:
        raise TypeError("observed outcome must be an exact ObservedApproximationOutcome instance.")
    return {
        "case_id": result.case_id,
        "expected": _expected_payload(result.expected, f"{path}.expected"),
        "observed": {
            "observation": _enum_field(observed.observation),
            "matched_conditions": _json_value(
                observed.matched_conditions,
                f"{path}.observed.matched_conditions",
            ),
            "unmatched_conditions": _json_value(
                observed.unmatched_conditions,
                f"{path}.observed.unmatched_conditions",
            ),
        "detail": _json_value(
            observed.detail,
            f"{path}.observed.detail",
        ),
        },
        "comparison_status": _enum_field(result.status),
    }


def _report_payload(report: ValidationReport) -> dict[str, Any]:
    if type(report) is not ValidationReport:
        raise TypeError("report must be an exact ValidationReport instance.")
    cases = [_case_payload(case, index) for index, case in enumerate(report.cases)]
    results = [
        _approximation_result_payload(result, index)
        for index, result in enumerate(report.approximation_results)
    ]
    results_by_id = {result.case_id for result in report.approximation_results}
    missing_ids = [case.case_id for case in report.cases if case.case_id not in results_by_id]

    category_counts = {
        category.value: sum(case.category is category for case in report.cases)
        for category in CaseCategory
    }
    status_counts = {
        status.value: sum(result.status is status for result in report.approximation_results)
        for status in ApproximationCaseStatus
    }
    observation_counts = {
        observation.value: sum(
            result.observed.observation is observation
            for result in report.approximation_results
        )
        for observation in ApproximationObservation
    }

    return {
        "report_type": "detection_validation_report",
        "schema_version": _json_value(report.schema_version, "$.schema_version"),
        "generation_context": "Local deterministic serialization of the supplied report model.",
        "rule": _rule_payload(report.rule),
        "structural_validation": _structural_payload(report.structural_validation),
        "cases": cases,
        "approximation_results": results,
        "approximation_summary": {
            "manifest_case_count": len(report.cases),
            "result_count": len(report.approximation_results),
            "missing_result_count": len(missing_ids),
            "missing_result_case_ids": missing_ids,
            "category_counts": category_counts,
            "comparison_status_counts": status_counts,
            "observation_counts": observation_counts,
            "unsupported_count": status_counts[ApproximationCaseStatus.UNSUPPORTED.value],
            "error_count": status_counts[ApproximationCaseStatus.ERROR.value],
            "not_run_count": status_counts[ApproximationCaseStatus.NOT_RUN.value],
        },
        "validation_layers": dict(_LAYER_EXPLANATIONS),
        "deployment_status": "NOT_PERFORMED_BY_THIS_WORKFLOW",
        "deployment_note": "This formatter and validation workflow do not deploy rules.",
        "wazuh_engine": {
            "status": _enum_field(report.wazuh_engine_status),
            "version": _json_value(report.wazuh_engine_version, "$.wazuh_engine.version"),
        },
        "limitations": _json_value(report.limitations, "$.limitations"),
        "privacy_notice": (
            "JSON preserves synthetic event fields, including command-line strings. "
            "Review exports before sharing."
        ),
    }


def format_json(report: ValidationReport) -> str:
    """Return a deterministic JSON representation of the supplied report."""

    payload = _report_payload(report)
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    )


def _markdown_text(value: Any) -> str:
    """Render trusted scalar types without invoking caller conversion methods."""

    if value is None:
        return "NOT PROVIDED"
    if isinstance(value, Enum):
        if type(value) not in _JSON_SAFE_ENUM_TYPES or type(value.value) is not str:
            return "[unsupported enum value]"
        value = value.value
    if type(value) is str:
        text = value
    elif type(value) is bool:
        text = "true" if value else "false"
    elif type(value) is int:
        text = str(value)
    elif type(value) is float:
        if not math.isfinite(value):
            return "[non-finite number]"
        text = format(value, ".15g")
    else:
        return "[unsupported value]"

    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ↵ ")
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\\": "\\\\",
        "`": "\\`",
        "*": "\\*",
        "_": "\\_",
        "{": "\\{",
        "}": "\\}",
        "[": "\\[",
        "]": "\\]",
        "(": "\\(",
        ")": "\\)",
        "#": "\\#",
        "+": "\\+",
        "-": "\\-",
        ".": "\\.",
        "!": "\\!",
        "|": "\\|",
        "~": "\\~",
    }
    return "".join(replacements.get(char, char) for char in text)


def _display_expected(expected: ExpectedOutcome) -> str:
    parts = [_markdown_text(expected.match_status)]
    if expected.rule_id is not None:
        parts.append(f"rule {_markdown_text(expected.rule_id)}")
    if expected.level is not None:
        parts.append(f"level {_markdown_text(expected.level)}")
    return "; ".join(parts)


def _case_condition_text(result: PerCaseValidationResult) -> str:
    observed = result.observed
    pieces: list[str] = []
    if observed.detail is not None:
        pieces.append(_markdown_text(observed.detail))
    if observed.matched_conditions:
        pieces.append(
            "Matched conditions: "
            + ", ".join(_markdown_text(value) for value in observed.matched_conditions)
        )
    if observed.unmatched_conditions:
        pieces.append(
            "Unmatched conditions: "
            + ", ".join(_markdown_text(value) for value in observed.unmatched_conditions)
        )
    return "; ".join(pieces) if pieces else "No result explanation supplied."


def _result_summary(report: ValidationReport) -> tuple[dict[str, int], dict[str, int], list[str]]:
    status_counts = {
        status.value: sum(result.status is status for result in report.approximation_results)
        for status in ApproximationCaseStatus
    }
    categories = {
        category.value: sum(case.category is category for case in report.cases)
        for category in CaseCategory
    }
    result_ids = {result.case_id for result in report.approximation_results}
    missing = [case.case_id for case in report.cases if case.case_id not in result_ids]
    return categories, status_counts, missing


def format_markdown(report: ValidationReport) -> str:
    """Return a readable report without expanding synthetic event records."""

    if type(report) is not ValidationReport:
        raise TypeError("report must be an exact ValidationReport instance.")

    lines = [
        "# Detection Validation Report",
        "",
        "Local report generated from the supplied validation model. No validation was rerun.",
        "",
        "## Rule Metadata",
        "",
        f"- Rule ID: {_markdown_text(report.rule.rule_id)}",
        f"- Level: {_markdown_text(report.rule.level)}",
        f"- Required group: {_markdown_text(report.rule.required_group)} (synthetic group input; decoder assignment is not established)",
        f"- Fields: {', '.join(_markdown_text(value) for value in report.rule.field_names)}",
        f"- Description: {_markdown_text(report.rule.description)}",
        f"- MITRE IDs: {', '.join(_markdown_text(value) for value in report.rule.mitre_ids) if report.rule.mitre_ids else 'None'}",
        "",
        "## Structural Validation",
        "",
        f"- Status: **{_markdown_text(report.structural_validation.status).upper()}**",
    ]
    if report.structural_validation.metadata is not None:
        lines.append("- Structural metadata: present")
    for error in report.structural_validation.errors:
        lines.append(f"- Error: {_markdown_text(error)}")
    for warning in report.structural_validation.warnings:
        lines.append(f"- Warning: {_markdown_text(warning)}")

    categories, statuses, missing_ids = _result_summary(report)
    observations = {
        observation.value: sum(
            result.observed.observation is observation
            for result in report.approximation_results
        )
        for observation in ApproximationObservation
    }
    lines.extend(
        [
            "",
            "## Python Approximation",
            "",
            "Results below are from Python `re` over synthetic inputs. Python `re` is not PCRE2. These results do not validate Wazuh decoder or rule-engine behavior.",
            "",
            "## Category Summary",
            "",
            "| Category | Cases |",
            "|---|---:|",
        ]
    )
    for category in CaseCategory:
        lines.append(f"| {_markdown_text(category.value)} | {categories[category.value]} |")
    lines.extend(["", "## Approximation Result Counts", "", "| Comparison status | Count |", "|---|---:|"])
    for status in ApproximationCaseStatus:
        lines.append(f"| {_markdown_text(status.value)} | {statuses[status.value]} |")
    lines.append(f"| Missing result | {len(missing_ids)} |")
    lines.append("")
    lines.append("Observed outcome counts: " + _markdown_text(", ".join(
        f"{key}={value}" for key, value in observations.items()
    )))

    result_by_id = {result.case_id: result for result in report.approximation_results}
    lines.extend(
        [
            "",
            "## Per-Case Results",
            "",
            "| Case | Category | Expected | Observed | Comparison | Explanation |",
            "|---|---|---|---|---|---|",
        ]
    )
    for case in report.cases:
        result = result_by_id.get(case.case_id)
        if result is None:
            observed = "NOT_RUN (result missing)"
            comparison = "MISSING_RESULT"
            explanation = _markdown_text(case.rationale)
        else:
            observed = result.observed.observation
            comparison = result.status
            explanation = _markdown_text(case.rationale) + "; " + _case_condition_text(result)
        lines.append(
            "| " + " | ".join(
                (
                    _markdown_text(case.case_id),
                    _markdown_text(case.category),
                    _display_expected(case.expected),
                    _markdown_text(observed),
                    _markdown_text(comparison),
                    explanation,
                )
            ) + " |"
        )

    fp_cases = [case for case in report.cases if case.category is CaseCategory.FALSE_POSITIVE_CONTEXT]
    lines.extend(["", "## False-Positive Context", ""])
    if fp_cases:
        lines.append(
            "These cases are expected alerts when rule conditions match. Their context supports analyst review; it is not a suppression instruction."
        )
        for case in fp_cases:
            context = (
                case.rationale
                if case.analyst_review_context is None
                else case.analyst_review_context
            )
            lines.append(f"- { _markdown_text(case.case_id) }: {_markdown_text(context)}")
    else:
        lines.append("No false-positive-context cases are present.")

    special_results = [
        result
        for result in report.approximation_results
        if result.status in {
            ApproximationCaseStatus.UNSUPPORTED,
            ApproximationCaseStatus.ERROR,
            ApproximationCaseStatus.NOT_RUN,
        }
    ]
    lines.extend(["", "## Unsupported, Error, and Not-Run Cases", ""])
    for result in special_results:
        lines.append(
            f"- {_markdown_text(result.case_id)}: comparison {_markdown_text(result.status)}, "
            f"observation {_markdown_text(result.observed.observation)} — "
            f"{_markdown_text(result.observed.detail)}"
        )
    for case_id in missing_ids:
        lines.append(f"- {_markdown_text(case_id)}: MISSING_RESULT; no approximation result was supplied.")
    if not special_results and not missing_ids:
        lines.append("No unsupported, error, not-run, or missing-result cases.")

    lines.extend(
        [
            "",
            "## Deployment Status",
            "",
            "**NOT PERFORMED BY THIS WORKFLOW.** Formatting and local approximation do not deploy rules.",
            "",
            "## Wazuh Rule-Engine Status",
            "",
            f"**{_markdown_text(report.wazuh_engine_status).upper()}**",
        ]
    )
    if report.wazuh_engine_version is not None:
        lines.append(f"- Reported Wazuh version: {_markdown_text(report.wazuh_engine_version)}")

    lines.extend(["", "## Limitations and Analyst Interpretation", ""])
    lines.extend(
        [
            "- Structural PASS checks XML structure only.",
            "- Python `re` results are approximations, not PCRE2 validation.",
            "- Supplied synthetic group metadata does not prove real decoder output.",
            "- Wazuh decoder and rule-engine behavior were not validated unless separately represented by a genuine engine result.",
            "- A comparison PASS means the Python approximation agreed with the expected case outcome; it is not an aggregate validation verdict.",
        ]
    )
    for limitation in report.limitations:
        lines.append(f"- {_markdown_text(limitation)}")

    return "\n".join(lines) + "\n"
