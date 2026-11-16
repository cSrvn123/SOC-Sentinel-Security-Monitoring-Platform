"""Typed models for Detection Validation Workflow reports.

Structural XML checks, Python expression approximations, and Wazuh rule-engine
execution have separate status types. Passing one layer never implies another.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

_MAX_WAZUH_RULE_LEVEL = 16


def _non_empty_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty.")
    return value


def _text_tuple(values: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise TypeError(f"{field_name} must be a list or tuple of strings.")
    result = tuple(_non_empty_text(value, f"{field_name} item") for value in values)
    return result


def _enum_member(value: Any, enum_type: type[Enum], field_name: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError:
            choices = ", ".join(member.value for member in enum_type)
            raise ValueError(f"{field_name} must be one of: {choices}.") from None
    raise TypeError(f"{field_name} must be a {enum_type.__name__} member or its string value.")


def _freeze_event_value(value: Any, path: str, active: set[int] | None = None) -> Any:
    """Copy JSON-like event data into recursively read-only mappings and tuples.

    Lists become tuples and mappings become read-only MappingProxyType objects.
    Synthetic event data is expected to contain JSON scalar/container values;
    unsupported objects and cyclic containers are rejected instead of leaving
    mutable references inside a validated case.
    """

    if value is None or type(value) in (str, int, float, bool):
        return value

    if active is None:
        active = set()
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise ValueError(f"synthetic_event contains a circular mapping at {path}.")
        active.add(identity)
        try:
            frozen_mapping = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError(f"synthetic_event mapping keys must be strings at {path}.")
                frozen_mapping[key] = _freeze_event_value(item, f"{path}[{key!r}]", active)
            return MappingProxyType(frozen_mapping)
        finally:
            active.remove(identity)

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active:
            raise ValueError(f"synthetic_event contains a circular sequence at {path}.")
        active.add(identity)
        try:
            return tuple(
                _freeze_event_value(item, f"{path}[{index}]", active)
                for index, item in enumerate(value)
            )
        finally:
            active.remove(identity)

    raise TypeError(
        f"synthetic_event contains unsupported value type {type(value).__name__} at {path}."
    )


class CaseCategory(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    FALSE_POSITIVE_CONTEXT = "false_positive_context"


class ExpectedMatchStatus(str, Enum):
    MATCH = "match"
    NO_MATCH = "no_match"


class StructuralStatus(str, Enum):
    """Status of XML syntax and supported-structure inspection only."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_RUN = "not_run"


class ApproximationObservation(str, Enum):
    """Observed result from the local Python-expression approximation only."""

    MATCH = "match"
    NO_MATCH = "no_match"
    ERROR = "error"
    UNSUPPORTED = "unsupported"
    NOT_RUN = "not_run"


class ApproximationCaseStatus(str, Enum):
    """Comparison of one approximation observation with its expected result."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    UNSUPPORTED = "unsupported"
    NOT_RUN = "not_run"


class WazuhEngineStatus(str, Enum):
    """Status from an actual Wazuh rule-engine run; default is explicitly NOT_RUN."""

    NOT_RUN = "not_run"
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


@dataclass(frozen=True)
class ExpectedOutcome:
    """Expected match behavior; rule metadata is required only for expected matches."""

    match_status: ExpectedMatchStatus
    rule_id: str | None = None
    level: int | None = None

    def __post_init__(self) -> None:
        status = _enum_member(self.match_status, ExpectedMatchStatus, "match_status")
        object.__setattr__(self, "match_status", status)
        if status is ExpectedMatchStatus.MATCH:
            rule_id = _non_empty_text(self.rule_id, "rule_id")
            if not rule_id.isdigit():
                raise ValueError("rule_id must contain decimal digits only.")
            if isinstance(self.level, bool) or not isinstance(self.level, int):
                raise TypeError("level must be an integer for an expected match.")
            if self.level < 0:
                raise ValueError("level must not be negative.")
            if self.level > _MAX_WAZUH_RULE_LEVEL:
                raise ValueError(f"level must not exceed {_MAX_WAZUH_RULE_LEVEL}.")
            return
        if self.rule_id is not None or self.level is not None:
            raise ValueError("rule_id and level must be None when no match is expected.")


@dataclass(frozen=True)
class ValidationCase:
    """One inert synthetic event and its documented expected behavior."""

    case_id: str
    category: CaseCategory
    synthetic_event: Mapping[str, Any]
    expected: ExpectedOutcome
    rationale: str
    analyst_review_context: str | None = None

    def __post_init__(self) -> None:
        case_id = _non_empty_text(self.case_id, "case_id")
        category = _enum_member(self.category, CaseCategory, "category")
        if not isinstance(self.synthetic_event, Mapping):
            raise TypeError("synthetic_event must be a mapping.")
        if any(not isinstance(key, str) for key in self.synthetic_event):
            raise TypeError("synthetic_event keys must be strings.")
        event = _freeze_event_value(self.synthetic_event, "synthetic_event")
        required_fields = (
            "win.system.eventID",
            "groups",
            "win.eventdata.image",
            "win.eventdata.commandLine",
        )
        missing = [field for field in required_fields if field not in event]
        if missing:
            raise ValueError("synthetic_event is missing required fields: " + ", ".join(missing) + ".")
        event_id = event["win.system.eventID"]
        if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id <= 0:
            raise ValueError("win.system.eventID must be a positive integer.")
        groups = event["groups"]
        if not isinstance(groups, (list, tuple)) or not groups:
            raise ValueError("groups must be a non-empty list or tuple of group names.")
        if any(not isinstance(group, str) or not group.strip() for group in groups):
            raise ValueError("every group name must be a non-empty string.")
        for field in ("win.eventdata.image", "win.eventdata.commandLine"):
            _non_empty_text(event[field], field)
        if not isinstance(self.expected, ExpectedOutcome):
            raise TypeError("expected must be an ExpectedOutcome.")
        if not isinstance(self.expected.match_status, ExpectedMatchStatus):
            raise TypeError("expected.match_status must be an ExpectedMatchStatus.")
        rationale = _non_empty_text(self.rationale, "rationale")

        if category is CaseCategory.NEGATIVE:
            if self.expected.match_status is not ExpectedMatchStatus.NO_MATCH:
                raise ValueError("negative cases must expect no_match.")
        elif self.expected.match_status is not ExpectedMatchStatus.MATCH:
            raise ValueError("positive and false-positive-context cases must expect match.")

        context = self.analyst_review_context
        if category is CaseCategory.FALSE_POSITIVE_CONTEXT:
            context = _non_empty_text(context, "analyst_review_context")
        elif context is not None:
            context = _non_empty_text(context, "analyst_review_context")

        object.__setattr__(self, "case_id", case_id)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "synthetic_event", event)
        object.__setattr__(self, "rationale", rationale)
        object.__setattr__(self, "analyst_review_context", context)


@dataclass(frozen=True)
class ObservedApproximationOutcome:
    """What the local approximation observed, without claiming Wazuh execution."""

    observation: ApproximationObservation
    matched_conditions: tuple[str, ...] = ()
    unmatched_conditions: tuple[str, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        observation = _enum_member(self.observation, ApproximationObservation, "observation")
        matched = _text_tuple(self.matched_conditions, "matched_conditions")
        unmatched = _text_tuple(self.unmatched_conditions, "unmatched_conditions")
        detail = None if self.detail is None else _non_empty_text(self.detail, "detail")
        if observation is ApproximationObservation.MATCH and unmatched:
            raise ValueError("a match observation cannot contain unmatched conditions.")
        if observation is ApproximationObservation.NO_MATCH and not unmatched:
            raise ValueError("a no_match observation must identify at least one unmatched condition.")
        if observation in {
            ApproximationObservation.ERROR,
            ApproximationObservation.UNSUPPORTED,
            ApproximationObservation.NOT_RUN,
        } and detail is None:
            raise ValueError(f"{observation.value} observations require detail.")
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "matched_conditions", matched)
        object.__setattr__(self, "unmatched_conditions", unmatched)
        object.__setattr__(self, "detail", detail)


@dataclass(frozen=True)
class PerCaseValidationResult:
    """Expected-versus-observed result for the Python approximation layer."""

    case_id: str
    expected: ExpectedOutcome
    observed: ObservedApproximationOutcome
    status: ApproximationCaseStatus

    def __post_init__(self) -> None:
        _non_empty_text(self.case_id, "case_id")
        if not isinstance(self.expected, ExpectedOutcome):
            raise TypeError("expected must be an ExpectedOutcome.")
        if not isinstance(self.observed, ObservedApproximationOutcome):
            raise TypeError("observed must be an ObservedApproximationOutcome.")
        status = _enum_member(self.status, ApproximationCaseStatus, "status")
        observation_to_status = {
            ApproximationObservation.ERROR: ApproximationCaseStatus.ERROR,
            ApproximationObservation.UNSUPPORTED: ApproximationCaseStatus.UNSUPPORTED,
            ApproximationObservation.NOT_RUN: ApproximationCaseStatus.NOT_RUN,
        }
        expected_status = observation_to_status.get(self.observed.observation)
        if expected_status is None:
            expected_match = self.expected.match_status is ExpectedMatchStatus.MATCH
            observed_match = self.observed.observation is ApproximationObservation.MATCH
            expected_status = (
                ApproximationCaseStatus.PASS
                if expected_match == observed_match
                else ApproximationCaseStatus.FAIL
            )
        if status is not expected_status:
            raise ValueError(
                f"status must be {expected_status.value} for the supplied expected and observed outcomes."
            )
        object.__setattr__(self, "status", status)


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata read from the rule under inspection, not inferred from test cases."""

    rule_id: str
    level: int
    required_group: str
    field_names: tuple[str, ...]
    description: str
    mitre_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        rule_id = _non_empty_text(self.rule_id, "rule_id")
        if not rule_id.isdigit():
            raise ValueError("rule_id must contain decimal digits only.")
        if isinstance(self.level, bool) or not isinstance(self.level, int):
            raise TypeError("level must be an integer.")
        if self.level < 0:
            raise ValueError("level must not be negative.")
        if self.level > _MAX_WAZUH_RULE_LEVEL:
            raise ValueError(f"level must not exceed {_MAX_WAZUH_RULE_LEVEL}.")
        group = _non_empty_text(self.required_group, "required_group")
        fields = _text_tuple(self.field_names, "field_names")
        if not fields:
            raise ValueError("field_names must contain at least one field.")
        description = _non_empty_text(self.description, "description")
        mitre_ids = _text_tuple(self.mitre_ids, "mitre_ids")
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "required_group", group)
        object.__setattr__(self, "field_names", fields)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "mitre_ids", mitre_ids)


@dataclass(frozen=True)
class StructuralValidationResult:
    """XML parse/contract result; independent of regex approximation and Wazuh."""

    status: StructuralStatus
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: RuleMetadata | None = None

    def __post_init__(self) -> None:
        status = _enum_member(self.status, StructuralStatus, "status")
        errors = _text_tuple(self.errors, "errors")
        warnings = _text_tuple(self.warnings, "warnings")
        if status in {StructuralStatus.FAIL, StructuralStatus.ERROR} and not errors:
            raise ValueError(f"{status.value} structural results must include an error.")
        if status is StructuralStatus.PASS and errors:
            raise ValueError("a passing structural result cannot include errors.")
        if self.metadata is not None and not isinstance(self.metadata, RuleMetadata):
            raise TypeError("metadata must be RuleMetadata or None.")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "errors", errors)
        object.__setattr__(self, "warnings", warnings)


@dataclass(frozen=True)
class ValidationReport:
    """Layered report; it has no aggregate PASS that could blur validation scope."""

    rule: RuleMetadata
    cases: tuple[ValidationCase, ...]
    structural_validation: StructuralValidationResult
    approximation_results: tuple[PerCaseValidationResult, ...] = ()
    wazuh_engine_status: WazuhEngineStatus = WazuhEngineStatus.NOT_RUN
    wazuh_engine_version: str | None = None
    limitations: tuple[str, ...] = ()
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if not isinstance(self.rule, RuleMetadata):
            raise TypeError("rule must be RuleMetadata.")
        if not isinstance(self.structural_validation, StructuralValidationResult):
            raise TypeError("structural_validation must be StructuralValidationResult.")
        cases = tuple(self.cases)
        if any(not isinstance(case, ValidationCase) for case in cases):
            raise TypeError("cases must contain only ValidationCase objects.")
        case_ids = [case.case_id for case in cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case IDs in a validation report must be unique.")
        cases_by_id = {case.case_id: case for case in cases}
        for case in cases:
            expected = case.expected
            if expected.match_status is ExpectedMatchStatus.MATCH:
                if expected.rule_id != self.rule.rule_id:
                    raise ValueError(
                        f"case {case.case_id} expects rule {expected.rule_id}, "
                        f"but report rule is {self.rule.rule_id}."
                    )
                if expected.level != self.rule.level:
                    raise ValueError(
                        f"case {case.case_id} expects level {expected.level}, "
                        f"but report rule level is {self.rule.level}."
                    )
        results = tuple(self.approximation_results)
        if any(not isinstance(result, PerCaseValidationResult) for result in results):
            raise TypeError("approximation_results must contain only PerCaseValidationResult objects.")
        if self.structural_validation.status is not StructuralStatus.PASS and any(
            result.status is not ApproximationCaseStatus.NOT_RUN for result in results
        ):
            raise ValueError(
                "approximation results must all be NOT_RUN unless structural validation is PASS."
            )
        result_ids = [result.case_id for result in results]
        if len(result_ids) != len(set(result_ids)):
            raise ValueError("approximation result case IDs must be unique.")
        if not set(result_ids).issubset(set(case_ids)):
            raise ValueError("approximation results must refer to cases present in the report.")
        for result in results:
            case = cases_by_id[result.case_id]
            if result.expected != case.expected:
                raise ValueError(
                    f"approximation result for case {result.case_id} has an expected outcome "
                    "that differs from the manifest case."
                )
        engine_status = _enum_member(
            self.wazuh_engine_status, WazuhEngineStatus, "wazuh_engine_status"
        )
        engine_version = (
            None
            if self.wazuh_engine_version is None
            else _non_empty_text(self.wazuh_engine_version, "wazuh_engine_version")
        )
        if engine_status in {WazuhEngineStatus.PASS, WazuhEngineStatus.FAIL} and engine_version is None:
            raise ValueError("a completed Wazuh engine result must identify the tested Wazuh version.")
        limitations = _text_tuple(self.limitations, "limitations")
        schema_version = _non_empty_text(self.schema_version, "schema_version")
        object.__setattr__(self, "cases", cases)
        object.__setattr__(self, "approximation_results", results)
        object.__setattr__(self, "wazuh_engine_status", engine_status)
        object.__setattr__(self, "wazuh_engine_version", engine_version)
        object.__setattr__(self, "limitations", limitations)
        object.__setattr__(self, "schema_version", schema_version)
