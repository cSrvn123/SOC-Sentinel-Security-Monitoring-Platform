"""Focused integrity tests for the Detection Validation Step 1 models."""

import copy
import json
import math
from dataclasses import replace
import unittest
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from detection_validation.models import (
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
from detection_validation import (
    ManifestValidationError,
    load_manifest,
    run_manifest_approximation,
    validate_detection_001_xml,
    format_json,
    format_markdown,
)
from detection_validation.formatting import _json_value
from detection_validation.runner import _UnsupportedExpression, _compile_field_expressions


def _rule(rule_id="100100", level=10):
    return RuleMetadata(
        rule_id=rule_id,
        level=level,
        required_group="sysmon_event1",
        field_names=("win.eventdata.image", "win.eventdata.commandLine"),
        description="Synthetic rule metadata.",
        mitre_ids=("T1059.001",),
    )


def _event():
    return {
        "win.system.eventID": 1,
        "groups": ["sysmon_event1"],
        "win.eventdata.image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "win.eventdata.commandLine": "powershell.exe -enc SYNTHETIC-TEST-DATA",
    }


def _case(case_id="P1", category=CaseCategory.POSITIVE, expected=None, event=None):
    if expected is None:
        expected = ExpectedOutcome(ExpectedMatchStatus.MATCH, "100100", 10)
    return ValidationCase(
        case_id=case_id,
        category=category,
        synthetic_event=_event() if event is None else event,
        expected=expected,
        rationale="Synthetic regression fixture.",
        analyst_review_context=(
            "Review synthetic authorization context."
            if category is CaseCategory.FALSE_POSITIVE_CONTEXT
            else None
        ),
    )


def _structural(rule=None):
    return StructuralValidationResult(
        StructuralStatus.PASS,
        metadata=_rule() if rule is None else rule,
    )


class ValidationReportConsistencyTests(unittest.TestCase):
    def test_rejects_false_pass_when_result_expectation_contradicts_case(self):
        case = _case(
            "N1",
            CaseCategory.NEGATIVE,
            ExpectedOutcome(ExpectedMatchStatus.NO_MATCH),
        )
        # This result is internally a PASS for its own claimed expectation,
        # but contradicts the no_match expectation recorded on manifest case N1.
        result = PerCaseValidationResult(
            case_id="N1",
            expected=ExpectedOutcome(ExpectedMatchStatus.MATCH, "100100", 10),
            observed=ObservedApproximationOutcome(ApproximationObservation.MATCH),
            status=ApproximationCaseStatus.PASS,
        )

        with self.assertRaisesRegex(ValueError, "differs from the manifest case"):
            ValidationReport(
                rule=_rule(),
                cases=(case,),
                structural_validation=_structural(),
                approximation_results=(result,),
            )

    def test_rejects_case_expected_rule_id_mismatch(self):
        case = _case(
            expected=ExpectedOutcome(ExpectedMatchStatus.MATCH, "999999", 10)
        )
        with self.assertRaisesRegex(ValueError, "expects rule 999999"):
            ValidationReport(_rule(), (case,), _structural())

    def test_rejects_case_expected_level_mismatch(self):
        case = _case(expected=ExpectedOutcome(ExpectedMatchStatus.MATCH, "100100", 9))
        with self.assertRaisesRegex(ValueError, "expects level 9"):
            ValidationReport(_rule(), (case,), _structural())

    def test_no_match_case_does_not_require_match_metadata(self):
        case = _case(
            "N1",
            CaseCategory.NEGATIVE,
            ExpectedOutcome(ExpectedMatchStatus.NO_MATCH),
            event={
                "win.system.eventID": 3,
                "groups": ["sysmon_event3"],
                "win.eventdata.image": r"C:\Windows\System32\cmd.exe",
                "win.eventdata.commandLine": "cmd.exe /c echo SYNTHETIC-TEST-DATA",
            },
        )
        report = ValidationReport(_rule(), (case,), _structural())
        self.assertIs(report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)
        self.assertIs(report.cases[0].expected.match_status, ExpectedMatchStatus.NO_MATCH)

    def test_matching_result_is_accepted_when_expectations_agree(self):
        case = _case()
        result = PerCaseValidationResult(
            case_id="P1",
            expected=ExpectedOutcome(ExpectedMatchStatus.MATCH, "100100", 10),
            observed=ObservedApproximationOutcome(ApproximationObservation.MATCH),
            status=ApproximationCaseStatus.PASS,
        )
        report = ValidationReport(_rule(), (case,), _structural(), (result,))
        self.assertEqual(report.approximation_results, (result,))

    def test_non_pass_structural_status_rejects_evaluated_approximation_outcomes(self):
        case = _case()
        outcomes = (
            PerCaseValidationResult(
                case.case_id,
                case.expected,
                ObservedApproximationOutcome(ApproximationObservation.MATCH),
                ApproximationCaseStatus.PASS,
            ),
            PerCaseValidationResult(
                case.case_id,
                case.expected,
                ObservedApproximationOutcome(
                    ApproximationObservation.NO_MATCH,
                    unmatched_conditions=("synthetic condition",),
                ),
                ApproximationCaseStatus.FAIL,
            ),
            PerCaseValidationResult(
                case.case_id,
                case.expected,
                ObservedApproximationOutcome(
                    ApproximationObservation.ERROR,
                    detail="Synthetic expression error.",
                ),
                ApproximationCaseStatus.ERROR,
            ),
            PerCaseValidationResult(
                case.case_id,
                case.expected,
                ObservedApproximationOutcome(
                    ApproximationObservation.UNSUPPORTED,
                    detail="Synthetic unsupported expression.",
                ),
                ApproximationCaseStatus.UNSUPPORTED,
            ),
        )
        base_report = ValidationReport(
            _rule(), (case,), _structural(), (outcomes[0],)
        )
        structural_failures = (
            StructuralValidationResult(StructuralStatus.FAIL, errors=("Synthetic mismatch",)),
            StructuralValidationResult(StructuralStatus.ERROR, errors=("Synthetic parse error",)),
            StructuralValidationResult(StructuralStatus.NOT_RUN),
        )

        for structural in structural_failures:
            for result in outcomes:
                with self.subTest(structural=structural.status.value, result=result.status.value):
                    evaluated_report = replace(base_report, approximation_results=(result,))
                    with self.assertRaisesRegex(ValueError, "must all be NOT_RUN"):
                        replace(evaluated_report, structural_validation=structural)

    def test_non_pass_structure_accepts_only_explicit_not_run_results(self):
        case = _case()
        not_run = PerCaseValidationResult(
            case.case_id,
            case.expected,
            ObservedApproximationOutcome(
                ApproximationObservation.NOT_RUN,
                detail="Structural validation was not successful.",
            ),
            ApproximationCaseStatus.NOT_RUN,
        )
        non_pass_results = (
            StructuralValidationResult(StructuralStatus.FAIL, errors=("Synthetic mismatch",)),
            StructuralValidationResult(StructuralStatus.ERROR, errors=("Synthetic parse error",)),
            StructuralValidationResult(StructuralStatus.NOT_RUN),
        )
        for structural in non_pass_results:
            with self.subTest(structural=structural.status.value):
                report = ValidationReport(_rule(), (case,), structural, (not_run,))
                self.assertEqual(report.approximation_results, (not_run,))

    def test_structural_pass_allows_empty_and_partial_approximation_results(self):
        positive = _case("P1")
        negative = _case(
            "N1", CaseCategory.NEGATIVE, ExpectedOutcome(ExpectedMatchStatus.NO_MATCH)
        )
        partial_result = PerCaseValidationResult(
            positive.case_id,
            positive.expected,
            ObservedApproximationOutcome(ApproximationObservation.MATCH),
            ApproximationCaseStatus.PASS,
        )
        empty = ValidationReport(_rule(), (positive, negative), _structural(), ())
        partial = ValidationReport(
            _rule(), (positive, negative), _structural(), (partial_result,)
        )
        self.assertEqual(empty.approximation_results, ())
        self.assertEqual(partial.approximation_results, (partial_result,))


class SyntheticEventImmutabilityTests(unittest.TestCase):
    def test_original_input_mutation_does_not_change_case(self):
        event = _event()
        event["details"] = {"inner": {"items": ["before"]}}
        case = _case(event=event)
        event["groups"].append("changed-outside")
        event["details"]["inner"]["items"].append("changed-outside")

        self.assertEqual(case.synthetic_event["groups"], ("sysmon_event1",))
        self.assertEqual(
            case.synthetic_event["details"]["inner"]["items"],
            ("before",),
        )

    def test_exposed_top_level_mapping_is_read_only(self):
        case = _case()
        with self.assertRaises(TypeError):
            case.synthetic_event["new-field"] = "value"

    def test_nested_mapping_is_read_only(self):
        event = _event()
        event["details"] = {"source": {"label": "synthetic"}}
        case = _case(event=event)

        with self.assertRaises(TypeError):
            case.synthetic_event["details"]["source"]["label"] = "changed"
        self.assertEqual(case.synthetic_event["details"]["source"]["label"], "synthetic")

    def test_nested_list_is_an_immutable_sequence(self):
        event = _event()
        event["values"] = ["one", "two"]
        case = _case(event=event)

        self.assertEqual(case.synthetic_event["values"], ("one", "two"))
        with self.assertRaises(AttributeError):
            case.synthetic_event["values"].append("three")
        with self.assertRaises(TypeError):
            case.synthetic_event["values"][0] = "changed"

    def test_mutation_several_levels_deep_is_prevented(self):
        event = _event()
        event["nested"] = {"items": [{"enabled": True, "tags": ["synthetic"]}]}
        case = _case(event=event)

        nested = case.synthetic_event["nested"]["items"][0]
        self.assertIsInstance(case.synthetic_event["nested"]["items"], tuple)
        with self.assertRaises(TypeError):
            nested["enabled"] = False
        with self.assertRaises(AttributeError):
            nested["tags"].append("changed")
        self.assertTrue(nested["enabled"])
        self.assertEqual(nested["tags"], ("synthetic",))

    def test_rejects_non_json_mutable_event_values(self):
        event = _event()
        event["mutable-object"] = object()
        with self.assertRaisesRegex(TypeError, "unsupported value type"):
            _case(event=event)


class Detection001StructuralValidationTests(unittest.TestCase):
    RULE_PATH = (
        Path(__file__).resolve().parents[2]
        / "wazuh"
        / "custom-rules"
        / "100100-suspicious-powershell.xml"
    )

    @classmethod
    def setUpClass(cls):
        cls.xml = cls.RULE_PATH.read_text(encoding="utf-8")

    def validate_temporary_xml(self, content):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-rule.xml"
            path.write_text(content, encoding="utf-8")
            return validate_detection_001_xml(path)

    def validate_temporary_bytes(self, content):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-rule.xml"
            path.write_bytes(content)
            return validate_detection_001_xml(path)

    def _make_directory_symlink_or_skip(self, target, link):
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"Directory symlink/reparse-point creation unavailable: {exc}")

    def _make_file_symlink_or_skip(self, target, link):
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"File symlink/reparse-point creation unavailable: {exc}")

    def test_valid_actual_detection_001_xml(self):
        result = validate_detection_001_xml(self.RULE_PATH)
        self.assertIs(result.status, StructuralStatus.PASS)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.metadata.rule_id, "100100")
        self.assertEqual(result.metadata.level, 10)
        self.assertEqual(result.metadata.required_group, "sysmon_event1")
        self.assertEqual(
            result.metadata.field_names,
            ("win.eventdata.image", "win.eventdata.commandLine"),
        )
        self.assertEqual(result.metadata.mitre_ids, ("T1059.001",))

    def test_malformed_xml_returns_error(self):
        result = self.validate_temporary_xml("<group><rule>")
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertIsNone(result.metadata)
        self.assertTrue(result.errors)

    def test_wrong_rule_id_fails(self):
        xml = self.xml.replace('id="100100"', 'id="100101"', 1)
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("attribute 'id'" in error for error in result.errors))

    def test_wrong_rule_level_fails(self):
        xml = self.xml.replace('level="10"', 'level="9"', 1)
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("attribute 'level'" in error for error in result.errors))

    def test_missing_required_parent_group_fails(self):
        xml = self.xml.replace("    <if_group>sysmon_event1</if_group>\n", "", 1)
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("if_group" in error for error in result.errors))

    def test_missing_required_field_fails(self):
        line = next(
            line
            for line in self.xml.splitlines()
            if '<field name="win.eventdata.image"' in line
        )
        xml = self.xml.replace(line + "\n", "", 1)
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("field" in error for error in result.errors))

    def test_modified_regex_attribute_fails(self):
        xml = self.xml.replace('type="pcre2"', 'type="regex"', 1)
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("attribute 'type'" in error for error in result.errors))

    def test_modified_regex_expression_fails(self):
        xml = self.xml.replace("(?=\\s|$)", "(?=\\s|$) ", 1)
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("Regex expression" in error for error in result.errors))

    def test_unsupported_rule_element_fails(self):
        xml = self.xml.replace(
            "    <if_group>sysmon_event1</if_group>",
            "    <if_group>sysmon_event1</if_group>\n    <if_sid>42</if_sid>",
            1,
        )
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("Unsupported rule condition" in error for error in result.errors))

    def test_unsupported_attribute_fails(self):
        xml = self.xml.replace(
            '<field name="win.eventdata.image" type="pcre2">',
            '<field name="win.eventdata.image" type="pcre2" negate="yes">',
            1,
        )
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("Unsupported attribute 'negate'" in error for error in result.errors))

    def test_unsupported_logical_construct_fails(self):
        xml = self.xml.replace(
            "    <if_group>sysmon_event1</if_group>",
            "    <if_group>sysmon_event1</if_group>\n    <if_matched_group>sysmon_event3</if_matched_group>",
            1,
        )
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("if_matched_group" in error for error in result.errors))

    def test_nested_rule_construct_fails(self):
        xml = self.xml.replace(
            "<if_group>sysmon_event1</if_group>",
            "<if_group>sysmon_event1<if_sid>42</if_sid></if_group>",
            1,
        )
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("nested element" in error for error in result.errors))

    def test_reordered_rule_children_fail(self):
        lines = self.xml.splitlines()
        group_index = next(i for i, line in enumerate(lines) if "<if_group>" in line)
        field_index = next(i for i, line in enumerate(lines) if '<field name="win.eventdata.image"' in line)
        lines[group_index], lines[field_index] = lines[field_index], lines[group_index]
        result = self.validate_temporary_xml("\n".join(lines) + "\n")
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("sibling order" in error for error in result.errors))

    def test_reordered_fields_fail(self):
        lines = self.xml.splitlines()
        image_index = next(i for i, line in enumerate(lines) if '<field name="win.eventdata.image"' in line)
        command_index = next(i for i, line in enumerate(lines) if '<field name="win.eventdata.commandLine"' in line)
        lines[image_index], lines[command_index] = lines[command_index], lines[image_index]
        result = self.validate_temporary_xml("\n".join(lines) + "\n")
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("field order" in error for error in result.errors))

    def test_missing_description_fails(self):
        line = next(line for line in self.xml.splitlines() if "<description>" in line)
        result = self.validate_temporary_xml(self.xml.replace(line + "\n", "", 1))
        self.assertIs(result.status, StructuralStatus.FAIL)
        self.assertTrue(any("description" in error for error in result.errors))

    def test_dtd_and_entity_declarations_are_rejected_without_parsing(self):
        xml = '<!DOCTYPE group [<!ENTITY ext SYSTEM "file:///never-read">]>\n' + self.xml
        result = self.validate_temporary_xml(xml)
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertIsNone(result.metadata)
        self.assertTrue(any("DTD and entity" in error for error in result.errors))

    def test_utf16_input_is_rejected_before_entity_parsing(self):
        xml = '<!DOCTYPE group [<!ENTITY ext SYSTEM "file:///never-read">]>\n' + self.xml
        result = self.validate_temporary_bytes(xml.encode("utf-16"))
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertIsNone(result.metadata)
        self.assertTrue(any("NUL bytes" in error for error in result.errors))

    def test_structural_pass_keeps_wazuh_engine_not_run(self):
        structural = validate_detection_001_xml(self.RULE_PATH)
        report = ValidationReport(
            rule=structural.metadata,
            cases=(),
            structural_validation=structural,
        )
        self.assertIs(structural.status, StructuralStatus.PASS)
        self.assertIs(report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)

    def test_missing_file_returns_error_without_side_effects(self):
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "not-present.xml"
            result = validate_detection_001_xml(missing)
            self.assertIs(result.status, StructuralStatus.ERROR)
            self.assertTrue(result.errors)

    def test_unc_path_is_rejected_before_file_access(self):
        result = validate_detection_001_xml(r"\\server\share\rule.xml")
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertTrue(any("Network/UNC" in error for error in result.errors))

    def test_mapped_network_drive_is_rejected_before_attribute_or_file_access(self):
        if os.name != "nt":
            self.skipTest("Mapped drive checks are Windows-specific.")
        with patch("detection_validation.loader._get_windows_drive_type", return_value=4), patch(
            "detection_validation.loader._get_windows_attributes",
            side_effect=AssertionError("attributes must not be queried for a remote drive"),
        ), patch.object(Path, "open", side_effect=AssertionError("remote path must not be opened")):
            result = validate_detection_001_xml(r"Z:\synthetic\rule.xml")
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertTrue(any("network-drive" in error for error in result.errors))

    def test_local_symlink_to_unc_target_is_rejected_without_opening_target(self):
        with TemporaryDirectory() as directory:
            link = Path(directory) / "rule-link.xml"
            self._make_file_symlink_or_skip(r"\\server\share\rule.xml", link)
            with patch.object(Path, "open", side_effect=AssertionError("symlink target must not be opened")):
                result = validate_detection_001_xml(link)
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertTrue(any("Symlink or reparse-point" in error for error in result.errors))

    def test_directory_reparse_point_to_unc_target_is_rejected_without_opening_child(self):
        with TemporaryDirectory() as directory:
            link = Path(directory) / "remote-directory"
            self._make_directory_symlink_or_skip(r"\\server\share", link)
            child = link / "rule.xml"
            with patch.object(Path, "open", side_effect=AssertionError("reparse target must not be opened")):
                result = validate_detection_001_xml(child)
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertTrue(any("Symlink or reparse-point" in error for error in result.errors))

    def test_inconclusive_component_check_fails_closed_before_open(self):
        if os.name != "nt":
            self.skipTest("Windows reparse attribute checks are Windows-specific.")
        with patch("detection_validation.loader._get_windows_drive_type", return_value=3), patch(
            "detection_validation.loader._get_windows_attributes", return_value=None
        ), patch.object(Path, "open", side_effect=AssertionError("unverified path must not be opened")):
            result = validate_detection_001_xml(self.RULE_PATH)
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertTrue(any("Unable to verify" in error for error in result.errors))

    def test_directory_is_an_unreadable_xml_input(self):
        with TemporaryDirectory() as directory:
            result = validate_detection_001_xml(Path(directory))
        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertTrue(result.errors)

    def test_exact_size_limit_is_read_and_parsed_normally(self):
        original = self.RULE_PATH.read_bytes()
        self.assertLessEqual(len(original), 1_048_576)
        content = original + b" " * (1_048_576 - len(original))
        result = self.validate_temporary_bytes(content)
        self.assertIs(result.status, StructuralStatus.PASS)

    def test_oversized_xml_is_rejected_after_only_one_bounded_read(self):
        original = self.RULE_PATH.read_bytes()
        content = original + b" " * (1_048_576 + 100 - len(original))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.xml"
            path.write_bytes(content)
            original_open = Path.open
            read_sizes = []
            positions = []

            class TrackingReader:
                def __init__(self, wrapped):
                    self.wrapped = wrapped

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    self.wrapped.close()

                def read(self, size=-1):
                    read_sizes.append(size)
                    result = self.wrapped.read(size)
                    positions.append(self.wrapped.tell())
                    return result

            def tracking_open(target, *args, **kwargs):
                return TrackingReader(original_open(target, *args, **kwargs))

            with patch.object(Path, "open", tracking_open):
                result = validate_detection_001_xml(path)

        self.assertIs(result.status, StructuralStatus.ERROR)
        self.assertTrue(any("1 MiB safety limit" in error for error in result.errors))
        self.assertEqual(read_sizes, [1_048_577])
        self.assertEqual(positions, [1_048_577])


class Detection001ApproximationRunnerTests(unittest.TestCase):
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    MANIFEST_PATH = PROJECT_ROOT / "tests" / "fixtures" / "detection-001-cases.json"
    RULE_PATH = PROJECT_ROOT / "wazuh" / "custom-rules" / "100100-suspicious-powershell.xml"

    @classmethod
    def setUpClass(cls):
        cls.original_manifest_bytes = cls.MANIFEST_PATH.read_bytes()
        cls.original_manifest = json.loads(cls.original_manifest_bytes)
        cls.structural = validate_detection_001_xml(cls.RULE_PATH)

    def run_with_manifest_data(self, data):
        with TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            return run_manifest_approximation(
                manifest_path,
                self.RULE_PATH,
                self.structural,
            )

    def test_all_40_manifest_cases_have_ordered_explicit_results(self):
        rule, cases = load_manifest(self.MANIFEST_PATH)
        report = run_manifest_approximation(self.MANIFEST_PATH, self.RULE_PATH, self.structural)

        self.assertEqual(len(cases), 40)
        self.assertEqual(len(report.approximation_results), 40)
        self.assertEqual(
            [case.case_id for case in report.cases],
            [result.case_id for result in report.approximation_results],
        )
        self.assertEqual(report.rule, rule)
        self.assertTrue(all(result.status is ApproximationCaseStatus.PASS for result in report.approximation_results))
        self.assertIs(report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)

    def test_positive_negative_and_false_positive_context_expectations(self):
        report = run_manifest_approximation(self.MANIFEST_PATH, self.RULE_PATH, self.structural)
        cases = {case.case_id: case for case in report.cases}
        results = {result.case_id: result for result in report.approximation_results}
        counts = {category: sum(case.category.value == category for case in cases.values()) for category in (
            "positive", "negative", "false_positive_context"
        )}
        self.assertEqual(counts, {"positive": 27, "negative": 10, "false_positive_context": 3})
        for case_id, case in cases.items():
            result = results[case_id]
            if case.category is CaseCategory.NEGATIVE:
                self.assertIs(result.observed.observation, ApproximationObservation.NO_MATCH, case_id)
            else:
                self.assertIs(result.observed.observation, ApproximationObservation.MATCH, case_id)
            if case.category is CaseCategory.FALSE_POSITIVE_CONTEXT:
                self.assertIs(case.expected.match_status, ExpectedMatchStatus.MATCH)
                self.assertIs(result.status, ApproximationCaseStatus.PASS)

    def test_group_mismatch_is_a_no_match_for_the_supplied_group_metadata(self):
        changed = copy.deepcopy(self.original_manifest)
        changed["cases"][0]["synthetic_event"]["groups"] = ["sysmon_event3"]
        report = self.run_with_manifest_data(changed)
        result = report.approximation_results[0]
        self.assertEqual(result.case_id, "P1")
        self.assertIs(result.observed.observation, ApproximationObservation.NO_MATCH)
        self.assertEqual(result.status, ApproximationCaseStatus.FAIL)
        self.assertTrue(any("if_group=sysmon_event1" in item for item in result.observed.unmatched_conditions))

    def test_event_field_expression_mismatch_is_reported_not_suppressed(self):
        changed = copy.deepcopy(self.original_manifest)
        changed["cases"][0]["synthetic_event"]["win.eventdata.image"] = r"C:\Windows\System32\cmd.exe"
        report = self.run_with_manifest_data(changed)
        result = report.approximation_results[0]
        self.assertIs(result.observed.observation, ApproximationObservation.NO_MATCH)
        self.assertTrue(any("win.eventdata.image" in item for item in result.observed.unmatched_conditions))
        self.assertIs(result.status, ApproximationCaseStatus.FAIL)

    def test_missing_required_event_field_rejects_manifest_without_partial_report(self):
        changed = copy.deepcopy(self.original_manifest)
        del changed["cases"][0]["synthetic_event"]["win.eventdata.commandLine"]
        with self.assertRaisesRegex(ManifestValidationError, "missing required fields"):
            self.run_with_manifest_data(changed)

    def test_duplicate_or_missing_documented_case_id_rejects_manifest(self):
        duplicate = copy.deepcopy(self.original_manifest)
        duplicate["cases"][1]["case_id"] = duplicate["cases"][0]["case_id"]
        with self.assertRaisesRegex(ManifestValidationError, "Duplicate case ID"):
            self.run_with_manifest_data(duplicate)

        incomplete = copy.deepcopy(self.original_manifest)
        incomplete["cases"].pop()
        with self.assertRaisesRegex(ManifestValidationError, "inventory is incomplete"):
            self.run_with_manifest_data(incomplete)

    def test_unexpected_case_id_rejects_manifest(self):
        changed = copy.deepcopy(self.original_manifest)
        changed["cases"][0]["case_id"] = "UNEXPECTED"
        with self.assertRaisesRegex(ManifestValidationError, "unexpected IDs: UNEXPECTED"):
            self.run_with_manifest_data(changed)

    def test_invalid_and_unsupported_regex_expressions_are_explicit(self):
        with self.assertRaisesRegex(ValueError, "Invalid Python regex"):
            _compile_field_expressions({"synthetic.field": "["})
        with self.assertRaises(_UnsupportedExpression):
            _compile_field_expressions({"synthetic.field": r"(?R)"})
        with self.assertRaises(_UnsupportedExpression):
            _compile_field_expressions({"synthetic.field": r"a*+"})

    def test_regex_subset_rejects_ordinary_capturing_groups(self):
        with self.assertRaisesRegex(_UnsupportedExpression, "capturing groups"):
            _compile_field_expressions({"synthetic.field": "(a)"})
        self.assertIn("synthetic.field", _compile_field_expressions({"synthetic.field": "(?:a)"}))

    def test_regex_subset_rejects_unescaped_wildcard_dot(self):
        with self.assertRaisesRegex(_UnsupportedExpression, "wildcard dots"):
            _compile_field_expressions({"synthetic.field": "a.b"})

    def test_regex_subset_keeps_escaped_and_character_class_dots_literal(self):
        escaped_dot = _compile_field_expressions({"synthetic.field": r"\."})["synthetic.field"]
        class_dot = _compile_field_expressions({"synthetic.field": "[.]"})["synthetic.field"]
        self.assertIsNotNone(escaped_dot.fullmatch("."))
        self.assertIsNone(escaped_dot.fullmatch("x"))
        self.assertIsNotNone(class_dot.fullmatch("."))
        self.assertIsNone(class_dot.fullmatch("x"))

    def test_regex_subset_tracks_escaped_backslashes_and_brackets_safely(self):
        literal_backslash_then_dot = _compile_field_expressions(
            {"synthetic.field": r"\\\."}
        )["synthetic.field"]
        self.assertIsNotNone(literal_backslash_then_dot.fullmatch("\\."))
        with self.assertRaises(_UnsupportedExpression):
            _compile_field_expressions({"synthetic.field": r"\\."})
        with self.assertRaises(_UnsupportedExpression):
            _compile_field_expressions({"synthetic.field": r"[\]]"})
        with self.assertRaises(_UnsupportedExpression):
            _compile_field_expressions({"synthetic.field": r"[\[]"})
        with self.assertRaisesRegex(ValueError, "Invalid Python regex"):
            _compile_field_expressions({"synthetic.field": "[a."})

    def test_unsupported_expression_marks_every_case_unsupported_not_pass(self):
        rule_root = ET.parse(self.RULE_PATH).getroot()
        rule_element = next(child for child in rule_root if child.tag == "rule")
        image_field = next(child for child in rule_element if child.tag == "field")
        image_field.text = "(?R)"

        # Isolate the runner's unsupported-expression result mapping. The real
        # structural validator rejects altered rule XML before this branch.
        with patch(
            "detection_validation.runner._rule_bytes_validation",
            return_value=(self.structural, rule_root),
        ):
            report = run_manifest_approximation(
                self.MANIFEST_PATH,
                self.RULE_PATH,
                self.structural,
            )

        self.assertEqual(len(report.approximation_results), 40)
        self.assertTrue(
            all(result.status is ApproximationCaseStatus.UNSUPPORTED for result in report.approximation_results)
        )
        self.assertTrue(
            all(result.observed.observation is ApproximationObservation.UNSUPPORTED for result in report.approximation_results)
        )
        self.assertFalse(
            any(result.status is ApproximationCaseStatus.PASS for result in report.approximation_results)
        )
        self.assertIs(report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)

    def test_structural_fail_prevents_all_case_evaluation(self):
        failed = StructuralValidationResult(StructuralStatus.FAIL, errors=("synthetic mismatch",))
        with patch(
            "detection_validation.runner._rule_bytes_validation",
            side_effect=AssertionError("XML must not be read after structural FAIL"),
        ):
            report = run_manifest_approximation(self.MANIFEST_PATH, self.RULE_PATH, failed)
        self.assertEqual(len(report.approximation_results), 40)
        self.assertTrue(all(result.status is ApproximationCaseStatus.NOT_RUN for result in report.approximation_results))
        self.assertTrue(all(result.observed.observation is ApproximationObservation.NOT_RUN for result in report.approximation_results))
        self.assertIs(report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)

    def test_structural_error_prevents_all_case_evaluation(self):
        error = StructuralValidationResult(StructuralStatus.ERROR, errors=("synthetic parse error",))
        with patch(
            "detection_validation.runner._rule_bytes_validation",
            side_effect=AssertionError("XML must not be read after structural ERROR"),
        ):
            report = run_manifest_approximation(self.MANIFEST_PATH, self.RULE_PATH, error)
        self.assertEqual(len(report.approximation_results), 40)
        self.assertTrue(all(result.status is ApproximationCaseStatus.NOT_RUN for result in report.approximation_results))

    def test_changed_rule_expression_is_freshly_structurally_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "changed-rule.xml"
            xml = self.RULE_PATH.read_text(encoding="utf-8").replace(r"(?i)(?:^|\\)", r"(?i)(?:^|/)", 1)
            path.write_text(xml, encoding="utf-8")
            report = run_manifest_approximation(self.MANIFEST_PATH, path, self.structural)
        self.assertIs(report.structural_validation.status, StructuralStatus.FAIL)
        self.assertEqual(len(report.approximation_results), 40)
        self.assertTrue(all(result.status is ApproximationCaseStatus.NOT_RUN for result in report.approximation_results))

    def test_manifest_and_frozen_synthetic_events_are_not_mutated(self):
        before = self.MANIFEST_PATH.read_bytes()
        report = run_manifest_approximation(self.MANIFEST_PATH, self.RULE_PATH, self.structural)
        self.assertEqual(self.MANIFEST_PATH.read_bytes(), before)
        event = report.cases[0].synthetic_event
        self.assertIsInstance(event["groups"], tuple)
        with self.assertRaises(TypeError):
            event["groups"][0] = "changed"
        with self.assertRaises(TypeError):
            event["win.eventdata.image"] = "changed"
        self.assertEqual(self.MANIFEST_PATH.read_bytes(), self.original_manifest_bytes)

    def test_successful_run_keeps_wazuh_engine_not_run_and_reports_approximation_limit(self):
        report = run_manifest_approximation(self.MANIFEST_PATH, self.RULE_PATH, self.structural)
        self.assertIs(report.structural_validation.status, StructuralStatus.PASS)
        self.assertIs(report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)
        self.assertTrue(any("do not establish PCRE2" in item for item in report.limitations))


class DetectionValidationFormattingTests(unittest.TestCase):
    MANIFEST_PATH = (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "fixtures"
        / "detection-001-cases.json"
    )
    RULE_PATH = (
        Path(__file__).resolve().parents[2]
        / "wazuh"
        / "custom-rules"
        / "100100-suspicious-powershell.xml"
    )

    @classmethod
    def setUpClass(cls):
        structural = validate_detection_001_xml(cls.RULE_PATH)
        cls.report = run_manifest_approximation(
            cls.MANIFEST_PATH, cls.RULE_PATH, structural
        )

    def test_json_complete_40_case_report_preserves_layers_and_order(self):
        rendered = format_json(self.report)
        payload = json.loads(rendered)
        self.assertEqual(payload["report_type"], "detection_validation_report")
        self.assertEqual(len(payload["cases"]), 40)
        self.assertEqual(len(payload["approximation_results"]), 40)
        self.assertEqual(
            [case["case_id"] for case in payload["cases"]],
            [case.case_id for case in self.report.cases],
        )
        self.assertEqual(
            payload["approximation_summary"]["category_counts"],
            {"positive": 27, "negative": 10, "false_positive_context": 3},
        )
        self.assertEqual(
            sum(payload["approximation_summary"]["category_counts"].values()), 40
        )
        self.assertEqual(payload["rule"]["rule_id"], "100100")
        self.assertEqual(payload["rule"]["field_names"], list(self.report.rule.field_names))
        self.assertEqual(payload["schema_version"], self.report.schema_version)
        self.assertEqual(payload["structural_validation"]["status"], "pass")
        self.assertEqual(payload["wazuh_engine"]["status"], "not_run")
        self.assertIsNone(payload["wazuh_engine"]["version"])
        self.assertEqual(payload["deployment_status"], "NOT_PERFORMED_BY_THIS_WORKFLOW")
        self.assertIn("Python re", payload["validation_layers"]["python_approximation"])
        self.assertTrue(any("PCRE2" in limitation for limitation in payload["limitations"]))
        self.assertEqual(payload["cases"][0]["synthetic_event"]["groups"], ["sysmon_event1"])
        self.assertIn("analyst_review_context", payload["cases"][0])
        self.assertIn("rule_id", payload["cases"][0]["expected"])
        self.assertIn("level", payload["cases"][0]["expected"])
        self.assertEqual(
            set(payload["cases"][0]),
            {"case_id", "category", "synthetic_event", "expected", "rationale", "analyst_review_context"},
        )
        self.assertEqual(
            set(payload["approximation_results"][0]),
            {"case_id", "expected", "observed", "comparison_status"},
        )
        self.assertEqual(
            set(payload["approximation_results"][0]["observed"]),
            {"observation", "matched_conditions", "unmatched_conditions", "detail"},
        )
        self.assertEqual(payload["approximation_summary"]["missing_result_count"], 0)

    def test_complete_report_category_counts_and_result_statuses(self):
        payload = json.loads(format_json(self.report))
        self.assertEqual(
            payload["approximation_summary"]["category_counts"],
            {
                "positive": 27,
                "negative": 10,
                "false_positive_context": 3,
            },
        )
        self.assertEqual(len(payload["cases"]), 40)
        self.assertEqual(payload["approximation_summary"]["result_count"], 40)

    def test_json_and_markdown_are_byte_deterministic(self):
        self.assertEqual(format_json(self.report), format_json(self.report))
        self.assertEqual(format_markdown(self.report), format_markdown(self.report))

    def test_json_recursively_serializes_immutable_mappings_and_tuples(self):
        source_event = dict(_event())
        source_event["nested"] = {"sequence": ["first", {"third": True}]}
        case = _case(event=source_event)
        custom_report = ValidationReport(
            self.report.rule, (case,), self.report.structural_validation
        )
        self.assertIsInstance(case.synthetic_event["groups"], tuple)
        self.assertIsInstance(case.synthetic_event["nested"]["sequence"], tuple)
        payload = json.loads(format_json(custom_report))
        serialized = payload["cases"][0]["synthetic_event"]
        self.assertIsInstance(serialized, dict)
        self.assertIsInstance(serialized["groups"], list)
        self.assertEqual(serialized["groups"], list(case.synthetic_event["groups"]))
        self.assertEqual(
            serialized["nested"],
            {"sequence": ["first", {"third": True}]},
        )

    def test_unsupported_json_values_are_rejected_explicitly(self):
        with self.assertRaisesRegex(TypeError, "unsupported JSON value type"):
            _json_value(object(), "$.synthetic")
        with self.assertRaisesRegex(ValueError, "non-finite"):
            _json_value(math.nan, "$.synthetic")

    def test_structural_fail_and_error_are_distinct_in_json_and_markdown(self):
        case = self.report.cases[0]
        fail_report = ValidationReport(
            self.report.rule,
            (case,),
            StructuralValidationResult(StructuralStatus.FAIL, errors=("Synthetic mismatch",)),
        )
        error_report = ValidationReport(
            self.report.rule,
            (case,),
            StructuralValidationResult(StructuralStatus.ERROR, errors=("Synthetic parse error",)),
        )
        self.assertEqual(json.loads(format_json(fail_report))["structural_validation"]["status"], "fail")
        self.assertEqual(json.loads(format_json(error_report))["structural_validation"]["status"], "error")
        self.assertIn("**FAIL**", format_markdown(fail_report))
        self.assertIn("**ERROR**", format_markdown(error_report))

    def test_unsupported_error_not_run_and_missing_results_are_never_pass(self):
        case = self.report.cases[0]
        no_match = _case("N1", CaseCategory.NEGATIVE, ExpectedOutcome(ExpectedMatchStatus.NO_MATCH))
        no_match_2 = _case("N2", CaseCategory.NEGATIVE, ExpectedOutcome(ExpectedMatchStatus.NO_MATCH))
        cases = (case, no_match, no_match_2)
        structural = self.report.structural_validation
        special_results = []
        for matching_case, observation, status, detail in (
            (case, ApproximationObservation.UNSUPPORTED, ApproximationCaseStatus.UNSUPPORTED, "Unsupported expression"),
            (no_match, ApproximationObservation.ERROR, ApproximationCaseStatus.ERROR, "Malformed expression"),
            (no_match_2, ApproximationObservation.NOT_RUN, ApproximationCaseStatus.NOT_RUN, "Not evaluated"),
        ):
            observed = ObservedApproximationOutcome(observation, detail=detail)
            special_results.append(
                PerCaseValidationResult(matching_case.case_id, matching_case.expected, observed, status)
            )
        partial = ValidationReport(
            self.report.rule,
            cases,
            structural,
            tuple(special_results),
        )
        payload = json.loads(format_json(partial))
        self.assertEqual(
            [item["comparison_status"] for item in payload["approximation_results"]],
            ["unsupported", "error", "not_run"],
        )
        self.assertNotIn("pass", [item["comparison_status"] for item in payload["approximation_results"]])
        markdown = format_markdown(partial)
        not_run_row = next(line for line in markdown.splitlines() if line.startswith("| N2 |"))
        self.assertIn(r"not\_run", not_run_row)
        self.assertNotIn(r"not\\\_run", not_run_row)
        missing = ValidationReport(self.report.rule, (case,), structural)
        missing_payload = json.loads(format_json(missing))
        self.assertEqual(missing_payload["approximation_summary"]["missing_result_case_ids"], [case.case_id])
        self.assertIn("MISSING_RESULT", format_markdown(missing))
        self.assertIn("result missing", format_markdown(missing))

    def test_wazuh_status_is_not_run_and_false_positive_context_is_not_suppressed(self):
        payload = json.loads(format_json(self.report))
        self.assertEqual(payload["wazuh_engine"]["status"], "not_run")
        markdown = format_markdown(self.report)
        self.assertIn("Wazuh Rule-Engine Status", markdown)
        self.assertIn("**NOT\_RUN**", markdown)
        self.assertIn("not a suppression instruction", markdown)
        fp_results = [
            result for result in self.report.approximation_results
            if next(case for case in self.report.cases if case.case_id == result.case_id).category
            is CaseCategory.FALSE_POSITIVE_CONTEXT
        ]
        self.assertTrue(fp_results)
        self.assertTrue(all(result.expected.match_status is ExpectedMatchStatus.MATCH for result in fp_results))

    def test_markdown_escapes_untrusted_text_and_omits_raw_event_data(self):
        original = self.report.cases[0]
        hostile = replace(
            original,
            rationale="# injected\n<script>alert(1)</script> | [link](https://invalid.example) ```",
            synthetic_event={
                **dict(original.synthetic_event),
                "win.eventdata.commandLine": "SECRET-SYNTHETIC-COMMAND-LINE",
            },
        )
        report = ValidationReport(
            self.report.rule,
            (hostile,),
            self.report.structural_validation,
            (),
        )
        markdown = format_markdown(report)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertIn("↵", markdown)
        self.assertIn("\\|", markdown)
        self.assertIn("\\`", markdown)
        self.assertNotIn("\n# injected", markdown)
        self.assertNotIn("SECRET-SYNTHETIC-COMMAND-LINE", markdown)
        self.assertNotIn("https://invalid.example", markdown)

    def test_markdown_contains_required_sections(self):
        markdown = format_markdown(self.report)
        for section in (
            "Rule Metadata",
            "Structural Validation",
            "Python Approximation",
            "Category Summary",
            "Approximation Result Counts",
            "Per-Case Results",
            "False-Positive Context",
            "Unsupported, Error, and Not-Run Cases",
            "Deployment Status",
            "Wazuh Rule-Engine Status",
            "Limitations and Analyst Interpretation",
        ):
            self.assertIn(f"## {section}", markdown)

    def test_formatting_does_not_mutate_report_or_event_data(self):
        case = self.report.cases[0]
        event_before = dict(case.synthetic_event)
        results_before = self.report.approximation_results
        format_json(self.report)
        format_markdown(self.report)
        self.assertEqual(dict(case.synthetic_event), event_before)
        self.assertEqual(self.report.approximation_results, results_before)


if __name__ == "__main__":
    unittest.main()
