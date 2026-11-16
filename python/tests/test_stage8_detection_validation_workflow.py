"""End-to-end coverage for the local Detection 001 validation workflow."""

import json
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path

from detection_validation import (
    ApproximationCaseStatus,
    ApproximationObservation,
    CaseCategory,
    ExpectedMatchStatus,
    ObservedApproximationOutcome,
    PerCaseValidationResult,
    StructuralStatus,
    StructuralValidationResult,
    WazuhEngineStatus,
    format_json,
    format_markdown,
    load_manifest,
    run_manifest_approximation,
    validate_detection_001_xml,
)


class Detection001EndToEndWorkflowTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]
    MANIFEST_PATH = ROOT / "tests" / "fixtures" / "detection-001-cases.json"
    RULE_PATH = ROOT / "wazuh" / "custom-rules" / "100100-suspicious-powershell.xml"

    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes_before = cls.MANIFEST_PATH.read_bytes()
        cls.rule_xml_bytes_before = cls.RULE_PATH.read_bytes()

        # Exercise the public workflow in order: manifest, structure, approximation,
        # then the two public formatters. All command-line fields remain inert data.
        cls.rule, cls.cases = load_manifest(cls.MANIFEST_PATH)
        cls.structural = validate_detection_001_xml(cls.RULE_PATH)
        cls.report = run_manifest_approximation(
            cls.MANIFEST_PATH,
            cls.RULE_PATH,
            cls.structural,
        )
        cls.json_text = format_json(cls.report)
        cls.json_report = json.loads(cls.json_text)
        cls.markdown_text = format_markdown(cls.report)

    def test_complete_pipeline_has_all_cases_and_expected_category_results(self):
        self.assertEqual(self.structural.status, StructuralStatus.PASS)
        self.assertEqual(len(self.cases), 40)
        self.assertEqual(len({case.case_id for case in self.cases}), 40)
        self.assertEqual(len(self.report.approximation_results), 40)

        case_ids = [case.case_id for case in self.cases]
        self.assertEqual([case.case_id for case in self.report.cases], case_ids)
        self.assertEqual(
            [result.case_id for result in self.report.approximation_results],
            case_ids,
        )
        self.assertEqual(
            Counter(case.category for case in self.cases),
            {
                CaseCategory.POSITIVE: 27,
                CaseCategory.NEGATIVE: 10,
                CaseCategory.FALSE_POSITIVE_CONTEXT: 3,
            },
        )

        cases_by_id = {case.case_id: case for case in self.cases}
        results_by_id = {
            result.case_id: result for result in self.report.approximation_results
        }
        self.assertEqual(set(results_by_id), set(cases_by_id))
        self.assertTrue(
            all(result.status is ApproximationCaseStatus.PASS for result in results_by_id.values())
        )
        for case_id, case in cases_by_id.items():
            observed = results_by_id[case_id].observed.observation
            if case.category is CaseCategory.NEGATIVE:
                self.assertEqual(case.expected.match_status, ExpectedMatchStatus.NO_MATCH)
                self.assertEqual(observed, ApproximationObservation.NO_MATCH)
            else:
                self.assertEqual(case.expected.match_status, ExpectedMatchStatus.MATCH)
                self.assertEqual(observed, ApproximationObservation.MATCH)

        false_positive_results = [
            results_by_id[case.case_id]
            for case in self.cases
            if case.category is CaseCategory.FALSE_POSITIVE_CONTEXT
        ]
        self.assertEqual(len(false_positive_results), 3)
        self.assertTrue(
            all(result.expected.match_status is ExpectedMatchStatus.MATCH for result in false_positive_results)
        )
        self.assertEqual(self.report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)

    def test_json_markdown_are_consistent_about_rule_cases_and_layers(self):
        payload = self.json_report
        self.assertEqual(payload["rule"]["rule_id"], self.rule.rule_id)
        self.assertEqual(payload["rule"]["level"], self.rule.level)
        self.assertEqual(payload["structural_validation"]["status"], "pass")
        self.assertEqual(payload["approximation_summary"]["manifest_case_count"], 40)
        self.assertEqual(payload["approximation_summary"]["result_count"], 40)
        self.assertEqual(payload["approximation_summary"]["missing_result_count"], 0)
        self.assertEqual(
            payload["approximation_summary"]["category_counts"],
            {"false_positive_context": 3, "negative": 10, "positive": 27},
        )
        self.assertEqual(payload["approximation_summary"]["comparison_status_counts"]["pass"], 40)
        self.assertEqual(payload["approximation_summary"]["unsupported_count"], 0)
        self.assertEqual(payload["approximation_summary"]["error_count"], 0)
        self.assertEqual(payload["approximation_summary"]["not_run_count"], 0)
        self.assertEqual(payload["approximation_summary"]["missing_result_case_ids"], [])
        self.assertEqual(payload["deployment_status"], "NOT_PERFORMED_BY_THIS_WORKFLOW")
        self.assertEqual(payload["wazuh_engine"]["status"], "not_run")

        markdown = self.markdown_text
        self.assertIn("## Structural Validation", markdown)
        self.assertIn("**PASS**", markdown)
        self.assertIn("## Python Approximation", markdown)
        self.assertIn("Python `re` is not PCRE2", markdown)
        self.assertIn("27", markdown)
        self.assertIn("10", markdown)
        self.assertIn("false\\_positive\\_context", markdown)
        self.assertIn("| positive | 27 |", markdown)
        self.assertIn("| negative | 10 |", markdown)
        self.assertIn("| false\\_positive\\_context | 3 |", markdown)
        self.assertIn("| pass | 40 |", markdown)
        self.assertIn("40", markdown)
        self.assertIn("not a suppression instruction", markdown)
        self.assertIn("NOT PERFORMED BY THIS WORKFLOW", markdown)
        self.assertIn("## Wazuh Rule-Engine Status", markdown)
        self.assertIn("**NOT\\_RUN**", markdown)

        json_results = {item["case_id"]: item for item in payload["approximation_results"]}
        markdown_rows = {
            line.split(" | ", 1)[0][2:]: line
            for line in markdown.splitlines()
            if line.startswith("| ") and not line.startswith("|---")
        }
        for case in self.cases:
            result = json_results[case.case_id]
            row = markdown_rows[case.case_id]
            self.assertIn(result["observed"]["observation"].replace("_", r"\_"), row)
            self.assertIn(result["comparison_status"], row)
            self.assertIn(case.expected.match_status.value.replace("_", r"\_"), row)

    def test_repeated_formatting_is_deterministic_and_does_not_mutate_inputs(self):
        json_again = format_json(self.report)
        markdown_again = format_markdown(self.report)
        self.assertEqual(self.json_text, json_again)
        self.assertEqual(self.markdown_text, markdown_again)
        self.assertEqual(self.MANIFEST_PATH.read_bytes(), self.manifest_bytes_before)
        self.assertEqual(self.RULE_PATH.read_bytes(), self.rule_xml_bytes_before)

        event = self.report.cases[0].synthetic_event
        self.assertIsInstance(event["groups"], tuple)
        with self.assertRaises(TypeError):
            event["win.eventdata.image"] = "modified"
        with self.assertRaises(AttributeError):
            event["groups"].append("modified")
        self.assertEqual(self.MANIFEST_PATH.read_bytes(), self.manifest_bytes_before)
        self.assertEqual(self.RULE_PATH.read_bytes(), self.rule_xml_bytes_before)

    def test_structural_fail_and_error_produce_only_not_run_approximation_results(self):
        for status in (StructuralStatus.FAIL, StructuralStatus.ERROR):
            with self.subTest(status=status.value):
                structural = StructuralValidationResult(
                    status=status,
                    errors=(f"Synthetic structural {status.value} fixture",),
                )
                report = run_manifest_approximation(
                    self.MANIFEST_PATH,
                    self.RULE_PATH,
                    structural,
                )
                self.assertEqual(len(report.approximation_results), 40)
                self.assertTrue(
                    all(
                        result.status is ApproximationCaseStatus.NOT_RUN
                        and result.observed.observation is ApproximationObservation.NOT_RUN
                        for result in report.approximation_results
                    )
                )
                self.assertEqual(report.wazuh_engine_status, WazuhEngineStatus.NOT_RUN)
                payload = json.loads(format_json(report))
                self.assertEqual(payload["structural_validation"]["status"], status.value)
                self.assertEqual(payload["approximation_summary"]["not_run_count"], 40)
                self.assertNotEqual(payload["approximation_summary"]["comparison_status_counts"]["pass"], 40)
                self.assertIn(status.value.upper(), format_markdown(report))

    def test_missing_result_is_not_presented_as_complete_success(self):
        incomplete = replace(
            self.report,
            approximation_results=self.report.approximation_results[:-1],
        )
        payload = json.loads(format_json(incomplete))
        self.assertEqual(payload["approximation_summary"]["manifest_case_count"], 40)
        self.assertEqual(payload["approximation_summary"]["result_count"], 39)
        self.assertEqual(payload["approximation_summary"]["missing_result_count"], 1)
        self.assertEqual(
            payload["approximation_summary"]["missing_result_case_ids"],
            [self.cases[-1].case_id],
        )
        self.assertEqual(payload["approximation_summary"]["comparison_status_counts"]["pass"], 39)
        markdown = format_markdown(incomplete)
        self.assertIn("MISSING_RESULT", markdown)
        self.assertIn("result missing", markdown)

    def test_unsupported_error_and_not_run_states_agree_across_outputs(self):
        positive = next(case for case in self.cases if case.category is CaseCategory.POSITIVE)
        negative_cases = [
            case for case in self.cases if case.category is CaseCategory.NEGATIVE
        ][:2]
        selected = (positive, *negative_cases)
        results = (
            PerCaseValidationResult(
                positive.case_id,
                positive.expected,
                ObservedApproximationOutcome(
                    ApproximationObservation.UNSUPPORTED,
                    detail="Unsupported expression fixture.",
                ),
                ApproximationCaseStatus.UNSUPPORTED,
            ),
            PerCaseValidationResult(
                negative_cases[0].case_id,
                negative_cases[0].expected,
                ObservedApproximationOutcome(
                    ApproximationObservation.ERROR,
                    detail="Malformed expression fixture.",
                ),
                ApproximationCaseStatus.ERROR,
            ),
            PerCaseValidationResult(
                negative_cases[1].case_id,
                negative_cases[1].expected,
                ObservedApproximationOutcome(
                    ApproximationObservation.NOT_RUN,
                    detail="Case was not evaluated.",
                ),
                ApproximationCaseStatus.NOT_RUN,
            ),
        )
        report = replace(
            self.report,
            cases=selected,
            approximation_results=results,
        )
        payload = json.loads(format_json(report))
        json_by_id = {item["case_id"]: item for item in payload["approximation_results"]}
        markdown_rows = {
            line.split(" | ", 1)[0][2:]: line
            for line in format_markdown(report).splitlines()
            if line.startswith("| ") and not line.startswith("|---")
        }
        for result in results:
            serialized = json_by_id[result.case_id]
            row = markdown_rows[result.case_id]
            self.assertEqual(serialized["comparison_status"], result.status.value)
            self.assertEqual(serialized["observed"]["observation"], result.observed.observation.value)
            markdown_status = result.status.value.replace("_", r"\_")
            markdown_observation = result.observed.observation.value.replace("_", r"\_")
            self.assertIn(markdown_status, row)
            self.assertIn(markdown_observation, row)
            if "_" in result.status.value:
                self.assertNotIn(result.status.value.replace("_", r"\\\_"), row)
            if "_" in result.observed.observation.value:
                self.assertNotIn(
                    result.observed.observation.value.replace("_", r"\\\_"),
                    row,
                )
        self.assertEqual(payload["approximation_summary"]["unsupported_count"], 1)
        self.assertEqual(payload["approximation_summary"]["error_count"], 1)
        self.assertEqual(payload["approximation_summary"]["not_run_count"], 1)
        markdown = format_markdown(report)
        self.assertIn("Unsupported, Error, and Not-Run Cases", markdown)
        self.assertIn("Unsupported expression fixture", markdown)
        self.assertIn("Malformed expression fixture", markdown)
        self.assertIn("Case was not evaluated", markdown)


if __name__ == "__main__":
    unittest.main()
