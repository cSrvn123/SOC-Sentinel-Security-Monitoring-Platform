from __future__ import annotations

import json
import unittest

from incident_reporting import IncidentReport, IncidentReportCollection, add_attack_mapping
from incident_reporting.models import AnalystConclusion, EventProvenance, IncidentSeverity


def incident(*, related_events: list[object] | None = None,
             provenance: list[object] | None = None, **fields: object) -> IncidentReport:
    values: dict[str, object] = {
        "incident_id": "INC-SYNTHETIC-MAPPING",
        "schema_version": "1.0",
        "source_case_id": "SOC-SYNTHETIC-MAPPING",
        "title": "Synthetic correlation case",
        "confidence": "high",
        "confidence_explanation": "Synthetic correlation strength only.",
        "related_events": list(related_events or []),
        "provenance": list(provenance or []),
        "evidence": ["Synthetic event supports a possible PowerShell execution."],
    }
    values.update(fields)
    return IncidentReport(**values)  # type: ignore[arg-type]


class IncidentAttackMappingTests(unittest.TestCase):
    def test_mapping_list_is_empty_by_default_and_no_mapping_is_inferred(self) -> None:
        item = incident(
            title="Suspicious PowerShell encoded command",
            confidence="high",
            evidence=["Synthetic IOC reputation status=malicious; count=9."],
            recommendations=["Review the synthetic activity."],
        )

        self.assertEqual(item.mitre_attack_mappings, [])
        self.assertEqual(item.severity, IncidentSeverity.NOT_ASSESSED)
        self.assertEqual(item.analyst_conclusion, AnalystConclusion.NOT_ASSESSED)

    def test_valid_technique_and_subtechnique_ids_produce_canonical_dicts(self) -> None:
        item = incident(related_events=[{"event": {"event_id": 1}}])

        technique = add_attack_mapping(
            item,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            rationale="The referenced synthetic process event shows command-interpreter execution.",
            evidence_references=[0],
        )
        subtechnique = add_attack_mapping(
            item,
            technique_id="T1059.001",
            technique_name="PowerShell",
            rationale="The referenced synthetic event identifies PowerShell execution.",
            evidence_references=(0,),
        )

        self.assertEqual(
            list(technique),
            ["technique_id", "technique_name", "tactic", "rationale", "evidence_references", "reference_status"],
        )
        self.assertEqual(technique["technique_id"], "T1059")
        self.assertEqual(technique["tactic"], "Execution")
        self.assertIsNone(subtechnique["tactic"])
        self.assertEqual(subtechnique["technique_id"], "T1059.001")
        self.assertEqual(technique["reference_status"], "UNVERIFIED")
        self.assertEqual(subtechnique["reference_status"], "UNVERIFIED")
        self.assertIs(item.mitre_attack_mappings[0], technique)
        self.assertEqual(json.loads(json.dumps(item.mitre_attack_mappings)), item.mitre_attack_mappings)

    def test_malformed_technique_ids_and_unsupported_types_are_rejected(self) -> None:
        item = incident(related_events=[{}])
        common = {
            "technique_name": "Synthetic technique",
            "rationale": "Synthetic evidence supports this explicit test mapping.",
            "evidence_references": [0],
        }
        for invalid in ("t1059", "T105", "T10590", "T1059.", "T1059.01", "T1059.0001", " T1059"):
            with self.subTest(invalid_id=invalid):
                with self.assertRaises(ValueError):
                    add_attack_mapping(item, technique_id=invalid, **common)
        with self.assertRaises(TypeError):
            add_attack_mapping(item, technique_id=1059, **common)  # type: ignore[arg-type]
        self.assertEqual(item.mitre_attack_mappings, [])

    def test_required_text_fields_and_optional_tactic_are_validated(self) -> None:
        item = incident(related_events=[{}])
        args = {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "rationale": "Synthetic event evidence supports this mapping.",
            "evidence_references": [0],
        }
        for field_name, invalid in (
            ("technique_name", "  "),
            ("technique_name", None),
            ("rationale", ""),
            ("rationale", object()),
            ("tactic", "  "),
            ("tactic", 42),
        ):
            with self.subTest(field=field_name, invalid=repr(invalid)):
                with self.assertRaises((TypeError, ValueError)):
                    add_attack_mapping(item, **(args | {field_name: invalid}))  # type: ignore[arg-type]
        self.assertEqual(item.mitre_attack_mappings, [])

    def test_evidence_reference_list_and_indices_are_validated_without_partial_append(self) -> None:
        item = incident(related_events=[{}, {}])
        args = {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "rationale": "Synthetic evidence supports this mapping.",
        }
        invalid_references = (None, [], "0", {0}, [-1], [2], [True], [0, "1"])
        for invalid in invalid_references:
            with self.subTest(references=repr(invalid)):
                with self.assertRaises((TypeError, ValueError)):
                    add_attack_mapping(item, evidence_references=invalid, **args)  # type: ignore[arg-type]
                self.assertEqual(item.mitre_attack_mappings, [])

    def test_multiple_references_preserve_source_refs_and_conservative_provenance(self) -> None:
        raw_a = {"synthetic": "candidate-a"}
        raw_b = {"synthetic": "candidate-b"}
        item = incident(
            related_events=[
                {
                    "source_references": ["event-ref-a"],
                    "provenance_status": "matched",
                    "original_record": raw_a,
                    "original_record_candidates": [raw_a],
                },
                {
                    "source_references": ["event-ref-b"],
                    "provenance_status": "unavailable",
                    "original_record": None,
                    "original_record_candidates": [raw_a, raw_b],
                },
            ],
            provenance=[
                EventProvenance(0, ["aligned-ref-a"], "synthetic-id", "ambiguous", None, [raw_a, raw_b]),
                EventProvenance(1, ["aligned-ref-b"], None, "matched", raw_b, [raw_b]),
            ],
        )

        mapping = add_attack_mapping(
            item,
            technique_id="T1059.001",
            technique_name="PowerShell",
            rationale="Two explicitly referenced synthetic events support review of this technique.",
            evidence_references=[0, 1],
        )

        refs = mapping["evidence_references"]
        self.assertEqual([ref["related_event_index"] for ref in refs], [0, 1])
        self.assertEqual(refs[0]["source_references"], ["event-ref-a", "aligned-ref-a"])
        self.assertEqual(refs[0]["provenance_status"], "ambiguous")
        self.assertEqual(refs[1]["source_references"], ["event-ref-b", "aligned-ref-b"])
        self.assertEqual(refs[1]["provenance_status"], "unavailable")
        self.assertNotIn("original_record", refs[0])
        self.assertNotIn("original_record_candidates", refs[0])
        self.assertNotIn(raw_a, mapping["evidence_references"])
        self.assertNotIn(raw_b, mapping["evidence_references"])
        self.assertEqual(mapping["reference_status"], "UNVERIFIED")

    def test_mapping_addition_preserves_assessment_evidence_and_collection_context(self) -> None:
        raw = {"synthetic": "original-source"}
        item = incident(
            related_events=[{
                "source_references": ["synthetic-ref"],
                "provenance_status": "matched",
                "original_record": raw,
                "event": {"event_id": 1},
            }],
            provenance=[EventProvenance(0, ["synthetic-ref"], "identity", "matched", raw, [raw])],
            severity=IncidentSeverity.HIGH,
            analyst_conclusion=AnalystConclusion.BENIGN,
            severity_rationale="Synthetic severity reasoning.",
            analyst_conclusion_rationale="Synthetic conclusion reasoning.",
            timeline=[{"related_event_index": 0, "synthetic": True}],
            evidence=["Synthetic evidence remains unchanged."],
        )
        metadata = {"source_type": "synthetic", "batch": [1]}
        collection = IncidentReportCollection(
            incidents=[item],
            diagnostics=["Synthetic diagnostic."],
            skipped_events=[{"reason": "synthetic skip"}],
            original_input_records=[raw],
            collection_metadata=metadata,
        )
        before = {
            "severity": item.severity,
            "conclusion": item.analyst_conclusion,
            "severity_rationale": item.severity_rationale,
            "conclusion_rationale": item.analyst_conclusion_rationale,
            "confidence": item.confidence,
            "evidence": list(item.evidence),
            "timeline": list(item.timeline),
            "provenance": list(item.provenance),
            "source_references": list(item.provenance[0].source_references),
            "diagnostics": list(collection.diagnostics),
            "skipped_events": list(collection.skipped_events),
            "metadata": collection.collection_metadata,
        }

        add_attack_mapping(
            item,
            technique_id="T1059.001",
            technique_name="PowerShell",
            rationale="The explicitly referenced synthetic event supports this mapping.",
            evidence_references=[0],
        )

        self.assertEqual(item.severity, before["severity"])
        self.assertEqual(item.analyst_conclusion, before["conclusion"])
        self.assertEqual(item.severity_rationale, before["severity_rationale"])
        self.assertEqual(item.analyst_conclusion_rationale, before["conclusion_rationale"])
        self.assertEqual(item.confidence, before["confidence"])
        self.assertEqual(item.evidence, before["evidence"])
        self.assertEqual(item.timeline, before["timeline"])
        self.assertEqual(item.provenance, before["provenance"])
        self.assertEqual(item.provenance[0].source_references, before["source_references"])
        self.assertEqual(collection.diagnostics, before["diagnostics"])
        self.assertEqual(collection.skipped_events, before["skipped_events"])
        self.assertIs(collection.collection_metadata, before["metadata"])
        self.assertIs(collection.original_input_records[0], raw)


if __name__ == "__main__":
    unittest.main()
