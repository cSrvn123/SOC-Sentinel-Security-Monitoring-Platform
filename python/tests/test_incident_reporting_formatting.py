from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum
from typing import Any

from incident_reporting import (
    AnalystConclusion,
    EventProvenance,
    IncidentEntities,
    IncidentReport,
    IncidentReportCollection,
    IncidentSeverity,
    format_json,
    format_markdown,
)
from incident_reporting.timeline import TimelineEntry


def make_incident(**overrides: Any) -> IncidentReport:
    values: dict[str, Any] = {
        "incident_id": "INC-SYN-001",
        "schema_version": "1.0",
        "source_case_id": "CASE-SYN-001",
        "title": "Synthetic incident",
        "confidence": "medium",
        "confidence_explanation": "Synthetic correlation only.",
    }
    values.update(overrides)
    return IncidentReport(**values)


def resolve_json_path(document: Any, path: str) -> Any:
    """Navigate the formatter's bracket-notation marker path in parsed JSON."""
    if not path.startswith("$"):
        raise AssertionError(f"JSON path must start with '$': {path!r}")
    current = document
    position = 1
    while position < len(path):
        if path[position] != "[":
            raise AssertionError(f"Expected '[' at offset {position}: {path!r}")
        token_start = position + 1
        if token_start < len(path) and path[token_start] == '"':
            cursor = token_start + 1
            escaped = False
            while cursor < len(path):
                char = path[cursor]
                if char == '"' and not escaped:
                    break
                if char == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
                cursor += 1
            if cursor >= len(path):
                raise AssertionError(f"Unterminated JSON object key in path: {path!r}")
            key = json.loads(path[token_start:cursor + 1])
            current = current[key]
            position = cursor + 1
        else:
            cursor = path.index("]", token_start)
            current = current[int(path[token_start:cursor])]
            position = cursor
        if position >= len(path) or path[position] != "]":
            raise AssertionError(f"Expected ']' at offset {position}: {path!r}")
        position += 1
    return current


class IncidentReportingFormatterTests(unittest.TestCase):
    def test_standalone_incident_is_json_incident_and_preserves_all_fields(self) -> None:
        raw = {"event": {"Image": "C:\\synthetic\\app.exe", "note": "synthetic"}}
        incident = make_incident(
            related_events=[{"event": {"timestamp": "2026-01-01T00:00:00+05:30"}}],
            timeline=[TimelineEntry(
                original_timestamp="2026-01-01T00:00:00+05:30",
                normalized_timestamp_utc="2025-12-31T18:30:00+00:00",
                timestamp_status="valid",
                related_event_index=0,
                source_references=["synthetic:record:1"],
                provenance_status="matched",
            )],
            entities=IncidentEntities(accounts=["synthetic-user"], computers=["synthetic-host"], ips=["192.0.2.10"]),
            evidence=["synthetic evidence"],
            provenance=[EventProvenance(
                related_event_index=0,
                source_references=["synthetic:record:1"],
                provenance_status="matched",
                original_record=raw,
            )],
            missing_evidence=["synthetic missing evidence"],
            recommendations=["review synthetic record"],
            evidence_limitations=["synthetic limitation"],
            analyst_conclusion=AnalystConclusion.INCONCLUSIVE,
            severity=IncidentSeverity.MEDIUM,
            mitre_attack_mappings=[{
                "technique_id": "T1059.001",
                "technique_name": "Synthetic technique",
                "tactic": None,
                "rationale": "Synthetic rationale",
                "evidence_references": [{"related_event_index": 0, "source_references": ["synthetic:record:1"], "provenance_status": "matched"}],
                "reference_status": "UNVERIFIED",
            }],
            analyst_conclusion_rationale="Synthetic conclusion rationale",
            severity_rationale="Synthetic severity rationale",
        )

        payload = json.loads(format_json(incident))
        self.assertNotIn("incidents", payload)
        self.assertEqual(payload["incident_id"], incident.incident_id)
        self.assertEqual(payload["confidence"], "medium")
        self.assertEqual(payload["severity"], "MEDIUM")
        self.assertEqual(payload["analyst_conclusion"], "INCONCLUSIVE")
        self.assertEqual(payload["severity_rationale"], "Synthetic severity rationale")
        self.assertEqual(payload["analyst_conclusion_rationale"], "Synthetic conclusion rationale")
        self.assertEqual(payload["related_events"][0]["event"]["timestamp"], "2026-01-01T00:00:00+05:30")
        self.assertEqual(payload["timeline"][0]["original_timestamp"], "2026-01-01T00:00:00+05:30")
        self.assertEqual(payload["timeline"][0]["normalized_timestamp_utc"], "2025-12-31T18:30:00+00:00")
        self.assertEqual(payload["mitre_attack_mappings"], incident.mitre_attack_mappings)
        self.assertEqual(payload["provenance"][0]["original_record"], raw)

    def test_explicit_null_optional_fields_are_preserved(self) -> None:
        payload = json.loads(format_json(make_incident()))
        self.assertIsNone(payload["severity_rationale"])
        self.assertIsNone(payload["analyst_conclusion_rationale"])
        self.assertEqual(payload["severity"], "NOT_ASSESSED")
        self.assertEqual(payload["analyst_conclusion"], "NOT_ASSESSED")
        self.assertEqual(payload["mitre_attack_mappings"], [])

    def test_collection_preserves_collection_fields_once_at_collection_level(self) -> None:
        raw = {"synthetic-record": "batch"}
        incident = make_incident(provenance=[EventProvenance(0, original_record=raw)])
        collection = IncidentReportCollection(
            schema_version="1.0",
            incidents=[incident],
            diagnostics=[{"message": "synthetic diagnostic"}],
            skipped_events=[{"event_index": 4, "reason": "synthetic missing timestamp"}],
            original_input_records=[raw],
            collection_metadata={"batch": "synthetic-batch"},
        )
        payload = json.loads(format_json(collection))
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["diagnostics"], collection.diagnostics)
        self.assertEqual(payload["skipped_events"], collection.skipped_events)
        self.assertEqual(payload["original_input_records"], [raw])
        self.assertEqual(payload["collection_metadata"], collection.collection_metadata)
        self.assertNotIn("original_input_records", payload["incidents"][0])
        self.assertEqual(payload["incidents"][0]["provenance"][0]["original_record"], raw)

    def test_multiple_and_empty_collections_are_valid_deterministic_json(self) -> None:
        first = make_incident(incident_id="INC-A", source_case_id="CASE-A")
        second = make_incident(incident_id="INC-B", source_case_id="CASE-B")
        many = IncidentReportCollection(incidents=[first, second])
        empty = IncidentReportCollection()
        self.assertEqual(json.loads(format_json(many))["incidents"][1]["incident_id"], "INC-B")
        self.assertEqual(json.loads(format_json(empty))["incidents"], [])
        self.assertEqual(format_json(many), format_json(many))

    def test_json_serializes_enums_dataclasses_and_structured_objects(self) -> None:
        @dataclass
        class Detail:
            name: str
            count: int

        class Ordinary:
            def __init__(self) -> None:
                self.label = "synthetic-object"
                self.detail = Detail("nested", 3)

        payload = json.loads(format_json(make_incident(evidence=[IncidentSeverity.HIGH, AnalystConclusion.BENIGN, Detail("d", 2), Ordinary()])))
        self.assertEqual(payload["evidence"][0], "HIGH")
        self.assertEqual(payload["evidence"][1], "BENIGN")
        self.assertEqual(payload["evidence"][2]["$fields"], {"name": "d", "count": 2})
        self.assertEqual(payload["evidence"][3]["$attributes"]["label"], "synthetic-object")
        self.assertEqual(payload["evidence"][3]["$attributes"]["detail"]["$fields"]["count"], 3)

    def test_json_marks_cycles_but_serializes_shared_references_twice(self) -> None:
        shared = {"value": "synthetic"}
        circular: list[Any] = []
        circular.append(circular)
        evidence = {"left": shared, "right": shared, "cycle": circular}
        payload = json.loads(format_json(make_incident(evidence=[evidence])))
        tree = payload["evidence"][0]
        self.assertEqual(tree["left"], tree["right"])
        self.assertEqual(tree["cycle"][0]["$serialization_marker"], "circular_reference")

    def test_json_preserves_tuple_and_set_type_with_deterministic_set_order(self) -> None:
        payload = json.loads(format_json(make_incident(evidence=[(1, "two"), {"b", "a"}])))
        self.assertEqual(payload["evidence"][0]["$type"], "builtins.tuple")
        self.assertEqual(payload["evidence"][0]["$values"], [1, "two"])
        self.assertEqual(payload["evidence"][1]["$type"], "builtins.set")
        self.assertEqual(payload["evidence"][1]["$values"], ["a", "b"])

    def test_set_unsupported_marker_path_navigates_to_emitted_value(self) -> None:
        class Unsupported:
            __slots__ = ()

        source = {Unsupported()}
        payload = json.loads(format_json(make_incident(evidence=[source])))
        set_value = payload["evidence"][0]
        marker = set_value["$values"][0]
        self.assertEqual(marker["$serialization_marker"], "unsupported_value")
        self.assertIs(resolve_json_path(payload, marker["$path"]), marker)
        self.assertEqual(len(source), 1)

    def test_nested_set_paths_match_list_and_mapping_output(self) -> None:
        class Unsupported:
            __slots__ = ()

        payload = json.loads(format_json(make_incident(evidence=[{"nested": ["left", {Unsupported()}]}])))
        marker = payload["evidence"][0]["nested"][1]["$values"][0]
        self.assertEqual(marker["$serialization_marker"], "unsupported_value")
        self.assertIs(resolve_json_path(payload, marker["$path"]), marker)

    def test_nested_frozensets_rebase_marker_path_at_each_sorted_level(self) -> None:
        class Unsupported:
            __slots__ = ()

        nested = frozenset({frozenset({Unsupported()})})
        payload = json.loads(format_json(make_incident(evidence=[nested])))
        marker = payload["evidence"][0]["$values"][0]["$values"][0]
        self.assertEqual(marker["$serialization_marker"], "unsupported_value")
        self.assertIs(resolve_json_path(payload, marker["$path"]), marker)

    def test_sorted_set_member_paths_use_final_emitted_indices_deterministically(self) -> None:
        class Unsupported:
            __slots__ = ()

        source = {"zulu", Unsupported(), "alpha"}
        report = make_incident(evidence=[source])
        first_output = format_json(report)
        self.assertEqual(first_output, format_json(report))
        payload = json.loads(first_output)
        values = payload["evidence"][0]["$values"]
        marker_index = next(i for i, value in enumerate(values) if isinstance(value, dict))
        marker = values[marker_index]
        self.assertEqual(marker["$serialization_marker"], "unsupported_value")
        self.assertEqual(values[:marker_index], ["alpha", "zulu"])
        self.assertIs(resolve_json_path(payload, marker["$path"]), marker)

    def test_set_rebasing_preserves_user_path_like_evidence_and_rebases_markers(self) -> None:
        class Unsupported:
            __slots__ = ()

        class Evidence:
            def __init__(self, label: str, nested: Any) -> None:
                self.label = label
                self.nested = nested

            __hash__ = object.__hash__

        class OrderedSet(set):
            def __init__(self, values: list[Any]) -> None:
                super().__init__(values)
                self.order = values

            def __iter__(self):
                return iter(self.order)

        values_path = '$["evidence"]["holder"]["members"]["$values"]'
        first = Evidence(
            "zulu",
            {"items": [{"reference_to": f"{values_path}[0]", "marker": Unsupported()}]},
        )
        second = Evidence(
            "alpha",
            [{"$path": f"{values_path}[1]", "marker": Unsupported()}],
        )
        source = OrderedSet([first, second])
        report = make_incident(evidence={"holder": {"members": source}})

        first_output = format_json(report)
        self.assertEqual(first_output, format_json(report))
        payload = json.loads(first_output)
        members = payload["evidence"]["holder"]["members"]["$values"]
        by_label = {member["$attributes"]["label"]: member for member in members}
        self.assertEqual(
            by_label["zulu"]["$attributes"]["nested"]["items"][0]["reference_to"],
            f"{values_path}[0]",
        )
        self.assertEqual(
            by_label["alpha"]["$attributes"]["nested"][0]["$path"],
            f"{values_path}[1]",
        )
        for member in members:
            marker = member["$attributes"]["nested"]
            marker = marker["items"][0]["marker"] if isinstance(marker, dict) else marker[0]["marker"]
            self.assertEqual(marker["$serialization_marker"], "unsupported_value")
            self.assertIs(resolve_json_path(payload, marker["$path"]), marker)

    def test_pair_sort_rebasing_preserves_user_path_like_evidence_and_rebases_markers(self) -> None:
        class Unsupported:
            __slots__ = ()

        class Evidence:
            def __init__(self, label: str, nested: Any) -> None:
                self.label = label
                self.nested = nested

            __hash__ = object.__hash__

        pair_path = '$["evidence"][0]["$mapping_entries"]'
        first = Evidence(
            "zulu",
            {"items": [{"reference_to": f"{pair_path}[0]", "marker": Unsupported()}]},
        )
        second = Evidence(
            "alpha",
            [{"$path": f"{pair_path}[1]", "marker": Unsupported()}],
        )
        source = {2: first, 1: second}
        report = make_incident(evidence=[source])

        first_output = format_json(report)
        self.assertEqual(first_output, format_json(report))
        payload = json.loads(first_output)
        pairs = payload["evidence"][0]["$mapping_entries"]
        self.assertEqual([pair["key"] for pair in pairs], [1, 2])
        by_label = {
            pair["value"]["$attributes"]["label"]: pair["value"]
            for pair in pairs
        }
        self.assertEqual(
            by_label["zulu"]["$attributes"]["nested"]["items"][0]["reference_to"],
            f"{pair_path}[0]",
        )
        self.assertEqual(
            by_label["alpha"]["$attributes"]["nested"][0]["$path"],
            f"{pair_path}[1]",
        )
        for value in by_label.values():
            marker = value["$attributes"]["nested"]
            marker = marker["items"][0]["marker"] if isinstance(marker, dict) else marker[0]["marker"]
            self.assertEqual(marker["$serialization_marker"], "unsupported_value")
            self.assertIs(resolve_json_path(payload, marker["$path"]), marker)

    def test_set_cycle_through_hashable_object_has_navigable_marker_path(self) -> None:
        class Node:
            def __init__(self) -> None:
                self.owner: Any = None

        node = Node()
        source = {node}
        node.owner = source
        payload = json.loads(format_json(make_incident(evidence=[source])))
        marker = payload["evidence"][0]["$values"][0]["$attributes"]["owner"]
        self.assertEqual(marker["$serialization_marker"], "circular_reference")
        self.assertIs(resolve_json_path(payload, marker["$path"]), marker)

    def test_one_malformed_set_member_does_not_hide_other_members(self) -> None:
        class MalformedMeta(type):
            def __getattribute__(cls, name: str) -> Any:
                if name == "__dataclass_fields__":
                    raise RuntimeError("synthetic inaccessible metadata")
                return super().__getattribute__(name)

        class MalformedObject(metaclass=MalformedMeta):
            pass

        source = {MalformedObject(), "retained-member"}
        payload = json.loads(format_json(make_incident(evidence=[source])))
        encoded = payload["evidence"][0]["$values"]
        self.assertIn("retained-member", encoded)
        marker = next(value for value in encoded if isinstance(value, dict))
        self.assertEqual(marker["$serialization_marker"], "set_member_serialization_failed")
        self.assertIs(resolve_json_path(payload, marker["$path"]), marker)

    def test_json_marks_non_finite_unsupported_and_non_string_mapping_keys(self) -> None:
        class Unsupported:
            __slots__ = ()

        payload = json.loads(format_json(make_incident(evidence=[float("nan"), float("inf"), Unsupported(), {1: "synthetic"}])))
        self.assertEqual(payload["evidence"][0]["$serialization_marker"], "non_finite_number")
        self.assertEqual(payload["evidence"][1]["$serialization_marker"], "non_finite_number")
        self.assertEqual(payload["evidence"][2]["$serialization_marker"], "unsupported_value")
        self.assertEqual(payload["evidence"][3]["$mapping_entries"][0]["key"], 1)

    def test_malformed_mapping_entry_preserves_list_and_mapping_siblings(self) -> None:
        class MalformedItems(dict):
            def items(self):
                return iter([
                    ("before", "synthetic-before"),
                    ("malformed-entry",),
                    ("after", "synthetic-after"),
                ])

        payload = json.loads(format_json(make_incident(evidence=["list-before", MalformedItems(), "list-after"])))
        evidence = payload["evidence"]
        self.assertEqual(evidence[0], "list-before")
        self.assertEqual(evidence[2], "list-after")
        encoded_mapping = evidence[1]
        self.assertEqual(
            sorted(pair["value"] for pair in encoded_mapping["$mapping_entries"]),
            ["synthetic-after", "synthetic-before"],
        )
        entry_marker = encoded_mapping["$entry_errors"][0]
        self.assertEqual(entry_marker["$serialization_marker"], "mapping_entry_unavailable")
        self.assertEqual(entry_marker["$path"], '$["evidence"][1]["$entry_errors"][0]')

    def test_mapping_iteration_failure_preserves_yielded_entries_and_marks_remainder(self) -> None:
        class PartialItems(dict):
            def items(self):
                yield "first", "synthetic-value"
                raise RuntimeError("synthetic iteration failure")

        report = make_incident(evidence=[PartialItems()])
        first_output = format_json(report)
        self.assertEqual(first_output, format_json(report))
        payload = json.loads(first_output)
        mapping = payload["evidence"][0]
        self.assertEqual(mapping["$mapping_entries"][0], {"key": "first", "value": "synthetic-value"})
        marker = mapping["$incomplete_remainder"]
        self.assertEqual(marker["$serialization_marker"], "mapping_iteration_incomplete")
        self.assertEqual(marker["$path"], '$["evidence"][0]["$incomplete_remainder"]')
        self.assertEqual(marker["entries_read"], 1)
        self.assertEqual(marker["exception_type"], "builtins.RuntimeError")

    def test_immediate_mapping_items_failure_is_explicit_at_mapping_path(self) -> None:
        class ImmediateFailure(dict):
            def items(self):
                raise PermissionError("synthetic access failure")

        payload = json.loads(format_json(make_incident(evidence=["sibling", ImmediateFailure()])))
        self.assertEqual(payload["evidence"][0], "sibling")
        marker = payload["evidence"][1]
        self.assertEqual(marker["$serialization_marker"], "mapping_unavailable")
        self.assertEqual(marker["$path"], '$["evidence"][1]')
        self.assertEqual(marker["exception_type"], "builtins.PermissionError")

    def test_nested_string_mapping_marker_path_matches_emitted_key_and_escapes_it(self) -> None:
        class MalformedItems(dict):
            def items(self):
                return iter([("unusable",)])

        unusual_key = 'a"b\\c.[d]'
        payload = json.loads(format_json(make_incident(evidence=[{unusual_key: MalformedItems()}])))
        marker = payload["evidence"][0][unusual_key]["$entry_errors"][0]
        self.assertEqual(
            marker["$path"],
            r'$["evidence"][0]["a\"b\\c.[d]"]["$entry_errors"][0]',
        )

    def test_non_string_mapping_pair_marker_path_matches_emitted_pair_array(self) -> None:
        class PairMapping(dict):
            def items(self):
                return iter([(7, MalformedItems())])

        class MalformedItems(dict):
            def items(self):
                return iter([("broken",)])

        payload = json.loads(format_json(make_incident(evidence=[PairMapping({7: MalformedItems()})])))
        mapping = payload["evidence"][0]
        self.assertEqual(mapping["$mapping_entries"][0]["key"], 7)
        marker = mapping["$mapping_entries"][0]["value"]["$entry_errors"][0]
        self.assertEqual(
            marker["$path"],
            '$["evidence"][0]["$mapping_entries"][0]["value"]["$entry_errors"][0]',
        )

    def test_non_string_key_conversion_collision_is_preserved_as_pairs(self) -> None:
        payload = json.loads(format_json(make_incident(evidence=[{1: "integer key", "1": "string key"}])))
        pairs = payload["evidence"][0]["$mapping_entries"]
        self.assertEqual(len(pairs), 2)
        self.assertEqual({(pair["key"], pair["value"]) for pair in pairs}, {(1, "integer key"), ("1", "string key")})

    def test_non_finite_float_subclasses_do_not_run_overridden_conversions(self) -> None:
        class HostileFloat(float):
            str_calls = 0
            repr_calls = 0
            float_calls = 0

            def __str__(self):
                type(self).str_calls += 1
                raise AssertionError("custom __str__ must not run")

            def __repr__(self):
                type(self).repr_calls += 1
                raise AssertionError("custom __repr__ must not run")

            def __float__(self):
                type(self).float_calls += 1
                raise AssertionError("custom __float__ must not run")

        values = [
            HostileFloat(float("nan")),
            HostileFloat(float("inf")),
            HostileFloat(float("-inf")),
        ]
        HostileFloat.str_calls = HostileFloat.repr_calls = HostileFloat.float_calls = 0
        payload = json.loads(format_json(make_incident(evidence=["before", values[0], "between", values[1], values[2], "after"])))

        evidence = payload["evidence"]
        self.assertEqual([evidence[0], evidence[2], evidence[5]], ["before", "between", "after"])
        self.assertEqual([item["value_text"] for item in (evidence[1], evidence[3], evidence[4])], ["NaN", "Infinity", "-Infinity"])
        self.assertTrue(all(item["$serialization_marker"] == "non_finite_number" for item in (evidence[1], evidence[3], evidence[4])))
        self.assertEqual((HostileFloat.str_calls, HostileFloat.repr_calls, HostileFloat.float_calls), (0, 0, 0))

    def test_json_scalar_subclasses_do_not_run_string_or_integer_conversions(self) -> None:
        class HostileString(str):
            calls = 0

            def __str__(self):
                type(self).calls += 1
                raise AssertionError("custom string conversion must not run")

        class HostileInt(int):
            int_calls = 0
            repr_calls = 0

            def __int__(self):
                type(self).int_calls += 1
                raise AssertionError("custom integer conversion must not run")

            def __repr__(self):
                type(self).repr_calls += 1
                raise AssertionError("custom repr must not run")

        HostileString.calls = HostileInt.int_calls = HostileInt.repr_calls = 0
        payload = json.loads(format_json(make_incident(evidence=[HostileString("safe-string"), HostileInt(17)])))
        self.assertEqual(payload["evidence"], ["safe-string", 17])
        self.assertEqual((HostileString.calls, HostileInt.int_calls, HostileInt.repr_calls), (0, 0, 0))

    def test_date_and_datetime_subclasses_use_safe_base_isoformat(self) -> None:
        class HostileDate(date):
            calls = 0

            def isoformat(self, *args, **kwargs):
                type(self).calls += 1
                raise AssertionError("custom date isoformat must not run")

        class HostileDateTime(datetime):
            calls = 0

            def isoformat(self, *args, **kwargs):
                type(self).calls += 1
                raise AssertionError("custom datetime isoformat must not run")

        class HostileTime(time):
            calls = 0

            def isoformat(self, *args, **kwargs):
                type(self).calls += 1
                raise AssertionError("custom time isoformat must not run")

        values = [
            HostileDate(2026, 2, 3),
            HostileDateTime(2026, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            HostileTime(4, 5, tzinfo=timezone(timedelta(hours=-4))),
        ]
        payload = json.loads(format_json(make_incident(evidence=values)))
        self.assertEqual([item["$value"] for item in payload["evidence"]], [
            "2026-02-03", "2026-02-03T04:05:00+05:30", "04:05:00-04:00",
        ])
        self.assertEqual((HostileDate.calls, HostileDateTime.calls, HostileTime.calls), (0, 0, 0))

    def test_enum_value_property_override_is_not_invoked(self) -> None:
        calls = [0]

        class HostileEnum(Enum):
            VALUE = "synthetic-enum-value"

            @property
            def value(self):
                calls[0] += 1
                raise AssertionError("caller-defined enum value property must not run")

        report = make_incident(evidence=[HostileEnum.VALUE])
        json_payload = json.loads(format_json(report))
        markdown = format_markdown(report)

        self.assertEqual(json_payload["evidence"], ["synthetic-enum-value"])
        self.assertIn(r"synthetic\-enum\-value", markdown)
        self.assertEqual(calls[0], 0)

    def test_json_marks_inaccessible_slot_without_invoking_computed_property(self) -> None:
        class SensitiveSlots:
            __slots__ = ("available", "unavailable")
            property_calls = 0

            def __init__(self) -> None:
                self.available = "retained"

            @property
            def computed(self) -> str:
                type(self).property_calls += 1
                raise RuntimeError("must not be invoked")

        payload = json.loads(format_json(make_incident(evidence=[SensitiveSlots()])))
        encoded = payload["evidence"][0]
        self.assertEqual(encoded["$attributes"]["available"], "retained")
        marker = encoded["$attribute_errors"]["unavailable"]
        self.assertEqual(marker["$serialization_marker"], "attribute_unavailable")
        self.assertEqual(marker["attribute"], "unavailable")
        self.assertEqual(marker["exception_type"], "builtins.AttributeError")
        self.assertEqual(SensitiveSlots.property_calls, 0)

    def test_json_depth_limit_is_explicit_and_output_valid(self) -> None:
        value: Any = "leaf"
        for _ in range(150):
            value = [value]
        payload = json.loads(format_json(make_incident(evidence=[value])))
        cursor: Any = payload["evidence"][0]
        markers = []
        while isinstance(cursor, list):
            cursor = cursor[0]
        if isinstance(cursor, dict):
            markers.append(cursor)
        self.assertEqual(markers[0]["$serialization_marker"], "maximum_depth_exceeded")
        self.assertEqual(markers[0]["max_depth"], 128)

    def test_json_handles_object_cycles_and_shared_objects_without_mutation(self) -> None:
        class Node:
            def __init__(self, name: str) -> None:
                self.name = name
                self.next: Any = None

        shared = Node("shared")
        left = Node("left")
        right = Node("right")
        left.next = right
        right.next = left
        evidence = {"one": shared, "two": shared, "cycle": left}
        before = (left.next, right.next, shared.next)
        payload = json.loads(format_json(make_incident(evidence=[evidence])))
        tree = payload["evidence"][0]
        self.assertEqual(tree["one"], tree["two"])
        nested = tree["cycle"]["$attributes"]["next"]["$attributes"]["next"]
        self.assertEqual(nested["$serialization_marker"], "circular_reference")
        self.assertEqual((left.next, right.next, shared.next), before)

    def test_formatting_does_not_mutate_source_objects(self) -> None:
        @dataclass
        class MutableEvidence:
            values: list[int]

        source = MutableEvidence([1, 2])
        raw = {"source": source}
        incident = make_incident(evidence=[source], provenance=[EventProvenance(0, original_record=raw)])
        before = list(source.values)
        format_json(incident)
        format_markdown(incident)
        self.assertEqual(source.values, before)
        self.assertIs(incident.evidence[0], source)
        self.assertIs(incident.provenance[0].original_record, raw)

    def test_markdown_contains_required_sections_and_separates_assessments(self) -> None:
        incident = make_incident(
            confidence="high",
            severity=IncidentSeverity.NOT_ASSESSED,
            analyst_conclusion=AnalystConclusion.NOT_ASSESSED,
            severity_rationale="Not assessed yet.",
            analyst_conclusion_rationale="Not assessed yet.",
            evidence=["Synthetic observation."],
            missing_evidence=["Independent validation."],
            recommendations=["Review related records."],
        )
        text = format_markdown(incident)
        for heading in (
            "Incident Summary", "Correlation Confidence", "Severity Assessment", "Analyst Conclusion",
            "Severity Rationale", "Analyst Conclusion Rationale", "Timeline", "Evidence",
            "Missing Evidence", "Recommendations", "MITRE ATT&CK Mappings",
            "Provenance and Evidence Limitations",
        ):
            self.assertIn(heading, text)
        self.assertIn("NOT\\_ASSESSED", text)
        self.assertIn("correlation strength only", text)
        self.assertIn("separate from correlation confidence", text)
        self.assertIn("A suspicious or inconclusive conclusion is not a confirmed-malicious finding.", text)

    def test_markdown_collection_keeps_batch_context_separate(self) -> None:
        raw = {"SECRET-SYNTHETIC-RAW-PAYLOAD": "must not expand"}
        incident = make_incident(provenance=[EventProvenance(0, original_record=raw)])
        collection = IncidentReportCollection(
            incidents=[incident], diagnostics=[{"reason": "synthetic diagnostic"}],
            skipped_events=[{"event_index": 9, "reason": "synthetic skip"}],
            original_input_records=[raw], collection_metadata={"batch": "synthetic"},
        )
        text = format_markdown(collection)
        self.assertIn("Collection Summary", text)
        self.assertIn("Collection Diagnostics", text)
        self.assertIn("Skipped Events", text)
        self.assertIn("synthetic diagnostic", text)
        self.assertIn("synthetic skip", text)
        self.assertIn("not incident-specific evidence", text)
        self.assertNotIn("SECRET-SYNTHETIC-RAW-PAYLOAD", text)

    def test_markdown_labels_unverified_attack_mapping_and_preserves_references(self) -> None:
        incident = make_incident(
            mitre_attack_mappings=[{
                "technique_id": "T1059.001", "technique_name": "Synthetic technique", "tactic": None,
                "rationale": "Synthetic evidence-based rationale", "reference_status": "UNVERIFIED",
                "evidence_references": [{"related_event_index": 2, "source_references": ["source:synthetic"], "provenance_status": "ambiguous"}],
            }],
            provenance=[EventProvenance(2, source_references=["source:synthetic"], provenance_status="ambiguous", original_record_candidates=[{"candidate": 1}, {"candidate": 2}])],
        )
        text = format_markdown(incident)
        self.assertIn("UNVERIFIED", text)
        self.assertIn("related event 2", text)
        self.assertIn("ambiguous", text)
        self.assertIn("candidate record count: 2", text)

    def test_markdown_timeline_preserves_time_zone_and_event_provenance_references(self) -> None:
        incident = make_incident(
            timeline=[TimelineEntry(
                original_timestamp="2026-02-03T04:05:06+05:30",
                normalized_timestamp_utc="2026-02-02T22:35:06+00:00",
                timestamp_status="valid",
                related_event_index=7,
                event_source="Sysmon",
                event_id=1,
                event_type="process_creation",
                source_references=["synthetic:channel:record-7"],
                provenance_status="ambiguous",
            )]
        )
        text = format_markdown(incident)
        self.assertIn(r"2026\-02\-03T04:05:06\+05:30", text)
        self.assertIn(r"2026\-02\-02T22:35:06\+00:00", text)
        self.assertIn("Related event 7", text)
        self.assertIn(r"synthetic:channel:record\-7", text)
        self.assertIn("ambiguous", text)

    def test_markdown_escapes_untrusted_markup_and_multiline_content(self) -> None:
        attack = "\n# Fake Heading\n<script>alert('synthetic')</script> [fake](https://invalid.example) ```\n"
        incident = make_incident(
            incident_id=attack,
            title=attack,
            evidence=[attack],
            recommendations=[attack],
            confidence_explanation=attack,
        )
        text = format_markdown(incident)
        self.assertNotIn("\n# Fake Heading", text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("[fake](https://invalid.example)", text)
        self.assertIn("⏎", text)
        self.assertIn("&lt;script&gt;", text)

    def test_markdown_never_calls_str_subclass_conversion_methods(self) -> None:
        class HostileString(str):
            calls = 0

            def __str__(self):
                type(self).calls += 1
                raise AssertionError("caller-controlled __str__ must not run")

        status = HostileString("UNVERIFIED")
        title = HostileString("synthetic title")
        evidence = HostileString("synthetic evidence")
        incident = make_incident(
            title=title,
            evidence=[evidence],
            mitre_attack_mappings=[{
                "technique_id": "T1000",
                "technique_name": "Synthetic technique",
                "rationale": "Synthetic rationale",
                "reference_status": status,
                "evidence_references": [],
            }],
        )

        text = format_markdown(incident)

        self.assertEqual(HostileString.calls, 0)
        self.assertIn("synthetic title", text)
        self.assertIn("synthetic evidence", text)
        self.assertIn("UNVERIFIED", text)

    def test_markdown_uses_placeholder_without_custom_object_str(self) -> None:
        class HostileObject:
            calls = 0

            def __str__(self):
                type(self).calls += 1
                raise AssertionError("caller-controlled __str__ must not run")

        value = HostileObject()
        text = format_markdown(make_incident(title=value, confidence_explanation=value, evidence=[value]))
        self.assertEqual(HostileObject.calls, 0)
        self.assertIn("HostileObject", text)
        self.assertIn("see JSON export for structured evidence", text)

    def test_markdown_does_not_expand_large_raw_payload_and_discloses_json_privacy(self) -> None:
        raw = {"synthetic-key": "X" * 10000}
        incident = make_incident(provenance=[EventProvenance(0, original_record=raw)])
        text = format_markdown(incident)
        self.assertNotIn("X" * 500, text)
        self.assertIn("Raw source records are not expanded", text)
        self.assertIn("JSON may contain explicit serialization markers", text)
        self.assertLess(len(text), 10000)


if __name__ == "__main__":
    unittest.main()
