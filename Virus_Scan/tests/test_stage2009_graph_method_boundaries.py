
"""Stage 2009 graph method no-hook text and sequence boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


from pathlib import Path

from Virus_Scan.models.graph.method_graph import add_method_node, build_method_graph, extract_calls, extract_methods
from Virus_Scan.runtime.graph_state import graph_node_snapshot, reset_graph_state
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE


class HostileGraphMethodValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned bool hook executed")

    def __str__(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned str hook executed")

    def __repr__(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned format hook executed")

    def __iter__(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned iter hook executed")


class HostileGraphMethodMapping:
    touched = 0

    def __bool__(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned mapping bool hook executed")

    def __iter__(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned mapping iter hook executed")

    def __len__(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned mapping len hook executed")

    def __getitem__(self, _key):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned mapping getitem hook executed")

    def items(self):  # pragma: no cover - regression guard
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items hook executed")


FORBIDDEN_METHOD_GRAPH_SNIPPETS = (
    "call_values, calls_reason = safe_graph_sequence(calls, 'graph_method_calls_unavailable')",
    "record_graph_input_degraded('graph_method_node_input_degraded', graph_first_reason(tags_reason, calls_reason), node=safe_graph_text(src))",
    "context={'node': safe_graph_text(src)}",
    "log_error(f'add_method_node failed: {e}')",
    "for line in safe_graph_text(cs_text).splitlines():",
    "for line in safe_graph_text(method_body).splitlines():",
    "items = methods.items()",
    "name_text, name_reason = safe_graph_text_with_reason(mname, 'graph_method_name_unavailable')",
    "record_graph_input_degraded('graph_method_graph_input_degraded', methods_reason, node=safe_graph_text(file))",
    "file_text = safe_graph_text(file)",
    "fid = f'{file_text}::{mname}'",
)


def test_stage2009_method_graph_public_boundaries_reject_hostile_values_without_hooks() -> None:
    reset_graph_state()
    HostileGraphMethodValue.touched = 0
    hostile = HostileGraphMethodValue()

    add_method_node(hostile, tags=hostile, calls=hostile)  # type: ignore[arg-type]
    methods = extract_methods(hostile)
    calls = extract_calls(hostile)
    build_method_graph(hostile, methods={"public void Run() {": hostile})

    assert HostileGraphMethodValue.touched == 0
    assert methods == {}
    assert calls == []
    node = graph_node_snapshot("unsupported_graph_text_type:HostileGraphMethodValue")
    assert node is not None
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in node["tags"]
    assert DETECTION_STAGE_DEGRADED_TAG in node["tags"]


def test_stage2009_method_graph_mapping_rejects_caller_owned_mapping_without_hooks() -> None:
    reset_graph_state()
    HostileGraphMethodMapping.touched = 0
    hostile_mapping = HostileGraphMethodMapping()

    build_method_graph("sample.cs", hostile_mapping)  # type: ignore[arg-type]

    assert HostileGraphMethodMapping.touched == 0
    assert graph_node_snapshot("sample.cs::anything") is None


def test_stage2009_method_graph_preserves_exact_public_method_behavior() -> None:
    reset_graph_state()

    methods = extract_methods("public void Run() {\n  Assembly.Load(payload);\n}\n")
    build_method_graph("sample.cs", methods)

    assert "public void Run() {" in methods
    assert graph_node_snapshot("sample.cs::public void Run() {") is not None
    assert graph_node_snapshot("assembly_load") is not None


def test_stage2009_method_graph_repaired_source_snippets_absent() -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/method_graph.py"))

    for snippet in FORBIDDEN_METHOD_GRAPH_SNIPPETS:
        assert snippet not in source

from Virus_Scan.models.graph.relationships import compute_graph_relationship_layer, phase_hits_from_tags, phase_matches_from_tags


FORBIDDEN_RELATIONSHIP_SNIPPETS = (
    "nodes, nodes_reason = safe_graph_sequence(raw_nodes, 'graph_phase_nodes_unavailable')",
    "record_graph_input_degraded('graph_phase_nodes_degraded', nodes_reason, phase=safe_graph_text(phase))",
    "if node_text in tagset or any(node_text in safe_graph_text(tag).lower() for tag in tagset):",
    "matches[safe_graph_text(phase)] = tuple(sorted(set(phase_matches)))",
    "return sorted(phase_matches_from_tags(tags).keys())",
    "for key, item in sorted(mapping_items, key=lambda pair: safe_graph_text(pair[0])):",
    "name = safe_graph_text(key)",
    "out[f'{name}_unavailable_reason'] = 'non_finite_graph_relationship_metric'",
    "node_text, node_text_reason = safe_graph_text_with_reason(node, 'graph_relationship_layer_failed') if node is not None else ('', '')",
    "hits.append(f'phase:{phase}')",
    "log_error(f'graph relationship layer failed for {safe_graph_text(node)}: {e}')",
)


def test_stage2009_graph_relationship_boundaries_reject_hostile_inputs_without_hooks() -> None:
    HostileGraphMethodValue.touched = 0
    hostile = HostileGraphMethodValue()

    matches = phase_matches_from_tags(hostile, attack_graph={"phase": {"nodes": hostile}})  # type: ignore[arg-type]
    hits = phase_hits_from_tags(hostile)  # type: ignore[arg-type]
    layer = compute_graph_relationship_layer(hostile, tags=hostile)  # type: ignore[arg-type]

    assert HostileGraphMethodValue.touched == 0
    assert matches == {}
    assert hits == []
    assert layer["graph_relationship_ready"] is False
    assert layer["final_json_must_record"] is True


def test_stage2009_graph_relationship_preserves_exact_phase_matching() -> None:
    graph = {"execution": {"nodes": ("cmd_exec",)}}

    assert phase_matches_from_tags(physical_tag_evidence(("cmd_exec",)), attack_graph=graph) == {"execution": ("cmd_exec",)}
    assert phase_hits_from_tags(("cmd_exec",)) == []


def test_stage2009_graph_relationship_repaired_source_snippets_absent() -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/relationships.py"))

    for snippet in FORBIDDEN_RELATIONSHIP_SNIPPETS:
        assert snippet not in source
