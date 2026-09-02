from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from contextlib import ExitStack
from unittest.mock import patch

from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


import Virus_Scan.models.graph as graph_model
from Virus_Scan.models.graph import chains as graph_chains
from Virus_Scan.models.graph import scan as graph_scan
from Virus_Scan.runtime.graph_state import reset_graph_state


def test_stage1347_behavior_chain_flow_uses_sorted_node_tags() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(
            graph_chains,
            "get_graph_node",
            lambda node: {
                "tag_evidence_records": physical_tag_evidence((
                    "network_download", "bitsadmin_exec", "background_transfer",
                )).records,
                "edges": set(),
            },
        ))
        stack.enter_context(patch.object(graph_chains, "graph_has_node", lambda node: False))
        _score, discovered = graph_model.propagate_behavior_chains_from_node("stage1347_root", max_depth=1)

        assert discovered
        assert discovered[0]["flow"] == [
            "background_transfer",
            "bitsadmin_exec",
            "network_activity",
            "network_download",
        ]
        assert discovered[0]["tags"] == [
            "background_transfer",
            "bitsadmin_exec",
            "network_activity",
            "network_download",
        ]


def test_stage1347_behavior_chain_traversal_uses_sorted_edge_order() -> None:
    graph = {
        "stage1347_root": {
            "tag_evidence_records": physical_tag_evidence(("bitsadmin_exec",), source_stage="stage1347_root").records,
            "edges": {"stage1347_c", "stage1347_a", "stage1347_b"},
        },
        "stage1347_a": {"tag_evidence_records": physical_tag_evidence(("background_transfer", "network_download"), source_stage="stage1347_a").records, "edges": set()},
        "stage1347_b": {"tag_evidence_records": physical_tag_evidence(("background_transfer", "network_download"), source_stage="stage1347_b").records, "edges": set()},
        "stage1347_c": {"tag_evidence_records": physical_tag_evidence(("background_transfer", "network_download"), source_stage="stage1347_c").records, "edges": set()},
    }
    with ExitStack() as stack:
        stack.enter_context(patch.object(graph_chains, "get_graph_node", lambda node: graph[node]))
        stack.enter_context(patch.object(graph_chains, "graph_has_node", lambda node: node in graph))

        _score, discovered = graph_model.propagate_behavior_chains_from_node("stage1347_root", max_depth=1)

        assert [row["end"] for row in discovered] == ["stage1347_a", "stage1347_b", "stage1347_c"]


def test_stage1347_scan_cs_returns_and_emits_sorted_tags(tmp_path) -> None:
    reset_graph_state()
    emitted = []
    with ExitStack() as stack:
        stack.enter_context(patch.object(graph_scan, "emit_stage_event", lambda file, stage, tags: emitted.append(list(tags)) or {}))
        cs_file = tmp_path / "stage1347.cs"
        cs_file.write_text("eval(Convert.FromBase64String(value)); Assembly.Load(new byte[] { 1 });")

        result = graph_model.scan_cs(str(cs_file))

        assert result == sorted(result)
        assert emitted == [result]
        assert {"assembly_load", "base64", "dynamic_code", "memory_dll_loader"}.issubset(set(result))


def test_stage1347_reconstruct_attack_chain_uses_sorted_edge_order() -> None:
    graph = {
        "stage1347_root": {"edges": {"stage1347_c", "stage1347_a", "stage1347_b"}},
        "stage1347_a": {"edges": set()},
        "stage1347_b": {"edges": set()},
        "stage1347_c": {"edges": set()},
    }
    with ExitStack() as stack:
        stack.enter_context(patch.object(graph_chains, "graph_node_snapshot", lambda node: graph.get(node)))
        stack.enter_context(patch.object(graph_chains, "graph_has_node", lambda node: node in graph))

        assert graph_model.reconstruct_attack_chain("stage1347_root", max_depth=1) == [
            "stage1347_root",
            "stage1347_a",
            "stage1347_b",
            "stage1347_c",
        ]
