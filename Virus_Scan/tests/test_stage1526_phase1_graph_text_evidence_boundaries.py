"""Stage 1526 Phase 1 graph exact-text evidence boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence

from Virus_Scan.models.graph import cache as graph_cache
from Virus_Scan.models.graph import chains as graph_chains
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.strip_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw strip() was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned bool was invoked")


def test_stage1526_graph_cache_key_detaches_hostile_text_without_raw_str():
    namespace = HostileText("graph_risk")
    node = HostileText("node-a")

    assert graph_cache.cache_key(namespace, node) == "graph_risk:node-a"
    assert type(graph_cache.cache_key(namespace, node)) is str
    assert namespace.str_calls == 0
    assert node.str_calls == 0
    assert namespace.strip_calls == 0
    assert node.strip_calls == 0
    assert namespace.bool_calls == 0
    assert node.bool_calls == 0


def test_stage1526_graph_chain_names_come_from_immutable_canonical_registry():
    assert not hasattr(graph_chains, "BEHAVIOR_CHAINS")
    evidence = evaluate_chain_evidence(
        tags=physical_tag_evidence(("bitsadmin_exec", "background_transfer", "network_download")),
        match_modes=("anchor", "unordered"),
    )

    assert evidence.total_score_points > 0.0
    assert "bitsadmin_staging_chain" in evidence.hits
    assert all(type(hit) is str for hit in evidence.hits)
    assert not hasattr(graph_chains, "detect_behavior_chains")


def test_stage1526_attack_phase_presence_detaches_hostile_graph_config_text():
    phase = HostileText("execution")
    node_name = HostileText("powershell")

    score = graph_chains.score_attack_chain_presence_from_edges(
        ("phase:execution", "stage:powershell"),
        attack_graph={phase: {"nodes": (node_name,)}},
    )

    assert score == 1.0
    assert phase.str_calls == 0
    assert node_name.str_calls == 0
    assert phase.strip_calls == 0
    assert node_name.strip_calls == 0
    assert phase.bool_calls == 0
    assert node_name.bool_calls == 0
