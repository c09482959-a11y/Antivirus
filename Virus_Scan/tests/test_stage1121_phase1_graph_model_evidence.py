from types import MappingProxyType

from Virus_Scan.models import graph
from Virus_Scan.runtime.graph_state import add_graph_edge_owned, reset_graph_state
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


ATTACK_GRAPH_FIXTURE = MappingProxyType({
    "execution": MappingProxyType({"nodes": ("powershell_exec", "cmd_exec")}),
    "credential_access": MappingProxyType({"nodes": ("credential_dump_attempt",)}),
})


def test_graph_causal_lineage_overlay_uses_owned_helpers_without_nameerror():
    evidence = graph.causal_entity_lineage_overlay(
        path="sample.exe",
        tags=["powershell_exec", "credential_dump_attempt"],
        metadata={"engine": "unity"},
    )

    assert evidence["schema_version"]
    assert evidence["version"]
    assert evidence["ready"] is True
    assert evidence["entity_continuity_present"] is True
    assert evidence["directed_edges_present"] is True
    assert isinstance(evidence["entities"], tuple)
    assert isinstance(evidence["transition_edges"], tuple)


def test_graph_phase_matcher_returns_deterministic_matched_evidence():
    matches = graph.phase_matches_from_tags(
        physical_tag_evidence(("credential_dump_attempt", "powershell_exec")),
        ATTACK_GRAPH_FIXTURE,
    )

    assert list(matches) == ["credential_access", "execution"]
    assert matches["execution"] == ("powershell_exec",)
    assert matches["credential_access"] == ("credential_dump_attempt",)


def test_graph_attack_chain_score_no_longer_returns_before_scoring_edges():
    score = graph.score_attack_chain_presence_from_edges(
        {"phase:execution", "tag:credential_dump_attempt"},
        ATTACK_GRAPH_FIXTURE,
    )

    assert score == 1.0


def test_public_attack_chain_score_reads_graph_edges_without_exception():
    reset_graph_state()
    try:
        add_graph_edge_owned("node-a", "phase:execution", edge_type="attack_phase", weight=1.0)
        score = graph.score_attack_chain_presence("node-a")
        assert 0.0 <= score <= 1.0
    finally:
        reset_graph_state()
