from __future__ import annotations

from collections.abc import Mapping
from unittest.mock import patch

import Virus_Scan.models.graph.chains as graph_chains
import Virus_Scan.models.graph.relationships as graph_relationships


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("graph chain traversal must not iterate caller object")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("graph mapping item hook must not execute")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("graph mapping iteration hook must not execute")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("graph mapping length hook must not execute")


class HostileFloat:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("graph relationship numeric hook must not execute")


def test_stage1679_chain_edges_reject_hostile_iterable_without_iteration() -> None:
    HostileIterable.touched = 0

    score = graph_chains.score_attack_chain_presence_from_edges(
        HostileIterable(),
        {"execution": {"nodes": ("execution",)}},
    )

    assert score == 0.0
    assert HostileIterable.touched == 0


def test_stage1679_chain_attack_graph_rejects_hostile_mapping_without_items_iteration() -> None:
    HostileMapping.touched = 0

    score = graph_chains.score_attack_chain_presence_from_edges(
        ("phase:execution",),
        HostileMapping(),
    )

    assert score == 0.0
    assert HostileMapping.touched == 0


def test_stage1679_chain_exact_builtin_attack_graph_still_scores_phase_edges() -> None:
    score = graph_chains.score_attack_chain_presence_from_edges(
        ("phase:execution",),
        {"execution": {"nodes": ("execution",)}},
    )

    assert score == 1.0


def test_stage1679_phase_matches_rejects_hostile_attack_graph_without_mapping_hooks() -> None:
    HostileMapping.touched = 0

    matches = graph_relationships.phase_matches_from_tags(
        ("execution",),
        attack_graph=HostileMapping(),
    )

    assert matches == {}
    assert HostileMapping.touched == 0


def test_stage1679_phase_matches_exact_builtin_attack_graph_still_matches_tags() -> None:
    matches = graph_relationships.phase_matches_from_tags(
        physical_tag_evidence(("execution",)),
        attack_graph={"execution": {"nodes": ("execution", "persistence")}},
    )

    assert matches == {"execution": ("execution",)}


def test_stage1679_graph_relationship_metric_rejects_hostile_float_without_hook() -> None:
    HostileFloat.touched = 0

    with patch.object(
        graph_relationships,
        "get_graph_node",
        lambda node: {"edges": set(), "tags": set()},
    ), patch.object(
        graph_relationships,
        "get_graph_features",
        lambda node: {
            "graph_features_ready": True,
            "graph_unavailable_reason": None,
            "base_risk": HostileFloat(),
            "risk": 0.25,
            "anomaly": 0.0,
        },
    ), patch.object(
        graph_relationships,
        "propagate_behavior_chains_from_node",
        lambda node, max_depth=3: (0.0, ()),
    ):
        layer = graph_relationships.compute_graph_relationship_layer(
            "stage1679-node",
            tags=physical_tag_evidence(("execution", "persistence")),
        )

    assert HostileFloat.touched == 0
    assert layer["graph_relationship_ready"] is False
    assert layer["graph_unavailable_reason"] == "non_numeric_graph_relationship_metric"
    assert layer["final_json_must_record"] is True
    assert layer["replay_record_required"] is True
