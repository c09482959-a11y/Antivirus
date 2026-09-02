"""Stage 1482: graph chain/link owners must not probe caller truthiness."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from Virus_Scan.models.graph.chains import score_attack_chain_presence_from_edges
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.graph import links as graph_links
from Virus_Scan.models.graph.links import link_temporal_to_graph
from Virus_Scan.runtime.graph_state import graph_node_snapshot, reset_graph_state


class _HostileIterable:
    def __iter__(self):
        raise RuntimeError("iteration unavailable")

    def __bool__(self):
        raise RuntimeError("truthiness unavailable")


class _HostileMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("mapping iteration unavailable")

    def __len__(self):
        raise RuntimeError("mapping length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("mapping item unavailable")


def test_stage1482_canonical_chain_evaluator_rejects_hostile_inputs_without_bool_probe() -> None:
    evidence = evaluate_chain_evidence(tags=_HostileIterable())
    assert evidence.decisions == ()
    assert evidence.failures


def test_stage1482_score_attack_chain_presence_detaches_hostile_edges_without_bool_probe() -> None:
    assert score_attack_chain_presence_from_edges(_HostileIterable()) == 0.0
    assert score_attack_chain_presence_from_edges(["phase:execution"], attack_graph=_HostileMapping()) == 0.0


def test_stage1482_link_temporal_to_graph_rejects_hostile_tags_as_unavailable_flow() -> None:
    reset_graph_state()

    result = link_temporal_to_graph("sample.exe", "archive", _HostileIterable(), "script")

    assert result == {"linked": False, "reason": "no_behavior_flow"}


def test_stage1482_generic_yara_graph_link_owner_is_removed() -> None:
    assert not hasattr(graph_links, "link_yara_to_graph")
