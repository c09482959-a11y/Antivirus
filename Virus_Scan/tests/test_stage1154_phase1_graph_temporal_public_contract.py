from __future__ import annotations

import ast
from collections import Counter, defaultdict
from pathlib import Path

from Virus_Scan.models.graph import link_temporal_to_graph
from Virus_Scan.runtime.graph_state import graph_snapshot, reset_graph_state
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.runtime.temporal_state import temporal_state_node_key

GRAPH_MODEL = Path("Virus_Scan/models/graph")


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1154_graph_model_uses_learned_transition_contract_without_chain_pattern_owner() -> None:
    tree = ast.parse("\n".join(path.read_text(encoding="utf-8") for path in sorted(GRAPH_MODEL.glob("*.py"))), filename=str(GRAPH_MODEL))
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.models.temporal"
        for alias in node.names
    }

    assert imported_names == set()
    assert temporal_state_node_key(" node ") == "node"
    assert "markov_known_chain_score" not in GRAPH_MODEL.joinpath("links.py").read_text(encoding="utf-8")


def test_stage1154_graph_temporal_link_is_cold_start_neutral_and_runtime_keyed() -> None:
    _reset_markov_state()
    reset_graph_state()

    result = link_temporal_to_graph(" node:temporal ", "asset", ["download", "exec"], "runtime")
    snapshot = graph_snapshot()

    assert result["linked"] is True
    assert result["weight"] == 1.0
    assert "node:temporal" in snapshot
    assert any(str(edge).startswith("transition:asset->runtime") for edge in snapshot["node:temporal"]["edges"])
