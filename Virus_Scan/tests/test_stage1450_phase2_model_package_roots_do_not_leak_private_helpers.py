from __future__ import annotations

import Virus_Scan.models.graph as graph
import Virus_Scan.models.temporal as temporal


def test_stage1450_temporal_package_root_does_not_publish_private_helper_attrs() -> None:
    for name in (
        "_temporal_delayed_execution_score",
        "temporal_pair_anomaly",
        "temporal_stage_sequence_anomaly",
        "_temporal_markov_overlay_support",
        "_umige_hidden_state_update",
    ):
        assert name not in temporal.__dict__


def test_stage1450_graph_package_root_does_not_publish_private_evidence_helpers() -> None:
    for name in (
        "_graph_unavailable_transition_edge",
        "_safe_graph_entities",
        "_safe_graph_mapping",
        "_safe_graph_entity_field",
    ):
        assert name not in graph.__dict__
