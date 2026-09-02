from __future__ import annotations

import ast
from pathlib import Path
from collections.abc import Mapping

import Virus_Scan.models.api as model_api
from Virus_Scan.models import clustering, graph, markov
from Virus_Scan.models.api import adaptive_signals
from Virus_Scan.detection.scoring.adaptive import feature_bundle


def _imports_for(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_adaptive_feature_bundle_uses_public_adaptive_signal_contract() -> None:
    imports = _imports_for("Virus_Scan/detection/scoring/adaptive/feature_bundle.py")

    assert "Virus_Scan.models.clustering" not in imports
    assert "Virus_Scan.models.graph" not in imports
    assert "Virus_Scan.models.markov" not in imports
    assert "Virus_Scan.models.profiles" not in imports
    assert "Virus_Scan.models.api.adaptive_signals" in imports
    assert feature_bundle.compute_markov_features is adaptive_signals.compute_markov_features
    assert feature_bundle.adaptive_profile_signal is adaptive_signals.adaptive_profile_signal
    assert feature_bundle.adaptive_cluster_signal is adaptive_signals.adaptive_cluster_signal


def test_model_adaptive_signal_public_contract_preserves_canonical_owners() -> None:
    assert "adaptive_signals" in model_api.__all__
    assert adaptive_signals.canonical_behavior_flow(("read", "write")) == markov.canonical_behavior_flow(("read", "write"))
    assert adaptive_signals.compute_markov_features("a", ("read",), "b") == markov.compute_markov_features("a", ("read",), "b")
    assert adaptive_signals.adaptive_profile_signal("node:1229", ("profile_tag",))
    assert adaptive_signals.extension_profile_anomaly("renpy", "sample.rpy", ("profile_tag",), 0.0)
    assert isinstance(adaptive_signals.adaptive_cluster_signal("node:1229", ("cluster_tag",)), Mapping)
    assert adaptive_signals.cluster_risk_score("node:1229") == clustering.cluster_risk_score("node:1229")
    assert adaptive_signals.get_graph_risk_enhanced("node:1229") == graph.get_graph_risk_enhanced("node:1229")
    assert adaptive_signals.compute_graph_relationship_layer("node:1229", tags=())
    for private_name in (
        "_adaptive_markov_signal",
        "_compute_markov_features",
        "_adaptive_profile_signal",
        "_extension_profile_anomaly",
        "_adaptive_cluster_signal",
        "_cluster_risk_score",
        "_get_graph_risk_enhanced",
        "_compute_graph_relationship_layer",
    ):
        assert private_name not in adaptive_signals.__dict__


def test_adaptive_signal_public_contract_exposes_cluster_context_thresholds() -> None:
    assert adaptive_signals.MIN_CLUSTER_MEMBERS_FOR_CONTEXT == clustering.MIN_CLUSTER_MEMBERS_FOR_CONTEXT
    assert adaptive_signals.MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT == clustering.MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT
    assert feature_bundle.MIN_CLUSTER_MEMBERS_FOR_CONTEXT == clustering.MIN_CLUSTER_MEMBERS_FOR_CONTEXT
    assert feature_bundle.MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT == clustering.MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT


def test_adaptive_signal_public_contract_preserves_markov_behavior() -> None:
    events = ("read", "write", "execute")

    assert adaptive_signals.canonical_behavior_flow(events) == markov.canonical_behavior_flow(events)
    assert adaptive_signals.compute_markov_features("scan", events, "score") == markov.compute_markov_features(
        "scan",
        events,
        "score",
    )
