from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.detection.scoring.adaptive.availability as availability
import Virus_Scan.detection.scoring.adaptive.confidence as confidence
import Virus_Scan.detection.scoring.adaptive.log_odds_fusion as log_odds_fusion
import Virus_Scan.detection.scoring.adaptive.log_odds_probabilities as log_odds_probabilities
import Virus_Scan.detection.scoring.adaptive.log_odds_weights as log_odds_weights
import Virus_Scan.detection.scoring.adaptive.feature_bundle as feature_bundle
import Virus_Scan.detection.scoring.adaptive.settings as settings

ADAPTIVE_ROOT = Path("Virus_Scan/detection/scoring/adaptive")
OWNER_MODULES = (
    availability,
    confidence,
    log_odds_fusion,
    log_odds_probabilities,
    log_odds_weights,
    feature_bundle,
    settings,
)
OWNER_PATHS = (
    ADAPTIVE_ROOT / "availability.py",
    ADAPTIVE_ROOT / "confidence.py",
    ADAPTIVE_ROOT / "log_odds_fusion.py",
    ADAPTIVE_ROOT / "log_odds_probabilities.py",
    ADAPTIVE_ROOT / "log_odds_weights.py",
    ADAPTIVE_ROOT / "feature_bundle.py",
    ADAPTIVE_ROOT / "settings.py",
)
FORBIDDEN_PRIVATE_HELPER_NAMES = (
    "_adaptive_unavailable_reason",
    "_availability_aware_layer_probability_summary",
    "_available_feature_probability",
    "_available_layer_weight_score",
    "_available_model_signal_probability",
    "_layer_unavailable_reason",
    "_layer_weight_unavailable_reason",
    "_probability_feature_unavailable_reason",
    "_adaptive_learned_weight_bundle",
    "_adaptive_normalized_weights",
    "_aw_norm_weights",
    "_coerce_model_probability",
    "_coerce_scaled_model_probability",
    "_finite_engine_context",
    "_max_model_probability",
    "_model_signal_unavailable_reason",
    "_readiness_unavailable_reason",
    "_apply_log_odds_concrete_caps",
    "_derive_log_odds_weights",
    "_log_odds_active_layer_bonus",
    "_log_odds_concrete_count",
    "_log_odds_feature_probabilities",
    "_log_odds_learning_meta",
    "_log_odds_static_model_probabilities",
    "_normalize_log_odds_weights",
    "_probability_feature_build_failed_bundle",
    "_model_adaptive_cluster_signal",
    "_model_adaptive_markov_signal",
    "_model_adaptive_profile_signal",
    "_model_canonical_behavior_flow",
    "_model_cluster_risk_score",
    "_model_cluster_risk_score_evidence",
    "_model_compute_graph_relationship_layer",
    "_model_compute_markov_features",
    "_model_context_cluster_quality",
    "_model_coordinated_model_validation_signal",
    "_model_extension_profile_anomaly",
    "_model_get_graph_risk_enhanced",
    "_model_graph_risk_enhanced_evidence",
    "_model_snapshot_temporal",
    "_make_model_feature_bundle",
    "_make_model_failure_record",
    "_materialize_model_failure_record",
    "_runtime_mapping",
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _top_level_private_defs_or_imports(path: Path) -> tuple[str, ...]:
    offenders: list[str] = []
    for node in _tree(path).body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local_name = alias.asname or alias.name
                if local_name.startswith("_"):
                    offenders.append(f"import:{node.lineno}:{local_name}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("_"):
                offenders.append(f"def:{node.lineno}:{node.name}")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.startswith("_") and target.id != "__all__":
                    offenders.append(f"assign:{node.lineno}:{target.id}")
    return tuple(offenders)


def test_stage1461_adaptive_owner_modules_publish_public_helper_names_only() -> None:
    expected_exports = {
        availability.__name__: (
            "adaptive_unavailable_reason",
            "availability_aware_layer_probability_summary",
            "available_feature_probability",
            "available_layer_weight_score",
            "available_model_signal_probability",
            "layer_unavailable_reason",
            "layer_weight_unavailable_reason",
            "probability_feature_unavailable_reason",
        ),
        confidence.__name__: (
            "adaptive_learned_model_confidence",
            "adaptive_learned_model_weight_from_confidence",
            "adaptive_normalized_weights",
            "coerce_model_probability",
            "coerce_scaled_model_probability",
            "finite_engine_context",
            "max_model_probability",
            "model_signal_unavailable_reason",
            "readiness_unavailable_reason",
        ),
        log_odds_fusion.__name__: (
            "calibrated_log_odds_score_100",
            "log_odds_concrete_count",
            "log_odds_learning_meta",
            "probability_feature_build_failed_bundle",
        ),
        log_odds_probabilities.__name__: (
            "LogOddsFeatureProbabilitiesRequest",
            "log_odds_feature_probabilities",
            "log_odds_static_model_probabilities",
        ),
        log_odds_weights.__name__: (
            "apply_log_odds_concrete_caps",
            "derive_log_odds_weights",
            "log_odds_active_layer_bonus",
            "normalize_log_odds_weights",
        ),
        feature_bundle.__name__: tuple(sorted((
            "model_adaptive_cluster_signal",
            "model_adaptive_markov_signal",
            "model_adaptive_profile_signal",
            "model_behavior_flow",
            "model_cluster_risk_score_evidence",
            "model_coordinated_validation_signal",
            "model_extension_profile_anomaly",
            "model_feature_bundle",
            "model_failure_record",
            "materialize_model_failure",
            "MIN_CLUSTER_MEMBERS_FOR_CONTEXT",
            "MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT",
            "model_context_cluster_quality",
            "model_graph_relationship_layer",
            "model_graph_risk_enhanced",
            "model_graph_risk_enhanced_evidence",
            "model_markov_features",
            "model_temporal_snapshot",
        ))),
        settings.__name__: (
            "ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP",
            "ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP",
            "ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT",
            "ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT",
            "ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP",
            "ADAPTIVE_LEARNED_MODEL_STATIC_VERSION",
            "ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP",
            "ADAPTIVE_PROBABILITY_FEATURE_BUNDLE_VERSION",
            "ADAPTIVE_WEIGHT_BOUNDS",
            "ADAPTIVE_WEIGHT_MIN_HISTORY",
            "ADAPTIVE_WEIGHT_VERSION",
            "CALIBRATED_SCORE_THRESHOLDS",
            "CALIBRATED_SCORE_VERSION",
            "LAYER_WEIGHTS",
            "runtime_mapping",
        ),
    }
    for module in OWNER_MODULES:
        assert module.__all__ == expected_exports[module.__name__]
        leaked = tuple(
            name
            for name in dir(module)
            if name.startswith("_") and not (name.startswith("__") and name.endswith("__"))
        )
        assert leaked == ()


def test_stage1461_adaptive_owner_modules_do_not_define_or_import_private_helpers() -> None:
    offenders: list[str] = []
    for path in OWNER_PATHS:
        for offender in _top_level_private_defs_or_imports(path):
            offenders.append(f"{path}:{offender}")
    assert offenders == []


def test_stage1461_adaptive_consumers_no_longer_import_renamed_private_helpers() -> None:
    offenders: list[str] = []
    for path in ADAPTIVE_ROOT.glob("*.py"):
        if path.name == "settings.py":
            continue
        text = path.read_text(encoding="utf-8")
        for name in FORBIDDEN_PRIVATE_HELPER_NAMES:
            if name in text:
                offenders.append(f"{path}:{name}")
    assert offenders == []


def test_stage1461_adaptive_public_helpers_preserve_unavailable_evidence_behavior() -> None:
    record = {"ready": False, "score": 95.0}
    assert confidence.readiness_unavailable_reason(record, "not_ready") == "not_ready"
    assert availability.available_model_signal_probability(record, "score") == 0.0
    feature = {"p_graph": 0.9, "graph_ready": False}
    assert availability.probability_feature_unavailable_reason(feature, "p_graph") == "graph_probability_not_ready"
    assert availability.available_feature_probability(feature, "p_graph", None) == 0.0
