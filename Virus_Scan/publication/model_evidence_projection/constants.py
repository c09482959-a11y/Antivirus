"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations

MODEL_EVIDENCE_WRITER_VERSION = "model_evidence_writer_v1"

MODEL_PROBABILITY_FIELDS = (
    "attention",
    "bucket",
    "cluster",
    "graph",
    "graph_chain",
    "markov",
    "mitre",
    "profile",
    "temporal",
    "vector",
)

MODEL_SIGNAL_SOURCE_FIELDS = (
    "temporal_signals",
    "temporal_features",
    "markov_sequence_signals",
    "markov_features",
    "clustering_signals",
    "cluster_features",
    "clustering_features",
    "graph_signals",
    "graph_features",
    "model_context",
    "contextual_expected_behavior",
    "context_confidence_amplifier",
    "context_confidence",
    "contextual_confidence",
    "analytical_calibration",
    "score_metadata",
    "score_meta",
    "adaptive_score_metadata",
    "adaptive_score_meta",
    "calibrated_score_metadata",
    "calibrated_log_odds",
    "layered_detection",
    "layer_weights",
    "engine_context",
    "engine_confidence",
    "baseline_maturity",
    "profile_selection",
    "detection_profile_context",
    "feature_vector",
    "adaptive_learning",
    "adaptive_weights",
    "pre_rolling_weights",
    "rolling_learned_static",
    "bucket_vector",
    "model_failure",
    "model_failure_record",
    "model_feature_bundle",
    "model_snapshot",
    "model_evidence_record",
    "probability_record",
    "markov_probability_record",
    "temporal_overlay_record",
    "profile_evidence",
    "profile_evidence_record",
    "cluster_evidence",
    "cluster_evidence_record",
    "graph_evidence",
    "graph_evidence_record",
    "cold_start_record",
    "replay_model_comparison",
    "replay_model_comparison_record",
)

MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS = (
    "score_metadata",
    "score_meta",
    "adaptive_score_metadata",
    "adaptive_score_meta",
    "calibrated_score_metadata",
    "calibrated_log_odds",
    "analytical_calibration",
    "model_context",
    "contextual_expected_behavior",
    "context_confidence_amplifier",
    "context_confidence",
    "contextual_confidence",
    "layered_detection",
    "adaptive_learning",
    "profile_selection",
    "detection_profile_context",
)

MODEL_CONTRACT_RECORD_FIELDS = (
    "model_feature_bundle",
    "model_snapshot",
    "model_evidence_record",
    "probability_record",
    "markov_probability_record",
    "temporal_overlay_record",
    "profile_evidence",
    "profile_evidence_record",
    "cluster_evidence",
    "cluster_evidence_record",
    "graph_evidence",
    "graph_evidence_record",
    "cold_start_record",
    "replay_model_comparison",
    "replay_model_comparison_record",
)

MODEL_CONTRACT_SCALAR_PROBABILITY_FIELDS = (
    "probability",
    "stage_probability",
    "sequence_probability",
    "confidence",
)

MODEL_CONTRACT_PROBABILITY_MAPPING_FIELDS = (
    "pair_probabilities",
    "feature_probabilities",
    "probabilities",
)

MODEL_CONTRACT_PROBABILITY_FIELD_EXCLUSIONS = (
    "probability_ready",
    "probability_support",
    "probability_count",
    "probability_unavailable_reason",
)

MODEL_CONTRACT_NONNEGATIVE_INTEGER_FIELDS = (
    "support",
    "count",
    "vocab",
)

MODEL_CONTRACT_BOOLEAN_FLAG_FIELDS = (
    "ready",
    "probability_ready",
    "stage_probability_ready",
    "matched",
)

MODEL_PROBABILITY_RECORD_REQUIRED_FIELDS = (
    "ready",
    "probability",
    "support",
    "count",
    "vocab",
    "smoothing",
    "reason",
    "model_version",
)

MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS = (
    "smoothing",
    "model_version",
)

MODEL_PROBABILITY_RECORD_KEYS = (
    "probability_record",
    "markov_probability_record",
)

MODEL_REPLAY_COMPARISON_RECORD_REQUIRED_FIELDS = (
    "model_name",
    "expected",
    "actual",
    "matched",
    "mismatch_fields",
    "model_version",
)

MODEL_REPLAY_COMPARISON_RECORD_KEYS = (
    "replay_model_comparison",
    "replay_model_comparison_record",
)

MODEL_FAILURE_RECORD_REQUIRED_FIELDS = (
    "model_name",
    "failure_type",
    "reason",
)

MODEL_FAILURE_RECORD_KEYS = (
    "model_failure",
    "model_failure_record",
    "model_failures",
)

__all__ = ('MODEL_CONTRACT_BOOLEAN_FLAG_FIELDS', 'MODEL_CONTRACT_NONNEGATIVE_INTEGER_FIELDS', 'MODEL_CONTRACT_PROBABILITY_FIELD_EXCLUSIONS', 'MODEL_CONTRACT_PROBABILITY_MAPPING_FIELDS', 'MODEL_CONTRACT_RECORD_FIELDS', 'MODEL_CONTRACT_SCALAR_PROBABILITY_FIELDS', 'MODEL_EVIDENCE_WRITER_VERSION', 'MODEL_FAILURE_RECORD_KEYS', 'MODEL_FAILURE_RECORD_REQUIRED_FIELDS', 'MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS', 'MODEL_PROBABILITY_FIELDS', 'MODEL_PROBABILITY_RECORD_KEYS', 'MODEL_PROBABILITY_RECORD_REQUIRED_FIELDS', 'MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS', 'MODEL_REPLAY_COMPARISON_RECORD_KEYS', 'MODEL_REPLAY_COMPARISON_RECORD_REQUIRED_FIELDS', 'MODEL_SIGNAL_SOURCE_FIELDS')
