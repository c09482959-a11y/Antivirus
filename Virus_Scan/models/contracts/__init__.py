"""Immutable model-layer contract records.

These contracts are value carriers only. They must not import scanner,
detection, publication, replay, or mutable runtime implementation owners.
"""

from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
    make_markov_probability_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)
from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
    make_temporal_overlay_record,
    make_profile_evidence_record,
    make_cluster_evidence_record,
    make_graph_evidence_record,
)

from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    make_cold_start_record,
    materialize_model_failure_record,
)

from Virus_Scan.models.contracts.model_snapshot import (
    make_model_snapshot,
    materialize_model_snapshot,
    make_replay_model_comparison_record,
    materialize_replay_model_comparison_record,
)

__all__ = (
    "make_cluster_evidence_record",
    "make_cold_start_record",
    "make_graph_evidence_record",
    "make_markov_probability_record",
    "make_model_evidence_record",
    "make_model_failure_record",
    "make_model_feature_bundle",
    "make_model_snapshot",
    "make_probability_record",
    "make_profile_evidence_record",
    "make_replay_model_comparison_record",
    "make_temporal_overlay_record",
    "materialize_model_evidence_record",
    "materialize_model_failure_record",
    "materialize_model_feature_bundle",
    "materialize_model_snapshot",
    "materialize_probability_record",
    "materialize_replay_model_comparison_record",
)
