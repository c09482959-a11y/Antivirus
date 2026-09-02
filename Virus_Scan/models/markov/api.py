"""Canonical public Markov model API.

The package owns Markov behavior-flow canonicalization, learned transition
updates, probability records, feature bundles, and evidence materialization.
Detection, temporal, graph, replay, and profile consumers must enter through
this bounded API rather than private implementation modules.
"""
from __future__ import annotations

from Virus_Scan.models.markov.adaptive import adaptive_markov_signal
from Virus_Scan.models.markov.feature_support import markov_tag_rarity_score
from Virus_Scan.models.markov.features import (
    compute_markov_features,
    markov_transition_score,
    tag_pair_anomaly,
)
from Virus_Scan.models.markov.flow import canonical_behavior_flow
from Virus_Scan.models.markov.learning import update_markov_model
from Virus_Scan.models.markov.probability import (
    markov_pair_probability,
    markov_stage_probability,
)
from Virus_Scan.models.markov.sequence_probability import markov_sequence_probability

__all__ = (
    'adaptive_markov_signal',
    'canonical_behavior_flow',
    'compute_markov_features',
    'markov_pair_probability',
    'markov_sequence_probability',
    'markov_stage_probability',
    'markov_tag_rarity_score',
    'markov_transition_score',
    'tag_pair_anomaly',
    'update_markov_model',
)
