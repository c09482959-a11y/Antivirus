"""Public Markov model contract.

Callers, including other model subdomains, use this bounded API instead of
importing private Markov implementation internals directly.  The
Markov implementation remains the canonical owner of behavior-flow
canonicalization, transition learning, probability records, and Markov-derived
features; this module only exposes that owner through a narrow public contract.
"""
from __future__ import annotations

from Virus_Scan.models.markov.api import (
    adaptive_markov_signal,
    canonical_behavior_flow,
    compute_markov_features,
    markov_pair_probability,
    markov_sequence_probability,
    markov_stage_probability,
    markov_tag_rarity_score,
    markov_transition_score,
    tag_pair_anomaly,
    update_markov_model,
)

__all__ = (
    "adaptive_markov_signal",
    "canonical_behavior_flow",
    "compute_markov_features",
    "markov_pair_probability",
    "markov_sequence_probability",
    "markov_stage_probability",
    "markov_tag_rarity_score",
    "markov_transition_score",
    "tag_pair_anomaly",
    "update_markov_model",
)
