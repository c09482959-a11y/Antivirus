"""Canonical temporal v5 package public surface."""
from __future__ import annotations

from Virus_Scan.contracts.temporal_accumulator import (
    TEMPORAL_ACCUMULATOR_VERSION,
)
from Virus_Scan.contracts.temporal_learning import TEMPORAL_MODEL_VERSION
from Virus_Scan.models.temporal.api import (
    build_temporal_history_timeline,
    compute_temporal_validation,
    detect_sequence_patterns,
    explain_temporal_drift,
    snapshot_temporal,
    transition_probability_overlay,
    update_temporal,
)
from Virus_Scan.models.temporal.evidence import (
    TEMPORAL_HIGH_RISK_TAGS,
    TEMPORAL_PHASE_ORDER,
    TEMPORAL_TAG_PHASES,
)

__all__ = (
    "TEMPORAL_ACCUMULATOR_VERSION",
    "TEMPORAL_HIGH_RISK_TAGS",
    "TEMPORAL_MODEL_VERSION",
    "TEMPORAL_PHASE_ORDER",
    "TEMPORAL_TAG_PHASES",
    "build_temporal_history_timeline",
    "compute_temporal_validation",
    "detect_sequence_patterns",
    "explain_temporal_drift",
    "snapshot_temporal",
    "transition_probability_overlay",
    "update_temporal",
)
