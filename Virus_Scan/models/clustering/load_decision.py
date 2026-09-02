"""Replayable cluster snapshot load decisions with canonical bool projection."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.models.clustering.common import safe_cluster_text
from Virus_Scan.models.clustering.mapping_boundaries import (
    cluster_reason_token,
    cluster_type_diagnostic,
)


@dataclass(frozen=True)
class ClusterSnapshotLoadDecision:
    """Owner-side snapshot load decision with explicit failure reason."""

    loaded: bool
    reason: str
    replay_record_required: bool = True

    def as_bool(self) -> bool:
        return self.loaded is True


def cluster_snapshot_load_failure(error: object) -> bool:
    log_error(cluster_type_diagnostic('runtime_cluster_state_load_failed', error))
    return ClusterSnapshotLoadDecision(
        False,
        'runtime_cluster_state_load_failed',
    ).as_bool()


def cluster_snapshot_load_rejected(reason: object) -> bool:
    decision = ClusterSnapshotLoadDecision(
        False,
        safe_cluster_text(reason, default_text='runtime_cluster_state_load_rejected'),
    )
    log_error(cluster_reason_token('runtime_cluster_state_load_rejected', decision.reason))
    return decision.as_bool()


__all__ = (
    'ClusterSnapshotLoadDecision',
    'cluster_snapshot_load_failure',
    'cluster_snapshot_load_rejected',
)
