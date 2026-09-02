from __future__ import annotations

import inspect

from Virus_Scan.scheduler.context.config_snapshot import SchedulerConfigSnapshot as CanonicalSchedulerConfigSnapshot
from Virus_Scan.scheduler.internal import immutable_outputs
from Virus_Scan.scheduler.internal.scheduler_config import (
    SchedulerConfigSnapshot,
    SchedulerConfigSnapshotRequest,
    build_scheduler_config_snapshot,
)


def test_phase9_internal_scheduler_config_uses_context_owned_snapshot_contract() -> None:
    snapshot = build_scheduler_config_snapshot(
        SchedulerConfigSnapshotRequest(
            scheduler="process",
            max_workers="2",
            per_file_timeout_sec="5",
            progress_every="1",
            workload_limits={"raw": ["a", "b"]},
            environment={"mode": ["fast"]},
        )
    )

    assert SchedulerConfigSnapshot is CanonicalSchedulerConfigSnapshot
    assert isinstance(snapshot, CanonicalSchedulerConfigSnapshot)
    assert snapshot.workload_limits["raw"] == ("a", "b")
    assert snapshot.environment["mode"] == ("fast",)


def test_phase9_internal_immutable_outputs_no_longer_exposes_generic_phase_god_objects() -> None:
    removed_generic_contracts = {
        "SchedulerIngressOutput",
        "SchedulerOwnershipOutput",
        "SchedulerExecutionOutput",
        "SchedulerTimeoutOutput",
        "SchedulerReconciliationOutput",
        "SchedulerReplayOutput",
        "SchedulerEvidenceOutput",
        "SchedulerFinalizationOutput",
    }

    exported_classes = {name for name, value in inspect.getmembers(immutable_outputs, inspect.isclass)}

    assert removed_generic_contracts.isdisjoint(exported_classes)
    assert "FrozenSchedulerMapping" in exported_classes
