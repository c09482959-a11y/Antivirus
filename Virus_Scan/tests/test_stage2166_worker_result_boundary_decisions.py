from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.scheduler.internal.worker_result_boundary import (
    scheduler_owned_mapping_snapshot,
    scheduler_scan_integrity_snapshot,
)
from Virus_Scan.scheduler.internal.worker_result_boundary_decisions import (
    scheduler_owned_mapping_decision,
    scheduler_scan_integrity_decision,
)


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("hostile mapping iteration must not run")

    def __len__(self):
        type(self).touched += 1
        raise AssertionError("hostile mapping length must not run")

    def __getitem__(self, key):
        type(self).touched += 1
        raise AssertionError("hostile mapping lookup must not run")

    def items(self):
        type(self).touched += 1
        raise AssertionError("hostile mapping items must not run")


def _hostile() -> HostileMapping:
    HostileMapping.touched = 0
    return HostileMapping()


def test_scheduler_owned_mapping_rejection_is_replayable_without_hooks():
    hostile = _hostile()

    decision = scheduler_owned_mapping_decision(hostile)

    assert HostileMapping.touched == 0
    assert decision.accepted is False
    assert decision.reason == "scheduler_owned_mapping_not_materializable"
    assert decision.value_type == "HostileMapping"
    assert scheduler_owned_mapping_snapshot(hostile) is None


def test_missing_scan_integrity_no_longer_collapses_to_empty_dict():
    decision = scheduler_scan_integrity_decision(
        None,
        unavailable_reason="non_materializable_test_integrity",
        original_type_field="test_integrity_original_type",
        unavailable_flag="test_integrity_unavailable",
        unavailable_reason_field="test_integrity_unavailable_reason",
    )

    assert decision.accepted is False
    assert decision.reason == "missing_scan_integrity"
    snapshot = scheduler_scan_integrity_snapshot(
        None,
        unavailable_reason="non_materializable_test_integrity",
        original_type_field="test_integrity_original_type",
        unavailable_flag="test_integrity_unavailable",
        unavailable_reason_field="test_integrity_unavailable_reason",
    )
    assert snapshot != {}
    assert snapshot["test_integrity_unavailable"] is True
    assert snapshot["scan_integrity_unavailable"] is True
    assert snapshot["scan_integrity_unavailable_reason"] == "missing_scan_integrity"
    assert snapshot["test_integrity_original_type"] == "NoneType"
    assert snapshot["queue_failure"] is True
    assert snapshot["allow_learning"] is False


def test_unsupported_scan_integrity_records_configured_reason_without_hooks():
    hostile = _hostile()

    snapshot = scheduler_scan_integrity_snapshot(
        hostile,
        unavailable_reason="non_materializable_worker_result_integrity",
        original_type_field="worker_result_integrity_original_type",
        unavailable_flag="worker_result_integrity_unavailable",
        unavailable_reason_field="worker_result_integrity_unavailable_reason",
    )

    assert HostileMapping.touched == 0
    assert snapshot["worker_result_integrity_unavailable"] is True
    assert snapshot["scan_integrity_unavailable"] is True
    assert snapshot["scan_integrity_unavailable_reason"] == "non_materializable_worker_result_integrity"
    assert snapshot["worker_result_integrity_original_type"] == "HostileMapping"
