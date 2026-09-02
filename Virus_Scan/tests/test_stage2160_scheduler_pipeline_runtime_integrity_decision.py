from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.scheduler.orchestration.scheduler_file_worker import (
    scheduler_file_result_integrity_decision,
)


class HostileScanIntegrity(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("hostile scan_integrity __iter__ must not run")

    def __len__(self):
        type(self).touched += 1
        raise AssertionError("hostile scan_integrity __len__ must not run")

    def __getitem__(self, key):
        type(self).touched += 1
        raise AssertionError("hostile scan_integrity __getitem__ must not run")

    def items(self):
        type(self).touched += 1
        raise AssertionError("hostile scan_integrity items must not run")


def _reset_hostile() -> HostileScanIntegrity:
    HostileScanIntegrity.touched = 0
    return HostileScanIntegrity()


def test_stage2160_non_mapping_result_has_replayable_integrity_decision() -> None:
    decision = scheduler_file_result_integrity_decision(("not", "a", "mapping"))

    assert decision.accepted is False
    assert decision.reason == "scheduler_file_result_not_mapping"
    assert decision.result_type == "tuple"
    assert decision.integrity == {}


def test_stage2160_missing_scan_integrity_has_replayable_decision() -> None:
    decision = scheduler_file_result_integrity_decision({"file": "sample.bin"})

    assert decision.accepted is False
    assert decision.reason == "scheduler_file_result_scan_integrity_missing"
    assert decision.result_type == "dict"
    assert decision.integrity == {}


def test_stage2160_hostile_scan_integrity_records_unavailable_evidence_without_hooks() -> None:
    hostile = _reset_hostile()

    decision = scheduler_file_result_integrity_decision({"scan_integrity": hostile})

    assert HostileScanIntegrity.touched == 0
    assert decision.accepted is False
    assert decision.reason == "scheduler_mapping_unsupported_value"
    assert decision.integrity["unsupported_scheduler_value"] is True
    assert decision.integrity["replay_must_record"] is True
    assert decision.integrity["checkpoint_must_record"] is True
    assert decision.integrity["final_json_must_record"] is True
    assert decision.integrity["value_type"] == "HostileScanIntegrity"
