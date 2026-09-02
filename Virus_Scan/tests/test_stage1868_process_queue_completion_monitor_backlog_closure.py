from __future__ import annotations

import inspect

from Virus_Scan.scheduler.orchestration import process_queue_completion_evidence
from Virus_Scan.scheduler.orchestration.process_queue_completion_evidence import (
    attach_scheduler_evidence_to_merged_results,
    attach_worker_exit_evidence_to_merged_results,
    collect_nonclean_worker_exit_evidence,
)
from Virus_Scan.scheduler.orchestration import process_queue_monitor_contracts


class HostileMergedResults:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def values(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("values hook executed")

    def items(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("items hook executed")

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")


class HostileStatus:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __int__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")


def test_stage1868_worker_exit_status_rejects_hostile_status_without_default_cleaning_or_hooks():
    HostileStatus.reset()

    collected = collect_nonclean_worker_exit_evidence(({"worker_exit_status": HostileStatus()},))

    assert HostileStatus.touched == 0
    assert len(collected) == 1
    assert collected[0]["worker_exit_status"]["unsupported_scheduler_value"] is True
    assert collected[0]["worker_exit_status"]["field_name"] == "scheduler_value"


def test_stage1868_worker_exit_attachment_rejects_non_dict_merged_before_values_hook():
    HostileMergedResults.reset()
    hostile_merged = HostileMergedResults()

    attach_worker_exit_evidence_to_merged_results(hostile_merged, ({"worker_exit_status": -1},))

    assert HostileMergedResults.touched == 0


def test_stage1868_scheduler_evidence_attachment_rejects_non_dict_merged_before_values_hook():
    HostileMergedResults.reset()
    hostile_merged = HostileMergedResults()

    attach_scheduler_evidence_to_merged_results(hostile_merged, ())

    assert HostileMergedResults.touched == 0


def test_stage1868_completion_and_monitor_contracts_have_no_legacy_fallback_keyword_routes():
    completion_source = inspect.getsource(process_queue_completion_evidence)
    monitor_source = inspect.getsource(process_queue_monitor_contracts)

    assert "fallback=" not in completion_source
    assert "fallback=" not in monitor_source
    assert 'f"unsupported_queue_identity_' not in monitor_source
