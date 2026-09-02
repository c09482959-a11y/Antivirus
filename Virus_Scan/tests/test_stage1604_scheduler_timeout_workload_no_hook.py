from __future__ import annotations

from Virus_Scan.scheduler.ownership.timeout_authority import build_timeout_authority_snapshot
from Virus_Scan.scheduler.timeout.inmemory_timeout_config_values import coerce_float_config, timeout_config_evidence
from Virus_Scan.scheduler.timeout.process_queue_monitor_values import monitor_float_config
from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget
from Virus_Scan.scheduler.timeout.timeout_budget_workload import safe_file_size_with_error


class HostileSchedulerScalar:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")


class HostileSchedulerTags:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool tags")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate tags")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len tags")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str tags")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr tags")


class HostileSchedulerOSError(OSError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str exception")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr exception")


def _reset() -> None:
    HostileSchedulerScalar.touched = 0
    HostileSchedulerTags.touched = 0
    HostileSchedulerOSError.touched = 0


def test_stage1604_compute_timeout_budget_rejects_hostile_workload_inputs_without_hooks() -> None:
    _reset()
    hostile = HostileSchedulerScalar()
    tags = HostileSchedulerTags()

    budget = compute_timeout_budget(
        hostile,
        configured_timeout_seconds=hostile,
        workload_class=hostile,
        method=hostile,
        tags=tags,
        deep_scan=hostile,
        recursion_depth=hostile,
        file_size_probe=lambda _path: 100,
    )

    assert "scheduler_file_size_probe_rejected" in (budget.inspection_error or "")
    assert budget.workload_class == "generic_scan"
    assert budget.file_size == 0
    assert budget.method == "generic_scan"
    assert budget.deep_scan is False
    assert budget.recursion_depth == 0
    assert "configured_timeout_seconds_rejected" in (budget.inspection_error or "")
    assert HostileSchedulerScalar.touched == 0
    assert HostileSchedulerTags.touched == 0


def test_stage1604_file_size_and_error_details_do_not_stringify_hostile_objects() -> None:
    _reset()
    hostile = HostileSchedulerScalar()

    size, error = safe_file_size_with_error("payload.bin", getsize=lambda _path: hostile)
    assert size == 0
    assert error == "scheduler_file_size_probe_rejected"
    assert HostileSchedulerScalar.touched == 0

    size, error = safe_file_size_with_error("payload.bin", getsize=lambda _path: (_ for _ in ()).throw(HostileSchedulerOSError("boom")))
    assert size == 0
    assert error == "scheduler_file_size_probe_rejected"
    assert HostileSchedulerOSError.touched == 0


def test_stage1604_timeout_config_evidence_rejects_hostile_raw_and_error_without_hooks() -> None:
    _reset()
    hostile = HostileSchedulerScalar()
    hostile_error = HostileSchedulerOSError("secret")

    value, evidence = coerce_float_config(setting="UMIGE_INMEMORY_PROGRESS_STALE_SEC", raw_value=hostile, default=120.0)
    assert value == 120.0
    assert evidence[0]["raw_value"]["unsupported_scheduler_value"] is True
    assert evidence[0]["detail"].startswith("ValueError:")

    monitor = monitor_float_config(
        setting="UMIGE_QUEUE_PROGRESS_STALL_SEC",
        raw_value=hostile,
        replacement=60.0,
        recoverable_exceptions=(Exception,),
    )
    assert monitor.value == 60.0
    assert monitor.evidence[0]["raw_value"]["unsupported_scheduler_value"] is True

    direct = timeout_config_evidence(setting="hostile", raw_value=hostile, default_value=hostile, error=hostile_error)
    assert direct["raw_value"]["unsupported_scheduler_value"] is True
    assert direct["default_value"]["unsupported_scheduler_value"] is True
    assert "secret" not in direct["detail"]
    assert HostileSchedulerScalar.touched == 0
    assert HostileSchedulerOSError.touched == 0


def test_stage1604_timeout_authority_rejects_hostile_boundaries_without_hooks() -> None:
    _reset()
    hostile = HostileSchedulerScalar()

    authority = build_timeout_authority_snapshot(
        hostile,
        minimum_hard_timeout_seconds=hostile,
        maximum_hard_timeout_seconds=hostile,
        source=hostile,
    )

    assert authority.configured_floor() == 0.0
    assert authority.minimum_hard_timeout_seconds == 30.0
    assert authority.maximum_hard_timeout_seconds == 86400.0
    assert authority.source == "scheduler_request"
    assert HostileSchedulerScalar.touched == 0
