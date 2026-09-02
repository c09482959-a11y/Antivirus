from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_boundary import (
    safe_bool_result,
    safe_heartbeat_flag_values,
    safe_worker_heartbeat_inputs,
)


class HostileValue:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def __int__(self):
        raise AssertionError("int hook executed")

    def __float__(self):
        raise AssertionError("float hook executed")

    def __repr__(self):
        raise AssertionError("repr hook executed")

    def __str__(self):
        raise AssertionError("str hook executed")


class HostileMapping:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def items(self):
        raise AssertionError("items hook executed")

    def get(self, _key, _default=None):
        raise AssertionError("get hook executed")


class HostileFlags:
    @property
    def running(self):
        raise AssertionError("descriptor hook executed")

    @property
    def cancel_request(self):
        raise AssertionError("descriptor hook executed")

    @property
    def poisoned_or_retire_mask(self):
        raise AssertionError("descriptor hook executed")


class HostileBool:
    def __bool__(self):
        raise AssertionError("bool hook executed")


def test_stage1952_heartbeat_flags_reject_hostile_descriptors_without_hooks() -> None:
    assert safe_heartbeat_flag_values(HostileFlags()) == (0, 0, 0)
    assert safe_heartbeat_flag_values(InMemoryHeartbeatFlags(running=1, cancel_request=2, poisoned=4, force_retire=8, stalled=16)) == (1, 2, 12)


def test_stage1952_heartbeat_inputs_reject_hostile_meta_without_mapping_hooks() -> None:
    result = safe_worker_heartbeat_inputs(
        meta=HostileMapping(),
        cfg=HostileMapping(),
        heartbeat_flags=HostileFlags(),
        completed_jobs=HostileValue(),
        process_id=HostileValue(),
        default_rss_limit=HostileValue(),
    )
    assert result[-1] == "unsupported_worker_heartbeat_meta"
    assert result[0:12] == ("unknown", 0, "scan", 0, 0, 0, 0.0, 0, 0, 0, 0, 0)


def test_stage1952_heartbeat_inputs_preserve_exact_dict_behavior() -> None:
    result = safe_worker_heartbeat_inputs(
        meta={
            "job_id": "job-1",
            "stage": "raw",
            "attempt": "2",
            "progress_counter": 3,
            "bytes_processed": "4",
            "last_progress_ns": 5,
        },
        cfg={"worker_rss_limit_mb": "256.5"},
        heartbeat_flags=InMemoryHeartbeatFlags(running=1, cancel_request=0, poisoned=2, force_retire=4, stalled=8),
        completed_jobs="6",
        process_id="7",
        default_rss_limit=128.0,
    )
    assert result[:12] == ("job-1", 2, "raw", 3, 4, 5, 256.5, 6, 7, 1, 0, 6)
    assert result[-1] == ""


def test_stage1952_safe_bool_result_rejects_hostile_bool_without_hook() -> None:
    assert safe_bool_result(HostileBool()) is False
