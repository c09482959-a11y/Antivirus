"""Stage1953 scheduler worker heartbeat cycle/value no-hook closure."""
from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import publish_inmemory_worker_heartbeat_cycle
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message import ingest_worker_heartbeat_message
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publisher import publish_active_worker_heartbeats
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_values import heartbeat_float, heartbeat_int, heartbeat_text, wall_time_value


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("format hook executed")

    def __int__(self):
        type(self).touched += 1
        raise AssertionError("int hook executed")

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("float hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("bool hook executed")


class HostileFieldName:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("field name str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("field name repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("field name format hook executed")


class HostileBoolResult:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("bool hook executed")


def test_stage1953_heartbeat_value_reasons_do_not_format_hostile_field_names() -> None:
    HostileScalar.reset()
    HostileFieldName.touched = 0
    field = HostileFieldName()

    assert heartbeat_int(HostileScalar(), field_name=field) is None
    assert heartbeat_float(HostileScalar(), field_name=field) is None
    assert heartbeat_text(HostileScalar(), field_name=field, missing_text="scan") is None
    assert HostileScalar.touched == 0
    assert HostileFieldName.touched == 0


def test_stage1953_wall_time_failure_is_explicit_not_clean_none() -> None:
    def broken_wall_time() -> float:
        raise RuntimeError("clock unavailable")

    with pytest.raises(ValueError, match="wall time unavailable"):
        wall_time_value(broken_wall_time)


def test_stage1953_heartbeat_message_wall_time_failure_leaves_state_unmutated() -> None:
    job_records = {1: {"attempt": 0, "state": "running"}}
    active = {1: {}}
    worker_heartbeats: dict[int, float] = {}
    worker_metrics: dict[int, dict[str, object]] = {}

    with pytest.raises(ValueError, match="wall time unavailable"):
        ingest_worker_heartbeat_message(
            message=("heartbeat", 1, "sample.bin", 7, 0.0, 0, 1, "scan", 0, 0, 0),
            job_records=job_records,
            active=active,
            terminal=set(),
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
            heartbeat_flags=InMemoryHeartbeatFlags(running=1, cancel_request=2, poisoned=4, stalled=8, force_retire=16),
            history_transition=lambda *args, **kwargs: args[1],
            cancel_job=lambda *args, **kwargs: None,
            lifecycle_recorder=lambda _request: None,
            wall_time=lambda: (_ for _ in ()).throw(RuntimeError("clock unavailable")),
        )

    assert job_records == {1: {"attempt": 0, "state": "running"}}
    assert active == {1: {}}
    assert worker_heartbeats == {}
    assert worker_metrics == {}


def test_stage1953_publisher_exception_uses_single_validated_parse_without_bool_hooks() -> None:
    HostileBoolResult.touched = 0
    meta = {"job_id": 44, "attempt": 2, "stage": "scan", "progress_counter": 1}
    reports: list[str] = []

    publish_active_worker_heartbeats(
        active_items=((object(), meta),),
        cfg={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=InMemoryHeartbeatFlags(running=1, cancel_request=2, poisoned=4, stalled=8, force_retire=16),
        completed_jobs=0,
        cancel_requested=lambda *_args, **_kwargs: HostileBoolResult(),
        update_shared_heartbeat=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("writer failed")),
        process_id=9,
        now_hb=12.0,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda label, _exc: reports.append(label),
    )

    assert HostileBoolResult.touched == 0
    assert reports == ["worker_heartbeat_publish_failed"]
    evidence = meta["heartbeat_publish_evidence"]
    assert evidence["worker_heartbeat_job_id"] == "44"
    assert evidence["worker_heartbeat_attempt"] == 2
    assert evidence["worker_heartbeat_stage"] == "scan"
    assert meta["heartbeat_publish_failed"] is True


def test_stage1953_record_suppressed_failure_is_evidence_not_sentinel_return() -> None:
    meta = {"job_id": 45, "attempt": 1, "stage": "scan", "progress_counter": 1}

    publish_active_worker_heartbeats(
        active_items=((object(), meta),),
        cfg={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=InMemoryHeartbeatFlags(running=1, cancel_request=2, poisoned=4, stalled=8, force_retire=16),
        completed_jobs=0,
        cancel_requested=lambda *_args, **_kwargs: False,
        update_shared_heartbeat=lambda *_args, **_kwargs: False,
        process_id=9,
        now_hb=12.0,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("report failed")),
    )

    assert meta["heartbeat_publish_failed"] is True
    assert "RuntimeError" in meta["heartbeat_publish_report_failed"]


def test_stage1953_heartbeat_cycle_source_removes_keyword_default_routes() -> None:
    root = Path(__file__).resolve().parents[1] / "scheduler" / "workers"
    cycle = (root / "inmemory_worker_heartbeat_cycle.py").read_text(encoding="utf-8")
    values = (root / "inmemory_worker_heartbeat_values.py").read_text(encoding="utf-8")
    publisher = (root / "inmemory_worker_heartbeat_publisher.py").read_text(encoding="utf-8")

    assert "fallback=" not in cycle
    assert "default=0" not in cycle
    assert "default=0.0" not in cycle
    assert "reason=f\"inmemory_heartbeat_" not in values
    assert "except (OSError, RuntimeError, TypeError, ValueError):\n        return None" not in values
    assert "except recoverable_exceptions:\n        return" not in publisher
    assert "fallback = safe_worker_heartbeat_inputs" not in publisher
    assert "meta=fallback[12]" not in publisher
