"""Stage2177 worker lifecycle replayable decision coverage."""
from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import inmemory_stage_is_pre_execution
from Virus_Scan.scheduler.workers.inmemory_worker_completion import collect_done_inmemory_worker_futures
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_boundary import exact_active_worker_items
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message import ingest_worker_heartbeat_message
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_decisions import (
    active_worker_heartbeat_items_decision,
    done_worker_futures_decision,
    worker_heartbeat_attempt_decision,
    worker_heartbeat_record_decision,
    worker_pre_execution_stage_decision,
)


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")


class HostileMapping(dict):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("mapping get hook executed")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("mapping items hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("mapping iter hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("mapping bool hook executed")


class DoneFuture:
    def __init__(self, done: bool) -> None:
        self._done = done

    def done(self) -> bool:
        return self._done


def test_stage2177_worker_lifecycle_decisions_record_rejections_without_hooks() -> None:
    HostileValue.reset()
    HostileMapping.reset()
    hostile = HostileValue()

    stage_decision = worker_pre_execution_stage_decision(hostile)
    active_decision = active_worker_heartbeat_items_decision(hostile)
    done_decision = done_worker_futures_decision(HostileMapping())

    assert stage_decision.value is False
    assert stage_decision.reason == "scheduler_text_rejected"
    assert stage_decision.evidence[0]["replay_must_record"] is True
    assert active_decision.items == ()
    assert active_decision.reason == "active_worker_heartbeat_items_rejected"
    assert done_decision.items == ()
    assert done_decision.reason == "inmemory_worker_active_mapping_rejected"
    assert HostileValue.touched == 0
    assert HostileMapping.touched == 0


def test_stage2177_worker_lifecycle_legacy_wrappers_keep_empty_outputs_without_hooks() -> None:
    HostileValue.reset()
    HostileMapping.reset()
    hostile = HostileValue()

    assert inmemory_stage_is_pre_execution(hostile) is False
    assert exact_active_worker_items(hostile) == ()
    assert collect_done_inmemory_worker_futures(HostileMapping()) == ()

    assert HostileValue.touched == 0
    assert HostileMapping.touched == 0


def test_stage2177_done_worker_future_decision_preserves_live_future_identity() -> None:
    done_future = DoneFuture(True)
    pending_future = DoneFuture(False)

    decision = done_worker_futures_decision({done_future: {"job_id": 1}, pending_future: {"job_id": 2}})

    assert decision.reason == ""
    assert decision.items == (done_future,)
    assert decision.items[0] is done_future


def test_stage2177_heartbeat_message_skip_decisions_are_replayable() -> None:
    missing = worker_heartbeat_record_decision(record=None, terminal=set(), job_id=1)
    terminal = worker_heartbeat_record_decision(record={"attempt": 0}, terminal={1}, job_id=1)
    rejected_attempt = worker_heartbeat_attempt_decision(record_attempt=None, attempt=2)
    mismatch = worker_heartbeat_attempt_decision(record_attempt=1, attempt=2)

    assert missing.value is False
    assert missing.reason == "inmemory_heartbeat_record_missing"
    assert terminal.reason == "inmemory_heartbeat_job_terminal"
    assert rejected_attempt.reason == "inmemory_heartbeat_record_attempt_rejected"
    assert mismatch.reason == "inmemory_heartbeat_attempt_mismatch"
    assert all(item.evidence[0]["checkpoint_must_record"] is True for item in (missing, terminal, rejected_attempt, mismatch))


def test_stage2177_heartbeat_message_legacy_false_paths_do_not_mutate_state() -> None:
    job_records = {1: {"attempt": 0, "state": "running"}}
    active = {1: {}}
    worker_heartbeats: dict[int, float] = {}
    worker_metrics: dict[int, dict[str, object]] = {}
    lifecycle: list[object] = []

    applied_terminal = ingest_worker_heartbeat_message(
        message=("heartbeat", 1, "sample.bin", 11, 1.0, 0, 1, "scan", 0, 0, 0),
        job_records=job_records,
        active=active,
        terminal={1},
        worker_heartbeats=worker_heartbeats,
        worker_metrics=worker_metrics,
        heartbeat_flags=InMemoryHeartbeatFlags(running=1, cancel_request=0, poisoned=0, stalled=0, force_retire=0),
        history_transition=lambda *args, **kwargs: args[1],
        cancel_job=lambda *args, **kwargs: None,
        lifecycle_recorder=lambda request: lifecycle.append(request),
        wall_time=lambda: 100.0,
    )
    applied_mismatch = ingest_worker_heartbeat_message(
        message=("heartbeat", 1, "sample.bin", 11, 1.0, 2, 1, "scan", 0, 0, 0),
        job_records=job_records,
        active=active,
        terminal=set(),
        worker_heartbeats=worker_heartbeats,
        worker_metrics=worker_metrics,
        heartbeat_flags=InMemoryHeartbeatFlags(running=1, cancel_request=0, poisoned=0, stalled=0, force_retire=0),
        history_transition=lambda *args, **kwargs: args[1],
        cancel_job=lambda *args, **kwargs: None,
        lifecycle_recorder=lambda request: lifecycle.append(request),
        wall_time=lambda: 100.0,
    )

    assert applied_terminal is False
    assert applied_mismatch is False
    assert job_records == {1: {"attempt": 0, "state": "running"}}
    assert worker_heartbeats == {}
    assert worker_metrics == {}
    assert lifecycle == []


def test_stage2177_unchanged_worker_heartbeat_updates_latest_state_without_history_growth() -> None:
    job_records = {
        1: {
            "attempt": 0,
            "state": "running",
            "last_progress_signature": ("scan", 0, 0, 0),
            "last_progress_time": 1.0,
        }
    }
    active = {1: {}}
    worker_heartbeats: dict[int, float] = {}
    worker_metrics: dict[int, dict[str, object]] = {}
    lifecycle: list[object] = []
    flags = InMemoryHeartbeatFlags(
        running=1,
        cancel_request=0,
        poisoned=0,
        stalled=0,
        force_retire=0,
    )

    for timestamp in (2.0, 3.0):
        assert ingest_worker_heartbeat_message(
            message=("heartbeat", 1, "sample.bin", 11, timestamp, 0, 0, "scan", 0, 0, 0),
            job_records=job_records,
            active=active,
            terminal=set(),
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
            heartbeat_flags=flags,
            history_transition=lambda *args, **kwargs: args[1],
            cancel_job=lambda *args, **kwargs: None,
            lifecycle_recorder=lambda request: lifecycle.append(request),
            wall_time=lambda: 100.0,
        ) is True

    assert lifecycle == []
    assert job_records[1]["last_heartbeat"] == 3.0
    assert worker_heartbeats == {11: 3.0}
    assert worker_metrics[11]["last_seen"] == 3.0
    assert job_records[1]["last_progress_time"] == 1.0


def test_stage2177_progressing_worker_heartbeat_records_one_lifecycle_transition() -> None:
    job_records = {
        1: {
            "attempt": 0,
            "state": "running",
            "last_progress_signature": ("scan", 0, 0, 0),
            "last_progress_time": 1.0,
        }
    }
    lifecycle: list[object] = []
    assert ingest_worker_heartbeat_message(
        message=("heartbeat", 1, "sample.bin", 11, 2.0, 0, 1, "scan", 4, 9, 0),
        job_records=job_records,
        active={1: {}},
        terminal=set(),
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_flags=InMemoryHeartbeatFlags(
            running=1,
            cancel_request=0,
            poisoned=0,
            stalled=0,
            force_retire=0,
        ),
        history_transition=lambda *args, **kwargs: args[1],
        cancel_job=lambda *args, **kwargs: None,
        lifecycle_recorder=lambda request: lifecycle.append(request),
        wall_time=lambda: 100.0,
    ) is True
    assert len(lifecycle) == 1
    assert lifecycle[0].transition == "heartbeat"
    assert job_records[1]["last_progress_signature"] == ("scan", 1, 4, 9)
