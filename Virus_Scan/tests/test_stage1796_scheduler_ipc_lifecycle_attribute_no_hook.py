from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache

from Virus_Scan.scheduler.workers.ipc_lifecycle import (
    close_owned_ipc_queue,
    shutdown_worker_processes,
    stop_worker_heartbeat,
)
from Virus_Scan.scheduler.orchestration import inmemory_parent_respawn
from Virus_Scan.scheduler.orchestration.inmemory_parent_respawn import InMemoryRespawnSweepRequest
from Virus_Scan.scheduler.queue.inmemory_result_completion import complete_inmemory_result_message
from Virus_Scan.scheduler.queue.raw_accumulator_lock import GlobalRawAccumLock
from Virus_Scan.scheduler.workers.inmemory_spawn import InMemoryWorkerRespawnResult


class HostileAttributeObject:
    touched = 0

    def __getattribute__(self, name):  # pragma: no cover - failure proves unsafe probing
        type(self).touched += 1
        raise AssertionError(f"caller-owned attribute hook invoked for {name}")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ invoked")


class HostileDescriptorObject:
    touched = 0

    @property
    def join(self):  # pragma: no cover - failure proves unsafe descriptor traversal
        type(self).touched += 1
        raise AssertionError("caller-owned join descriptor invoked")

    @property
    def cancel_join_thread(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned queue descriptor invoked")

    @property
    def set(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned event descriptor invoked")


def _reset() -> None:
    HostileAttributeObject.touched = 0
    HostileDescriptorObject.touched = 0


def test_stage1796_close_owned_ipc_queue_rejects_hostile_attribute_hooks_without_touching_them() -> None:
    _reset()

    status = close_owned_ipc_queue(HostileAttributeObject())

    assert status["closed"] is False
    assert status["errors"][0] == {
        "stage": "queue_cancel_join_thread_rejected",
        "error": "unsafe_worker_lifecycle_getattribute_rejected",
    }
    assert HostileAttributeObject.touched == 0


def test_stage1796_shutdown_worker_processes_rejects_hostile_process_hooks_without_touching_them() -> None:
    _reset()

    summary = shutdown_worker_processes([HostileAttributeObject()], exit_grace_sec=0.0)

    stages = [entry["stage"] for entry in summary["errors"]]
    assert "worker_join_rejected" in stages
    assert "worker_alive_check_rejected" in stages
    assert "worker_final_alive_check_rejected" in stages
    assert "worker_final_join_rejected" in stages
    assert "worker_close_rejected" in stages
    assert {entry["error"] for entry in summary["errors"]} == {
        "unsafe_worker_lifecycle_getattribute_rejected"
    }
    assert HostileAttributeObject.touched == 0


def test_stage1796_stop_worker_heartbeat_rejects_hostile_event_and_thread_hooks_without_touching_them() -> None:
    _reset()

    stop_status = stop_worker_heartbeat(HostileAttributeObject(), None)
    thread_status = stop_worker_heartbeat(None, HostileAttributeObject())

    assert stop_status["error"] == "unsafe_worker_lifecycle_getattribute_rejected"
    assert thread_status["error"] == "unsafe_worker_lifecycle_getattribute_rejected"
    assert HostileAttributeObject.touched == 0


def test_stage1796_ipc_lifecycle_rejects_hostile_descriptors_without_traversal() -> None:
    _reset()

    queue_status = close_owned_ipc_queue(HostileDescriptorObject())
    process_summary = shutdown_worker_processes([HostileDescriptorObject()], exit_grace_sec=0.0)
    heartbeat_status = stop_worker_heartbeat(HostileDescriptorObject(), HostileDescriptorObject())

    assert queue_status["errors"][0]["error"] == "unsafe_worker_lifecycle_descriptor_rejected"
    assert process_summary["errors"][0]["error"] == "unsafe_worker_lifecycle_descriptor_rejected"
    assert heartbeat_status["error"] == "unsafe_worker_lifecycle_descriptor_rejected"
    assert HostileDescriptorObject.touched == 0


def test_stage1796_raw_accumulator_lock_rejects_hostile_dependencies_and_name_without_hooks(tmp_path) -> None:
    _reset()
    try:
        GlobalRawAccumLock(tmp_path, "ok", deps=HostileAttributeObject())
    except TypeError as exc:
        assert "raw_accumulator_deps_record_scheduler_suppressed_instance_dict_rejected" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("hostile dependencies must be rejected")
    assert HostileAttributeObject.touched == 0

    class Deps:
        def record_scheduler_suppressed(self, *_args, **_kwargs):
            return None

    try:
        GlobalRawAccumLock(tmp_path, HostileAttributeObject(), deps=Deps())
    except TypeError as exc:
        assert "raw_accumulator_lock_name_rejected" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("hostile lock names must be rejected")
    assert HostileAttributeObject.touched == 0


def test_stage1796_inmemory_result_completion_rejects_terminal_transition_descriptor_without_touching_it(tmp_path) -> None:
    _reset()

    class Recovery:
        completed = 0

        def record_lifecycle_request(self, *_args, **_kwargs):
            return None

        @property
        def terminal_transition(self):  # pragma: no cover
            HostileDescriptorObject.touched += 1
            raise AssertionError("terminal_transition descriptor executed")

    record = {"attempt": 0, "started_at": 10.0, "queued_at": 10.0}
    results = {}
    outcome = complete_inmemory_result_message(
        message=("result", 1, tmp_path / "sample.bin", "ok", 123, 11.0, 0),
        job_records={1: record},
        active={1: object()},
        terminal=set(),
        failed=set(),
        done=set(),
        results=results,
        recovery=Recovery(),
        state_index=InMemorySchedulerStateIndex(),
        container_root=tmp_path,
        routing_evidence_context={},
        routing_evidence_attacher=lambda **kwargs: kwargs["result"],
        attach_result_evidence=lambda **kwargs: kwargs["result"],
        record_stage_cost_observation=lambda **_kwargs: None,
        publish_partial_results=lambda _request: None,
        partial_output_path=tmp_path / "partial.json",
        partial_output_every=1,
        partial_writer=lambda *_args, **_kwargs: None,
        partial_checkpoint_cache=PartialCheckpointCache(),
        log_error=lambda _message: None,
        bulk_scan_maintenance=lambda _completed: None,
        log_bulk_progress=lambda **_kwargs: None,
        started_at=0.0,
        progress_every=1,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        wall_time=lambda: 11.0,
        sleep=lambda _seconds: None,
        recoverable_exceptions=(Exception,),
        suppressed_recorder=lambda *_args: None,
    )

    assert outcome.handled is True
    assert record["state"] == "done"
    assert record["terminal_transition_unavailable"] == "unsafe_inmemory_recovery_descriptor_rejected"
    assert HostileDescriptorObject.touched == 0


def test_stage1796_inmemory_respawn_does_not_probe_hostile_process_container_or_exception_text() -> None:
    _reset()
    messages: list[str] = []

    def fake_respawn(*_args, **_kwargs):
        return InMemoryWorkerRespawnResult(respawn_sequence=4, started=1, processes=(object(),))

    original_respawn = inmemory_parent_respawn.respawn_missing_inmemory_workers
    inmemory_parent_respawn.respawn_missing_inmemory_workers = fake_respawn
    try:
        result = inmemory_parent_respawn.run_inmemory_respawn_sweep(
        InMemoryRespawnSweepRequest(
            ctx=object(),
            procs=HostileAttributeObject(),
            pending=(1,),
            active={},
            target_workers=1,
            task_queue=object(),
            result_queue=object(),
            worker_config={},
            lifecycle_epoch="epoch",
            respawn_sequence=3,
            state_index=InMemorySchedulerStateIndex(),
            worker_metrics={},
            recoverable_exceptions=(RuntimeError,),
        )
        )
    finally:
        inmemory_parent_respawn.respawn_missing_inmemory_workers = original_respawn
    assert result.started == 1
    assert HostileAttributeObject.touched == 0

    class HostileRespawnError(RuntimeError):
        touched = 0

        def __str__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("exception __str__ executed")

        def __repr__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("exception __repr__ executed")

    def raise_respawn(*_args, **_kwargs):
        raise HostileRespawnError("boom")

    inmemory_parent_respawn.respawn_missing_inmemory_workers = raise_respawn
    try:
        result = inmemory_parent_respawn.run_inmemory_respawn_sweep(
        InMemoryRespawnSweepRequest(
            ctx=object(),
            procs=[],
            pending=(1,),
            active={},
            target_workers=1,
            task_queue=object(),
            result_queue=object(),
            worker_config={},
            lifecycle_epoch="epoch",
            respawn_sequence=9,
            state_index=InMemorySchedulerStateIndex(),
            worker_metrics={},
            recoverable_exceptions=(RuntimeError,),
        )
        )
    finally:
        inmemory_parent_respawn.respawn_missing_inmemory_workers = original_respawn
    assert result.started == 0
    assert messages == []
    assert HostileRespawnError.touched == 0
