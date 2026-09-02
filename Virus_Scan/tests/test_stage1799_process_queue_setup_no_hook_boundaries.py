from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.execution.process_queue_setup import (
    ProcessQueueSetupDependencies,
    ProcessQueueSetupOutput,
    ProcessQueueSetupRequest,
    initialize_process_queue_work,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup_admission import (
    ProcessQueueStartupAdmissionRequest,
    prepare_process_queue_startup_admission,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).getattribute_calls += 1
            raise AssertionError("__class__ hook must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("__str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("__repr__ hook must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise AssertionError("__format__ hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("__bool__ hook must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("__iter__ hook must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("__float__ hook must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("__int__ hook must not execute")


class SetupDependencyRecorder:
    def __init__(self) -> None:
        self.log_messages = []
        self.slice_inputs = None
        self.wrote_jobs = None
        self.marked = False

    def process_weight_for_path(self, _path):
        return HostileValue()

    def dynamic_process_queue_target(self, _process_count, _requested_process_count):
        return HostileValue(), HostileValue()

    def build_feed_policy(self, _env, **_kwargs):
        return {"policy": "owned"}

    def initial_file_feed_buffer(self, _process_count, _target_workers, _feed_policy):
        return HostileValue()

    def write_jobs(self, _queue_dir, all_files) -> None:
        self.wrote_jobs = all_files

    def write_jobs_slice(self, _queue_dir, ordered_queue_items, cursor, initial_buffer, queue_enqueued_identities):
        self.slice_inputs = (ordered_queue_items, cursor, initial_buffer, queue_enqueued_identities)
        return HostileValue(), HostileValue(), 0

    def mark_feed_complete(self, _queue_dir) -> None:
        self.marked = True

    def log_info(self, message) -> None:
        self.log_messages.append(message)


def _reset() -> None:
    HostileValue.str_calls = 0
    HostileValue.repr_calls = 0
    HostileValue.format_calls = 0
    HostileValue.bool_calls = 0
    HostileValue.iter_calls = 0
    HostileValue.float_calls = 0
    HostileValue.int_calls = 0
    HostileValue.getattribute_calls = 0


def _assert_no_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0


def test_stage1799_setup_request_rejects_hostile_scalars_without_hooks() -> None:
    _reset()

    request = ProcessQueueSetupRequest(
        all_files=HostileValue(),
        process_count=HostileValue(),
        requested_process_count=HostileValue(),
        dynamic_queue_feed=HostileValue(),
        env=None,
    )

    assert request.all_files[0]["unsupported_scheduler_value"] is True
    assert request.process_count == 0
    assert request.requested_process_count == 0
    assert request.dynamic_queue_feed is False
    _assert_no_hooks()


def test_stage1799_setup_output_rejects_hostile_scalars_and_identities_without_hooks() -> None:
    _reset()
    identity = HostileValue()

    output = ProcessQueueSetupOutput(
        ordered_queue_items=((0, 0, "game.exe"),),
        queue_feed_cursor=HostileValue(),
        queue_enqueued_identities={identity},
        queue_total_enqueued=HostileValue(),
    )

    assert output.queue_feed_cursor == 0
    assert output.queue_total_enqueued == 0
    assert output.queue_enqueued_identities == frozenset({"unsupported_queue_identity_0"})
    _assert_no_hooks()


def test_stage1799_initialize_dynamic_setup_rejects_hostile_dependency_outputs_without_hooks() -> None:
    _reset()
    recorder = SetupDependencyRecorder()
    request = ProcessQueueSetupRequest(
        all_files=("a.bin", "b.bin"),
        process_count=2,
        requested_process_count=4,
        dynamic_queue_feed=True,
        env={},
    )

    output = initialize_process_queue_work(
        Path("queue"),
        request,
        ProcessQueueSetupDependencies(
            process_weight_for_path=recorder.process_weight_for_path,
            dynamic_process_queue_target=recorder.dynamic_process_queue_target,
            build_feed_policy=recorder.build_feed_policy,
            initial_file_feed_buffer=recorder.initial_file_feed_buffer,
            write_jobs=recorder.write_jobs,
            write_jobs_slice=recorder.write_jobs_slice,
            mark_feed_complete=recorder.mark_feed_complete,
            log_info=recorder.log_info,
            recoverable_exceptions=(RuntimeError,),
        ),
    )

    assert output.queue_feed_cursor == 0
    assert output.queue_total_enqueued == 0
    assert recorder.slice_inputs[2] == 0
    assert "cpu=unavailable" in recorder.log_messages[0]
    _assert_no_hooks()


def test_stage1799_startup_admission_keeps_setup_scalars_owned_without_raw_conversion(
    tmp_path: Path,
) -> None:
    _reset()

    result = prepare_process_queue_startup_admission(
        ProcessQueueStartupAdmissionRequest(
            queue_dir=tmp_path / "queue",
            all_files=(),
            process_count="2",
            requested_process_count="3",
            dynamic_queue_feed=False,
        )
    )

    assert result.queue_feed_cursor == 0
    assert result.queue_total_enqueued == 0
    _assert_no_hooks()
