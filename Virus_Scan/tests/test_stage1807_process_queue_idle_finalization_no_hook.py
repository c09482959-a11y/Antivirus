from __future__ import annotations

from dataclasses import fields

from Virus_Scan.scheduler.queue.terminal_accounting import IdleQueueFinalizationRequest

from Virus_Scan.scheduler.queue.process_queue_idle_finalization import (
    ProcessQueueIdleFinalizationDependencies,
    ProcessQueueIdleFinalizationRequest,
    reconcile_process_queue_idle_finalization,
)


class HostileIdleValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.getattribute_calls = 0

    @classmethod
    def total_calls(cls) -> int:
        return (
            cls.str_calls
            + cls.repr_calls
            + cls.format_calls
            + cls.bool_calls
            + cls.iter_calls
            + cls.float_calls
            + cls.int_calls
            + cls.getattribute_calls
        )

    def __getattribute__(self, name: str):  # pragma: no cover - must never execute
        type(self).getattribute_calls += 1
        raise RuntimeError(f"idle value attribute access is forbidden: {name}")

    def __str__(self):  # pragma: no cover - must never execute
        type(self).str_calls += 1
        raise RuntimeError("idle value stringification is forbidden")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).repr_calls += 1
        raise RuntimeError("idle value repr is forbidden")

    def __format__(self, spec):  # pragma: no cover - must never execute
        type(self).format_calls += 1
        raise RuntimeError("idle value formatting is forbidden")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).bool_calls += 1
        raise RuntimeError("idle value truth testing is forbidden")

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).iter_calls += 1
        raise RuntimeError("idle value iteration is forbidden")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).float_calls += 1
        raise RuntimeError("idle value float conversion is forbidden")

    def __int__(self):  # pragma: no cover - must never execute
        type(self).int_calls += 1
        raise RuntimeError("idle value int conversion is forbidden")


def _unused_callable(*_args, **_kwargs):
    return None


def _idle_queue_finalization_decision(_request):
    return False, 0.0


def _dependencies():
    return ProcessQueueIdleFinalizationDependencies(
        load_queue_file_results=_unused_callable,
        worker_error_result=_unused_callable,
        terminate_worker=_unused_callable,
        report=_unused_callable,
        log_error=_unused_callable,
        log_info=_unused_callable,
        sleep=_unused_callable,
        idle_queue_finalization_request_factory=IdleQueueFinalizationRequest,
        idle_queue_finalization_request_owner=_idle_queue_finalization_decision,
    )


def test_stage1807_idle_finalization_request_rejects_hostile_scalars_without_hooks():
    HostileIdleValue.reset()

    request = ProcessQueueIdleFinalizationRequest(
        feed_complete=HostileIdleValue(),
        no_live_queue_work=HostileIdleValue(),
        accounted_files=HostileIdleValue(),
        total_files=HostileIdleValue(),
        idle_done_since=HostileIdleValue(),
        now=HostileIdleValue(),
        idle_grace_sec=HostileIdleValue(),
        idle_notice_sec=HostileIdleValue(),
        all_files=HostileIdleValue(),
        queue_dir=HostileIdleValue(),
        outputs_dir=HostileIdleValue(),
        procs=HostileIdleValue(),
        live_workers=HostileIdleValue(),
    )

    assert request.feed_complete is False
    assert request.no_live_queue_work is False
    assert request.accounted_files == 0
    assert request.total_files == 0
    assert request.idle_done_since == 0.0
    assert request.now == 0.0
    assert request.idle_grace_sec == 0.0
    assert request.idle_notice_sec == 0.0
    assert request.live_workers == 0
    assert len(request.all_files) == 1
    assert len(request.procs) == 1
    assert HostileIdleValue.total_calls() == 0


def test_stage1807_idle_reconcile_rejects_hostile_request_and_dependencies_without_hooks():
    HostileIdleValue.reset()

    output = reconcile_process_queue_idle_finalization(HostileIdleValue(), HostileIdleValue())

    assert output.idle_done_since is None
    assert output.idle_notice_sec == 0.0
    assert output.had_error is True
    assert output.should_stop is False
    assert HostileIdleValue.total_calls() == 0


def test_stage1807_idle_dependencies_have_no_alternate_finalization_or_writer_path():
    dependency_fields = {field.name for field in fields(ProcessQueueIdleFinalizationDependencies)}
    assert "finalize_missing_file_accounting" not in dependency_fields
    assert "write_worker_output" not in dependency_fields


def test_stage1807_idle_finalization_preserves_exact_text_scalars():
    request = ProcessQueueIdleFinalizationRequest(
        feed_complete="true",
        no_live_queue_work="true",
        accounted_files="2",
        total_files="2",
        idle_done_since="1.5",
        now="3.5",
        idle_grace_sec="10.0",
        idle_notice_sec="0.25",
        all_files=("a", "b"),
        queue_dir="queue",
        outputs_dir="outputs",
        procs=(),
        live_workers="4",
    )

    assert request.feed_complete is True
    assert request.no_live_queue_work is True
    assert request.accounted_files == 2
    assert request.total_files == 2
    assert request.idle_done_since == 1.5
    assert request.now == 3.5
    assert request.idle_grace_sec == 10.0
    assert request.idle_notice_sec == 0.25
    assert request.all_files == ("a", "b")
    assert request.live_workers == 4
