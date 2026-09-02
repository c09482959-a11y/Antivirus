from __future__ import annotations

import inspect

from Virus_Scan.scheduler.ownership import (
    process_queue_dynamic_feed,
    process_queue_dynamic_feed_contracts,
    process_queue_dynamic_feed_execution,
    process_queue_dynamic_feed_normalization,
    process_queue_dynamic_feed_support,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed import advance_process_queue_dynamic_feed
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_contracts import (
    ProcessQueueDynamicFeedDependencies,
    ProcessQueueDynamicFeedRequest,
)


class HostileFeedValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __int__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("int hook executed")


class HostileRecoverableTuple(tuple):
    touched = 0

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")


def _deps(**overrides):
    data = dict(
        build_feed_policy=lambda *args, **kwargs: object(),
        decide_feed=lambda *args, **kwargs: object(),
        write_jobs_slice=lambda *args, **kwargs: (0, 0, 0),
        mark_feed_complete=lambda path: None,
        progress_counts=lambda path: {},
        record_issue=lambda *args, **kwargs: None,
        log_error=lambda message: None,
        log_info=lambda message: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )
    data.update(overrides)
    return ProcessQueueDynamicFeedDependencies(**data)


def test_stage1870_dynamic_feed_dependency_recoverable_exceptions_are_sanitized_at_boundary_without_hooks():
    HostileRecoverableTuple.touched = 0

    deps = _deps(recoverable_exceptions=HostileRecoverableTuple((RuntimeError,)))

    assert HostileRecoverableTuple.touched == 0
    assert deps.recoverable_exceptions == (OSError, RuntimeError, TypeError, ValueError)


def test_stage1870_dynamic_feed_rejection_names_and_logging_do_not_execute_hostile_hooks():
    HostileFeedValue.reset()
    hostile = HostileFeedValue()
    issues: list[tuple[object, dict[str, object]]] = []
    logs: list[str] = []

    decision = type("Decision", (), {})()
    decision.feed_capacity = 1

    output = advance_process_queue_dynamic_feed(
        ProcessQueueDynamicFeedRequest(
            enabled=True,
            queue_dir="queue",
            ordered_queue_items=((0, 0, "a.bin"),),
            queue_feed_cursor=0,
            queue_total_enqueued=0,
            queue_enqueued_identities=(hostile,),
            target_workers=1,
            file_active_count=0,
            file_pending_count=0,
            io_pressure=False,
            cpu_sample=None,
            elastic_io_sample={"pressure": False, "reason": hostile},
            all_files_count=1,
            raw_live=0,
            current_time=20.0,
            queue_last_feed_log=0.0,
            env={},
        ),
        _deps(
            decide_feed=lambda *args, **kwargs: decision,
            write_jobs_slice=lambda *args, **kwargs: (1, 1, 0),
            record_issue=lambda stage, exc, **kwargs: issues.append((stage, kwargs)),
            log_info=logs.append,
        ),
    )

    assert HostileFeedValue.touched == 0
    assert output.queue_feed_cursor == 1
    assert output.queue_total_enqueued == 1
    assert output.queue_enqueued_identities == ()
    assert logs and "added=1" in logs[0]


def test_stage1870_dynamic_feed_sources_have_no_fstring_or_fallback_routes():
    combined = "\n".join(
        inspect.getsource(module)
        for module in (
            process_queue_dynamic_feed,
            process_queue_dynamic_feed_contracts,
            process_queue_dynamic_feed_execution,
            process_queue_dynamic_feed_normalization,
            process_queue_dynamic_feed_support,
        )
    )

    forbidden = (
        "safe_recoverable_exceptions(deps.recoverable_exceptions)",
        "fallback=",
        "fallback:",
        "dynamic feed fallback publication failed",
        'f"process_queue_feed_',
        'f"queue_enqueued_identities',
        'f"bulk scan dynamic queue feed',
        'f"dynamic process queue feed failed:',
    )
    offenders = [token for token in forbidden if token in combined]

    assert offenders == []
    assert "queue_enqueued_identities[" + int.__str__(0) + "]" == "queue_enqueued_identities[0]"
