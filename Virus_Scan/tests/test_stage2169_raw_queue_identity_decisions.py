from pathlib import Path

from Virus_Scan.scheduler.queue import raw_queue_identity
from Virus_Scan.scheduler.queue.raw_queue_identity_decisions import (
    QueueIdentityIndexGetFailureDecision,
    QueueIdentityMappingDecision,
    queue_identity_index_get_failure_decision,
    queue_identity_mapping_decision,
)


class HostileValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook must not run")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook must not run")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("format hook must not run")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook must not run")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook must not run")


class HostileError(OSError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("exception str hook must not run")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("exception repr hook must not run")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("exception format hook must not run")


def test_stage2169_queue_identity_mapping_rejection_is_replayable_without_hooks() -> None:
    HostileValue.touched = 0

    decision = queue_identity_mapping_decision(HostileValue())

    assert isinstance(decision, QueueIdentityMappingDecision)
    assert decision.accepted is False
    assert decision.reason == "queue_identity_mapping_unsupported"
    assert decision.value_type == "HostileValue"
    assert decision.as_mapping_or_none() is None
    assert raw_queue_identity._owned_mapping_from_value(HostileValue()) is None
    assert HostileValue.touched == 0


def test_stage2169_queue_identity_mapping_accepts_string_key_snapshot() -> None:
    source = {"file": "sample.bin", 7: "ignored"}

    decision = queue_identity_mapping_decision(source)

    assert decision.accepted is True
    assert decision.reason == "queue_identity_mapping_accepted"
    assert decision.items == (("file", "sample.bin"),)
    assert decision.as_mapping_or_none() == {"file": "sample.bin"}
    assert raw_queue_identity._owned_mapping_from_value(source) == {"file": "sample.bin"}


def test_stage2169_queue_identity_index_failure_is_replayable_without_exception_text(tmp_path: Path) -> None:
    HostileError.touched = 0
    recorded = []

    def failing_get(*_args):
        raise HostileError("cache unavailable")

    original_get = raw_queue_identity._queue_identity_owned_get
    original_record = raw_queue_identity.record_scheduler_suppressed
    raw_queue_identity._queue_identity_owned_get = failing_get
    raw_queue_identity.record_scheduler_suppressed = lambda where, exc: recorded.append((where, type(exc).__name__))
    try:
        result = raw_queue_identity._queue_identity_index_get(tmp_path, ("pending",))
    finally:
        raw_queue_identity._queue_identity_owned_get = original_get
        raw_queue_identity.record_scheduler_suppressed = original_record
    decision = queue_identity_index_get_failure_decision(tmp_path, ("pending",), HostileError("again"))

    assert result is None
    assert recorded == [("queue_identity_index_get_failed", "HostileError")]
    assert isinstance(decision, QueueIdentityIndexGetFailureDecision)
    assert decision.accepted is False
    assert decision.reason == "queue_identity_index_get_failed"
    assert decision.queue_dir_type == "PosixPath"
    assert decision.states_type == "tuple"
    assert decision.error_type == "HostileError"
    assert decision.as_value() is None
    assert HostileError.touched == 0
