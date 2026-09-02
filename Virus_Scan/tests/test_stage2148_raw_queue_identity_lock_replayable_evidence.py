from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock
from Virus_Scan.scheduler.queue.identity_lock import (
    IdentityLockAcquireDecision,
    IdentityLockReleaseDecision,
)


class HostileIdentity:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("identity __str__ must not run")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("identity __repr__ must not run")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("identity __bool__ must not run")


class HostileQueueDir:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("queue_dir __fspath__ must not run")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("queue_dir __str__ must not run")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("queue_dir __bool__ must not run")


class HostileReleasePath:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("release path __fspath__ must not run")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("release path __str__ must not run")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("release path __bool__ must not run")


def test_stage2148_lock_path_unavailable_is_replayable_typed_decision() -> None:
    HostileQueueDir.reset()

    decision = identity_lock.acquire_identity_lock_decision(
        HostileQueueDir(),
        "file:stage2148",
    )

    assert type(decision) is IdentityLockAcquireDecision
    assert decision.acquired is False
    assert decision.lock_path is None
    assert decision.reason == "process_queue_identity_lock_failed_closed"
    assert HostileQueueDir.touched == 0


def test_stage2148_acquire_rejected_identity_has_replayable_canonical_value(tmp_path) -> None:
    HostileIdentity.reset()

    decision = identity_lock.acquire_identity_lock_decision(tmp_path, HostileIdentity())

    assert type(decision) is IdentityLockAcquireDecision
    assert decision.acquired is False
    assert decision.lock_path is None
    assert decision.reason == "process_queue_identity_lock_identity_rejected"
    assert HostileIdentity.touched == 0


def test_stage2148_release_bad_path_has_replayable_false_decision() -> None:
    HostileReleasePath.reset()
    events: list[tuple[str, str]] = []

    decision = identity_lock.release_identity_lock_decision(
        HostileReleasePath(),
        report_issue=lambda where, exc, **_kwargs: events.append((where, type(exc).__name__)),
    )

    assert type(decision) is IdentityLockReleaseDecision
    assert decision.released is False
    assert decision.reason == "process_queue_identity_lock_release_unsuccessful"
    assert events == [("process_queue_identity_lock_release_unsuccessful", "RuntimeError")]
    assert HostileReleasePath.touched == 0


def test_stage2148_superseded_raw_identity_lock_modules_are_absent() -> None:
    for path in (
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_acquire.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_materialization.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_release.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_evidence.py",
    ):
        assert not Path(path).exists()
