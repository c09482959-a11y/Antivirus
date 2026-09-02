from __future__ import annotations

from Virus_Scan.scheduler.queue import identity_lock


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not float")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not int")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not bool")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not str")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not repr")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not format")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not iter")


class HostileIdentity(HostileScalar):
    pass


class HostileReleaseResult(HostileScalar):
    pass


def test_stage1813_identity_lock_fails_closed_on_hostile_stale_seconds(tmp_path) -> None:
    HostileScalar.reset()

    decision = identity_lock.acquire_identity_lock_decision(
        tmp_path,
        "file:stage1813-stale",
        stale_sec=HostileScalar(),
    )

    assert decision.acquired is False
    assert decision.reason == "process_queue_identity_stale_seconds_rejected"
    assert HostileScalar.touched == 0
    assert not list((tmp_path / "identity_locks").glob("*.lock"))


def test_stage1813_identity_lock_rejects_non_string_identity_without_hooks(tmp_path) -> None:
    HostileIdentity.reset()

    decision = identity_lock.acquire_identity_lock_decision(tmp_path, HostileIdentity())

    assert decision.acquired is False
    assert decision.reason == "process_queue_identity_lock_identity_rejected"
    assert HostileIdentity.touched == 0


def test_stage1813_release_identity_lock_rejects_hostile_unlink_result_without_hooks(tmp_path) -> None:
    HostileReleaseResult.reset()
    events = []
    lock_path = tmp_path / "stage1813-release.lock"
    lock_path.write_text("lock", encoding="utf-8")

    decision = identity_lock.release_identity_lock_decision(
        lock_path,
        safe_unlink=lambda _path, log_context: HostileReleaseResult(),
        report_issue=lambda where, exc, **_kwargs: events.append((where, type(exc).__name__)),
    )

    assert decision.released is False
    assert HostileReleaseResult.touched == 0
    assert events == [("process_queue_identity_lock_release_result_rejected", "ValueError")]
