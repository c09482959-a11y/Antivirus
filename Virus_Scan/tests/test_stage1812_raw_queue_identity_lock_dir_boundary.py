from __future__ import annotations

import hashlib

from Virus_Scan.scheduler.queue import identity_lock


class HostileQueueDir:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not fspath")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not str")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not repr")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not format")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not bool")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("must not iter")


def test_stage1812_identity_lock_rejects_hostile_queue_dir_without_hooks() -> None:
    HostileQueueDir.reset()

    decision = identity_lock.acquire_identity_lock_decision(
        HostileQueueDir(),
        "file:stage1812",
    )

    assert decision.acquired is False
    assert decision.lock_path is None
    assert decision.reason == "process_queue_identity_lock_failed_closed"
    assert HostileQueueDir.touched == 0


def test_stage1812_identity_lock_preserves_valid_queue_dir(tmp_path) -> None:
    decision = identity_lock.acquire_identity_lock_decision(tmp_path, "file:stage1812")

    assert decision.acquired is True
    assert decision.lock_path is not None
    assert decision.lock_path.exists()
    assert identity_lock.release_identity_lock_decision(decision.lock_path).released is True


def test_stage1812_identity_lock_uses_full_sha256_identity_token(tmp_path) -> None:
    identity = "file:stage1812-full-digest"
    expected = hashlib.sha256(identity.encode("utf-8", "surrogatepass")).hexdigest() + ".lock"

    decision = identity_lock.acquire_identity_lock_decision(tmp_path, identity)

    assert decision.acquired is True
    assert decision.lock_path is not None
    assert decision.lock_path.name == expected
    assert len(decision.lock_path.stem) == 64
    assert identity_lock.release_identity_lock_decision(decision.lock_path).released is True
