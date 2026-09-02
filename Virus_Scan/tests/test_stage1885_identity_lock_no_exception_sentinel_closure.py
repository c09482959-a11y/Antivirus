from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock


class HostileQueueDir:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __fspath__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("fspath")

    def __str__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("repr")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("format")

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("bool")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("iter")


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __float__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("float")

    def __int__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("int")

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("bool")

    def __str__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("repr")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("format")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("iter")


class HostileReleaseResult:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("bool")

    def __str__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("repr")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("format")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("iter")


def _identity_lock_tree() -> ast.Module:
    root = Path(__file__).resolve().parents[2]
    source = root / "Virus_Scan" / "scheduler" / "queue" / "identity_lock.py"
    return parse_python_file(source)


def test_stage1885_acquire_identity_lock_rejects_hostile_queue_dir_without_hooks() -> None:
    HostileQueueDir.reset()

    decision = identity_lock.acquire_identity_lock_decision(HostileQueueDir(), "file:stage1885-hostile-dir")

    assert decision.acquired is False
    assert HostileQueueDir.touched == 0


def test_stage1885_acquire_identity_lock_rejects_hostile_stale_seconds_without_hooks(tmp_path) -> None:
    HostileScalar.reset()

    decision = identity_lock.acquire_identity_lock_decision(
        tmp_path,
        "file:stage1885-hostile-stale",
        stale_sec=HostileScalar(),
    )

    assert decision.acquired is False
    assert HostileScalar.touched == 0
    assert not any((tmp_path / "identity_locks").glob("*.lock"))


def test_stage1885_release_identity_lock_rejects_hostile_unlink_result_without_hooks(tmp_path) -> None:
    HostileReleaseResult.reset()
    records: list[tuple[str, str]] = []
    lock_path = tmp_path / "stage1885-release.lock"
    lock_path.write_text("lock", encoding="utf-8")

    decision = identity_lock.release_identity_lock_decision(
        lock_path,
        safe_unlink=lambda _path, log_context: HostileReleaseResult(),
        report_issue=lambda where, exc, **_kwargs: records.append((where, type(exc).__name__)),
    )

    assert decision.released is False
    assert HostileReleaseResult.touched == 0
    assert records == [("process_queue_identity_lock_release_result_rejected", "ValueError")]


def test_stage1885_identity_lock_has_no_exception_handler_sentinel_returns() -> None:
    violations: list[tuple[int, str]] = []
    for node in ast.walk(_identity_lock_tree()):
        if isinstance(node, ast.ExceptHandler):
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    violations.append((child.lineno, ast.unparse(child.value) if child.value else ""))
    assert violations == []
