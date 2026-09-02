from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path, PurePosixPath

import pytest

import Virus_Scan.runtime.cleanup_invariants as cleanup
from Virus_Scan.runtime.cleanup_invariants import RuntimeCleanupSnapshot, validate_runtime_cleanup


class HostileCleanupRoot:
    touched = 0

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not stringify root")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not repr root")

    def __fspath__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not fspath root")


class HostileIgnoredName:
    touched = 0

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not stringify ignored name")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not repr ignored name")


class HostileThread:
    touched = 0

    @property
    def name(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not read thread name")

    @property
    def daemon(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not read daemon")

    def is_alive(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call is_alive")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not repr thread")


class HostilePathSubclass(PurePosixPath):
    touched = 0

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not stringify path subclass")

    def __fspath__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not fspath path subclass")


class HostileRootsIterable:
    touched = 0

    def __iter__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not iterate roots")

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not stringify roots")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not repr roots")


class HostileContext:
    touched = 0

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not stringify context")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not repr context")


def test_stage1755_cleanup_capture_rejects_hostile_roots_and_ignored_names_without_hooks() -> None:
    HostileCleanupRoot.touched = 0
    HostileIgnoredName.touched = 0

    snapshot = RuntimeCleanupSnapshot.capture(
        roots=(HostileCleanupRoot(),),
        ignored_thread_names=(HostileIgnoredName(),),
    )

    assert snapshot.tmp_artifacts == ("<unsupported_cleanup_root:HostileCleanupRoot>",)
    assert HostileCleanupRoot.touched == 0
    assert HostileIgnoredName.touched == 0


def test_stage1755_cleanup_thread_name_rejects_hostile_thread_without_hooks() -> None:
    HostileThread.touched = 0

    assert cleanup._cleanup_thread_name(HostileThread()) == "<unsupported_thread:HostileThread>"
    assert HostileThread.touched == 0


def test_stage1755_cleanup_capture_rejects_path_subclass_root_without_path_hooks() -> None:
    HostilePathSubclass.touched = 0

    snapshot = RuntimeCleanupSnapshot.capture(roots=(HostilePathSubclass("/tmp/stage1755"),))

    assert snapshot.tmp_artifacts == ("<unsupported_cleanup_root:HostilePathSubclass>",)
    assert HostilePathSubclass.touched == 0


def test_stage1755_cleanup_capture_rejects_hostile_roots_iterable_without_iterating() -> None:
    HostileRootsIterable.touched = 0

    snapshot = RuntimeCleanupSnapshot.capture(roots=HostileRootsIterable())

    assert snapshot.tmp_artifacts == ("<unsupported_cleanup_root:HostileRootsIterable>",)
    assert HostileRootsIterable.touched == 0


def test_stage1755_cleanup_validate_rejects_hostile_context_without_stringifying() -> None:
    HostileContext.touched = 0
    snapshot = RuntimeCleanupSnapshot(
        active_thread_names=("worker",),
        active_process_ids=(),
        queue_artifacts=(),
        tmp_artifacts=(),
    )

    with pytest.raises(RuntimeError, match="unsupported_cleanup_context:HostileContext"):
        snapshot.validate_clean(context=HostileContext())
    assert HostileContext.touched == 0


def test_stage1755_cleanup_capture_preserves_exact_stdlib_path_artifacts(tmp_path) -> None:
    (tmp_path / "pending").mkdir()
    (tmp_path / "leftover.tmp").write_text("x", encoding="utf-8")

    snapshot = RuntimeCleanupSnapshot.capture(roots=(tmp_path,))

    assert snapshot.queue_artifacts == ((tmp_path / "pending").as_posix(),)
    assert snapshot.tmp_artifacts == ((tmp_path / "leftover.tmp").as_posix(),)
    with pytest.raises(RuntimeError, match="dirty runtime cleanup state"):
        validate_runtime_cleanup(roots=(tmp_path,), context="stage1755_cleanup")


def test_stage1755_cleanup_source_no_longer_uses_hookable_root_or_thread_materialization() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/cleanup_invariants.py"))
    forbidden = (
        "str(item) for item in ignored_thread_names",
        "getattr(thread",
        "monkey" + "patch",
        "repr(thread)",
        "Path(str(root_obj))",
        "str(candidate)",
        "for root_obj in roots",
        'f"{context}',
    )
    offenders = [pattern for pattern in forbidden if pattern in source]
    assert offenders == []
