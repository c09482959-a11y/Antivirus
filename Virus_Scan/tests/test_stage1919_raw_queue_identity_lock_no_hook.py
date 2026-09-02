import ast
from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock
from Virus_Scan.tests.support.static_inventory import read_python_file

SOURCE = Path("Virus_Scan/scheduler/queue/identity_lock.py")


class HostileIdentity:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("identity str hook must not execute")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("identity repr hook must not execute")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("identity format hook must not execute")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("identity bool hook must not execute")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("identity iter hook must not execute")


class HostileError(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("exception str hook must not execute")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("exception repr hook must not execute")


def test_stage1919_acquire_rejects_hostile_identity_without_hooks(tmp_path):
    HostileIdentity.touched = 0

    decision = identity_lock.acquire_identity_lock_decision(tmp_path, HostileIdentity())

    assert decision.acquired is False
    assert HostileIdentity.touched == 0


def test_stage1919_release_reports_unlink_failure_without_exception_text_hooks(tmp_path):
    HostileError.touched = 0
    reports = []
    lock_path = tmp_path / "identity.lock"

    decision = identity_lock.release_identity_lock_decision(
        lock_path,
        safe_unlink=lambda *_args, **_kwargs: (_ for _ in ()).throw(HostileError("unlink denied")),
        report_issue=lambda where, exc, **_kwargs: reports.append((where, type(exc).__name__)),
    )

    assert decision.released is False
    assert reports == [("process_queue_identity_lock_release_failed", "HostileError")]
    assert HostileError.touched == 0


def test_stage1919_canonical_identity_lock_has_one_materialization_path():
    source = read_python_file(SOURCE)
    tree = ast.parse(source)

    assert "lock_path_func" not in source
    assert "raw_queue_identity_lock" not in source
    assert "hexdigest()[:32]" not in source
    assert "hexdigest()" in source
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "hash"
        for node in ast.walk(tree)
    )
