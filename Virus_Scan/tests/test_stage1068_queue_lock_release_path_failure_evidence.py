from __future__ import annotations

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock
from Virus_Scan.scheduler.runtime.queue_filesystem_operations import queue_atomic_replace, queue_safe_unlink


class UntrustedPath:
    def __bool__(self):
        raise RuntimeError("truthiness must not be consulted")

    def __fspath__(self):
        raise TypeError("path normalization failed")


def _failure_wheres() -> set[str]:
    return {str(record.get("where")) for record in failure_snapshot().get("records", [])}


def test_process_queue_identity_lock_release_bad_path_records_scheduler_evidence():
    clear_failure_records()

    assert identity_lock.release_identity_lock_decision(UntrustedPath()).released is False

    assert "process_queue_identity_lock_release_unsuccessful" in _failure_wheres()


def test_removed_raw_queue_identity_lock_family_is_physically_absent():
    for path in (
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_acquire.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_materialization.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_release.py",
        "Virus_Scan/scheduler/queue/raw_queue_identity_lock_evidence.py",
    ):
        assert not Path(path).exists()


def test_queue_filesystem_primitives_fail_closed_on_untrusted_paths(tmp_path):
    dst = tmp_path / "dst.json"
    src = tmp_path / "src.json"
    src.write_text("{}", encoding="utf-8")

    assert queue_safe_unlink(UntrustedPath(), retries=1) is False
    assert queue_atomic_replace(UntrustedPath(), dst, retries=1) is False
    assert queue_atomic_replace(src, UntrustedPath(), retries=1) is False
    assert src.exists()
