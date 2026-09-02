from pathlib import Path

from Virus_Scan.scheduler.queue import claim as claiming
from Virus_Scan.scheduler.queue import authority as queue_authority


def test_duplicate_live_guard_owned_by_queue_authority_only():
    source = Path(claiming.__file__).read_text(encoding="utf-8")
    assert "def _queue_duplicate_live_guard" not in source
    assert claiming._queue_duplicate_live_guard is queue_authority.queue_duplicate_live_guard


def test_queue_duplicate_live_guard_fails_closed_on_directory_error(tmp_path):
    seen = []
    assert queue_authority.queue_duplicate_live_guard(
        tmp_path,
        tmp_path / "active" / "claim.json",
        {"file": "x.bin", "queue_file_id": "id-x", "job_type": "file"},
        queue_job_dirs=lambda queue_dir: (_ for _ in ()).throw(OSError("dirs unavailable")),
        report=lambda stage, exc, **kw: seen.append((stage, type(exc).__name__, kw.get("fatal"))),
    ) is False
    assert ("queue_duplicate_live_guard_failed_closed", "OSError", True) in seen
