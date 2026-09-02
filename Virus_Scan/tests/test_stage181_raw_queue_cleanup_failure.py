import os
import tempfile
from pathlib import Path

def _unlink_and_return_true(path, **kwargs):
    Path(path).unlink(**kwargs)
    return True

from Virus_Scan.scheduler.queue.raw_queue_cleanup import cleanup_diagnostic_tmp_files, cleanup_orphan_claim_meta
from Virus_Scan.scheduler.evidence.raw_queue_failure import default_failure_info


def test_default_failure_info_preserves_extra_without_overwriting_core_fields():
    payload = default_failure_info(stage="retry", error="boom", exception_type="X", worker_pid="12", attempt=2, extra={"stage": "ignored", "identity": "abc"})
    assert payload["stage"] == "retry"
    assert payload["worker_pid"] == 12
    assert payload["attempt"] == 2
    assert payload["identity"] == "abc"


def test_cleanup_orphan_claim_meta_removes_only_orphan_sidecars(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    live = active / "live.json"
    live.write_text("{}", encoding="utf-8")
    live_sidecar = active / "live.json.claim"
    live_sidecar.write_text("{}", encoding="utf-8")
    orphan = active / "orphan.json.claim"
    orphan.write_text("{}", encoding="utf-8")
    issues = []
    removed = cleanup_orphan_claim_meta(
        active,
        safe_listdir=lambda p: os.listdir(p),
        safe_unlink=lambda p, **_: _unlink_and_return_true(p),
        queue_now=lambda: 1000.0,
        report=lambda *args, **kwargs: issues.append((args, kwargs)),
    )
    assert removed == 1
    assert live_sidecar.exists()
    assert not orphan.exists()
    assert issues == []


def test_cleanup_diagnostic_tmp_files_reports_age_failures_and_removes_stale(tmp_path):
    diag = tmp_path / "diagnostics"
    diag.mkdir()
    stale = diag / "old.tmp"
    stale.write_text("x", encoding="utf-8")
    os.utime(stale, (1, 1))
    issues = []
    cleanup_diagnostic_tmp_files(
        tmp_path,
        failure_diagnostics_dir=lambda q: diag,
        safe_listdir=lambda p: os.listdir(p),
        safe_unlink=lambda p, **_: _unlink_and_return_true(p),
        report=lambda *args, **kwargs: issues.append((args, kwargs)),
        max_age_sec=0.0,
    )
    assert not stale.exists()
