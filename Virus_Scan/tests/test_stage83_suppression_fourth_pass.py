import json
import inspect

import pytest

from Virus_Scan.core import jsonio
from Virus_Scan.reporting import result_schema
from Virus_Scan.scheduler.workers import process_liveness as worker_authority
from Virus_Scan.scheduler.workers import retire_tokens as worker_retire_tokens
from Virus_Scan.scheduler.queue.identity_lock import acquire_identity_lock_decision
from Virus_Scan.runtime.api import FilesystemDurabilityError
from Virus_Scan.scheduler.runtime.queue_json_quarantine_sidecar import queue_quarantine_sidecar_write_once


def test_atomic_json_save_fails_closed_when_replace_fails(tmp_path):
    path = tmp_path / "out.json"
    path.mkdir()

    with pytest.raises(FilesystemDurabilityError):
        jsonio.atomic_json_save(str(path), {"new": 2}, backups=0)
    assert path.is_dir()


def test_quarantine_sidecar_has_one_canonical_flush_path():
    assert "os_fsync" not in inspect.signature(queue_quarantine_sidecar_write_once).parameters
    assert "flush_open_writable_file(handle.fileno())" in inspect.getsource(queue_quarantine_sidecar_write_once)


def test_queue_failure_diagnostics_fail_closed_on_sync_failure(tmp_path):
    q = tmp_path / "q"
    q.mkdir()
    claim = q / "job.claim"
    claim.write_text(json.dumps({"file": "x"}), encoding="utf-8")
    (q / "failure_diagnostics").write_text("not a directory", encoding="utf-8")
    ok = jsonio._record_process_queue_failure(q, claim, job={"file": "x"}, error_info={"stage": "s", "error": "e"})
    assert ok is False
    assert "failure_info" in json.loads(claim.read_text(encoding="utf-8"))


def test_queue_file_result_fails_closed_on_sync_failure(tmp_path):
    claim = tmp_path / "job.claim"
    claim.write_text("{}", encoding="utf-8")
    blocked_queue = tmp_path / "blocked-queue"
    blocked_queue.write_text("not a directory", encoding="utf-8")
    ok = result_schema.write_queue_file_result(blocked_queue, claim, "file.bin", {"score": 0})
    assert ok is False


def test_identity_lock_invalid_identity_fails_closed_without_lock(tmp_path):
    decision = acquire_identity_lock_decision(tmp_path, "invalid:abc")
    assert decision.acquired is False
    assert not list(tmp_path.rglob("*.lock"))


def test_retire_token_fails_closed_on_sync_failure(tmp_path):
    blocked_queue = tmp_path / "blocked-queue"
    blocked_queue.write_text("not a directory", encoding="utf-8")
    made = worker_retire_tokens.request_queue_worker_retire(blocked_queue, 5)
    assert made == 0
