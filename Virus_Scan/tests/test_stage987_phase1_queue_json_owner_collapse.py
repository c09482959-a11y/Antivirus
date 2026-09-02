"""Stage987 Phase 1 queue JSON duplicate-owner collapse regression tests."""
from __future__ import annotations

import inspect

import Virus_Scan.core.jsonio as core_jsonio
from Virus_Scan.scheduler.runtime import queue_json_publication
from Virus_Scan.scheduler.runtime.queue_json import _queue_write_json_replace, read_json_file


def test_stage987_core_jsonio_no_longer_owns_scheduler_queue_json_writes():
    for removed_name in (
        "QueueJsonReplaceLockOwner",
        "_QUEUE_JSON_REPLACE_LOCK_OWNER",
        "_queue_write_json_replace",
        "_queue_write_claim_meta",
        "_queue_write_quarantine_sidecar",
        "_queue_cleanup_orphan_json_temps",
    ):
        assert not hasattr(core_jsonio, removed_name), removed_name


def test_stage987_scheduler_runtime_queue_json_is_canonical_writer(tmp_path):
    target = tmp_path / "job.json"
    payload = {"job_type": "unit", "file": "sample.bin", "queue_identity": "stage987"}

    assert _queue_write_json_replace(target, payload, verify=True, log_context="stage987") is True
    loaded = read_json_file(target, default={})

    assert loaded["job_type"] == "unit"
    assert loaded["file"] == "sample.bin"
    assert loaded["queue_identity"] == "stage987"
    assert loaded["schema_version"] >= 1


def test_stage987_quarantine_sidecar_uses_canonical_durable_writer(tmp_path):
    target = tmp_path / "job.json"
    target.write_text("{}", encoding="utf-8")
    assert queue_json_publication.queue_write_quarantine_sidecar(target, {"a": 1}) is True
    sidecars = [child for child in tmp_path.iterdir() if ".qmeta" in child.name]
    assert len(sidecars) == 1
    assert read_json_file(sidecars[0], default={}) == {"a": 1}


def test_stage987_queue_json_publication_has_no_except_pass_suppression():
    source = inspect.getsource(queue_json_publication)
    assert "except QUEUE_JSON_EXCEPTIONS:\n                    pass" not in source
