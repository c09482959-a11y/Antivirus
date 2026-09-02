from __future__ import annotations

import json

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.queue import identity_index


def _failure_wheres() -> set[str]:
    return {str(record.get("where")) for record in failure_snapshot().get("records", [])}


def _identity_index_path(queue_dir) -> object:
    paths = sorted((queue_dir / "identity_index").glob("*.json"))
    assert len(paths) == 1
    return paths[0]


def test_queue_identity_index_corrupt_json_records_scheduler_failure(tmp_path):
    clear_failure_records()
    key = (tmp_path, "pending")
    identity_index.set_index_entry(key, {"job-a"})
    _identity_index_path(tmp_path).write_text("{", encoding="utf-8")

    assert identity_index.get_index_entry(key, 60.0) is None
    assert "queue_identity_index_read_failed" in _failure_wheres()


def test_queue_identity_index_non_mapping_payload_records_scheduler_failure(tmp_path):
    clear_failure_records()
    key = (tmp_path, "active")
    identity_index.set_index_entry(key, {"job-b"})
    _identity_index_path(tmp_path).write_text(json.dumps(["job-b"]), encoding="utf-8")

    assert identity_index.get_index_entry(key, 60.0) is None
    assert "queue_identity_index_invalid_payload" in _failure_wheres()


def test_queue_identity_index_bad_timestamp_records_scheduler_failure(tmp_path):
    clear_failure_records()
    key = (tmp_path, "done")
    identity_index.set_index_entry(key, {"job-c"})
    _identity_index_path(tmp_path).write_text(
        json.dumps({"time": {"bad": "timestamp"}, "ids": ["job-c"]}),
        encoding="utf-8",
    )

    assert identity_index.get_index_entry(key, 60.0) is None
    assert "queue_identity_index_timestamp_failed" in _failure_wheres()


def test_queue_identity_index_missing_key_records_scheduler_failure():
    clear_failure_records()

    assert identity_index.get_index_entry((), 60.0) is None
    assert "queue_identity_index_missing_queue_key" in _failure_wheres()
