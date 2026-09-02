from pathlib import Path
import json

from Virus_Scan.scheduler.queue import publish
from Virus_Scan.scheduler.queue.publish_job import (
    ProcessQueuePublishAttempt,
    ProcessQueuePublishAttemptRequest,
    ProcessQueuePublishResult,
    build_process_queue_publish_attempt,
    publish_locked_process_queue_job,
)


def test_stage808_process_queue_publish_job_boundary_is_split():
    source = Path(publish.__file__).read_text(encoding="utf-8")
    helper_source = Path(publish_locked_process_queue_job.__code__.co_filename).read_text(encoding="utf-8")
    assert "build_process_queue_publish_attempt" in source
    assert "publish_locked_process_queue_job" in source
    assert "ProcessQueuePublishAttempt" in helper_source
    assert "ProcessQueuePublishResult" in helper_source
    assert len(source.splitlines()) < 190
    assert len(helper_source.splitlines()) < 160


def test_stage808_process_queue_publish_attempt_is_immutable_payload(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    attempt = build_process_queue_publish_attempt(
        ProcessQueuePublishAttemptRequest(
            order=2,
            original_index=7,
            file_path=sample,
            workload_class="generic",
            queue_file_identity_for_path=lambda path: "identity",
            process_weight_for_path=lambda path: 3.5,
        )
    )
    assert isinstance(attempt, ProcessQueuePublishAttempt)
    assert attempt.pending_name == "00000002_00000007.json"
    assert attempt.job == {
        "index": 7,
        "order": 2,
        "file": str(sample),
        "queue_file_id": "identity",
        "weight": 3.5,
        "workload_class": "generic",
    }
    assert not hasattr(attempt, "__dict__")


def test_stage808_slice_publication_uses_bounded_job_helper(tmp_path):
    queue_dir = tmp_path / "queue"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    cursor, enqueued, skipped = publish._write_process_queue_jobs_slice(
        queue_dir,
        [(0, 0, sample, "generic")],
        0,
        1,
        set(),
    )
    assert (cursor, enqueued, skipped) == (1, 1, 0)
    pending, *_ = publish._queue_job_dirs(queue_dir)
    jobs = list(pending.glob("*.json"))
    assert len(jobs) == 1
    payload = json.loads(jobs[0].read_text())
    assert payload["file"] == str(sample)
    assert payload["queue_file_id"]
