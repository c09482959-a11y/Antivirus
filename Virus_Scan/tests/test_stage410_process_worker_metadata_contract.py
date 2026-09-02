from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.workers.metadata import attach_worker_metadata


def test_stage410_process_worker_metadata_survives_compact_json_contract():
    raw = {
        "file": "sample.dll",
        "path": "sample.dll",
        "score": 10.0,
        "classification": "benign_clean",
        "tags": ["file_seen"],
    }

    annotated = attach_worker_metadata(
        raw,
        scheduler_mode="process-deterministic-threaded",
        worker_id="process-deterministic-threaded-worker-1",
        worker_pid=12345,
    )
    compact = compact_result_record(annotated)

    assert annotated is not raw
    assert compact["scheduler_mode"] == "process-deterministic-threaded"
    assert compact["worker_id"] == "process-deterministic-threaded-worker-1"
    assert compact["worker_id"]
    assert compact["scheduler_mode"].startswith("process")
