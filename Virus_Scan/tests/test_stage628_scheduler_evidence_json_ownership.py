from pathlib import Path

import pytest

from Virus_Scan.scheduler.evidence.execution_events import (
    SchedulerExecutionEventRequest,
    build_execution_event,
    build_raw_job_execution_event,
)
from Virus_Scan.scheduler.evidence.scheduler_json_writer import write_process_queue_json_durable, RawQueueJsonDependencies


def test_execution_events_are_immutable_and_do_not_own_json_persistence(tmp_path):
    event = build_execution_event(SchedulerExecutionEventRequest(
        event_type="unit",
        file_id="sample.bin",
        worker_id="worker-1",
        attempt="2",
        status="done",
        tags=["a", "b"],
        errors=["e"],
        metadata={"x": 1},
    ))
    assert event.as_dict()["attempt"] == 2
    assert event.tags == ("a", "b")
    with pytest.raises(TypeError):
        event.metadata["x"] = 2


def test_raw_job_execution_event_uses_job_identity_without_mutating_job():
    job = {"file_id": "f1", "attempt": 1, "tags": ["tag"], "seq": 7, "retried": True}
    event = build_raw_job_execution_event(job, status="ok", worker_id="w1")
    assert event.file_id == "f1"
    assert event.worker_id == "w1"
    assert event.metadata["seq"] == 7
    assert job["tags"] == ["tag"]


def test_obsolete_duplicate_json_owners_removed():
    assert not Path("Virus_Scan/scheduler/evidence/process_queue_json.py").exists()
    assert not Path("Virus_Scan/scheduler/evidence/raw_queue_json.py").exists()
    assert not Path("Virus_Scan/scheduler/execution/global_raw_queue_scan.py").exists()


def test_process_queue_json_writer_remains_canonical(tmp_path):
    assert write_process_queue_json_durable(
        tmp_path / "p.tmp",
        tmp_path / "p.json",
        {"schema_version": 1, "ok": True},
        log_context="stage628_process_json",
    ) is True
    assert (tmp_path / "p.json").exists()
