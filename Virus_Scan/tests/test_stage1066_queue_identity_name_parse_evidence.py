from __future__ import annotations

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name


class BadQueueName:
    def __str__(self) -> str:
        raise ValueError("bad queue name")


def test_stage1066_queue_identity_name_parse_failure_records_scheduler_evidence() -> None:
    clear_failure_records()

    assert queue_is_job_json_name(BadQueueName()) is False

    records = failure_snapshot().get("records", [])
    matching = [record for record in records if record.get("where") == "process_queue_identity_name_parse_failed"]
    assert len(matching) == 1
    assert matching[0].get("domain") == "scheduler"
    assert matching[0].get("error_type") == "ValueError"
    assert matching[0].get("degraded") is True
    assert "queue_is_job_json_name" in str(matching[0].get("trace_tail", ""))
