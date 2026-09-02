"""Stage 1067: queue job identity source failures emit scheduler evidence."""
from __future__ import annotations

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.queue.identity import queue_job_identity


class _UnstringableSource:
    def __str__(self) -> str:
        raise TypeError("source cannot be stringified")


class _UnstringableJobValue:
    def __str__(self) -> str:
        raise TypeError("job value cannot be stringified")


def _recorded_where_values() -> tuple[str, ...]:
    return tuple(record.get("where", "") for record in failure_snapshot().get("records", ()))


def test_queue_job_identity_unstringable_source_fails_closed_with_evidence():
    clear_failure_records()

    identity = queue_job_identity({}, _UnstringableSource())

    assert identity == "invalid:process_queue_identity_missing"
    assert "process_queue_identity_source_parse_failed" in _recorded_where_values()


def test_queue_job_identity_unstringable_job_value_fails_closed_with_evidence():
    clear_failure_records()

    identity = queue_job_identity({"file": _UnstringableJobValue()}, None)

    assert identity == "invalid:process_queue_identity_missing"
    assert "process_queue_identity_source_parse_failed" in _recorded_where_values()
