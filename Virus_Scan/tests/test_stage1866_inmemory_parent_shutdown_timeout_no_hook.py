from pathlib import Path

from Virus_Scan.scheduler.orchestration.inmemory_timeout_config_job_evidence import (
    attach_timeout_config_evidence_to_job_records,
)
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import (
    InMemoryRecoveryEvidenceJournal,
)


class HostileJobRecords:
    def items(self):  # pragma: no cover - must not execute
        raise AssertionError("hostile job-record items hook executed")

    def __iter__(self):  # pragma: no cover - must not execute
        raise AssertionError("hostile job-record iter hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        raise AssertionError("hostile job-record bool hook executed")


def _source(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_stage1866_recovery_journal_initial_counts_are_constant_time_owned_state():
    journal = InMemoryRecoveryEvidenceJournal()
    journal.append_retry(({"stage": "retry"},))
    journal.append_cancel(({"stage": "cancel"},))

    assert journal.retry_count() == 1
    assert journal.cancel_count() == 1


def test_stage1866_timeout_config_job_records_reject_hostile_mapping_without_hooks():
    result = attach_timeout_config_evidence_to_job_records(
        HostileJobRecords(),
        ({"setting": "heartbeat", "value": 3},),
    )

    assert result is None


def test_stage1866_timeout_config_job_records_attach_to_exact_dict_only():
    job_records = {"job-1": {"history": ()}}

    attach_timeout_config_evidence_to_job_records(
        job_records,
        ({"setting": "heartbeat", "value": 3},),
    )

    assert job_records["job-1"]["timeout_config_evidence_recorded"] is True
    assert len(job_records["job-1"]["timeout_config_evidence"]) == 1
    assert job_records["job-1"]["history"][-1]["action"] == "timeout_config_evidence"


def test_stage1866_inmemory_parent_timeout_maintenance_uses_direct_journal_counts():
    source = _source("Virus_Scan/scheduler/orchestration/inmemory_parent_timeout_maintenance.py")

    assert 'getattr(request.recovery, "retry_recovery_evidence"' not in source
    assert 'getattr(request.recovery, "cancel_only_evidence"' not in source
    assert 'log_error(f"in-memory timeout retry sweep failed: {exc}")' not in source
    assert "request.recovery.retry_evidence_count()" in source
    assert "request.recovery.cancel_evidence_count()" in source
    assert 'str.__add__("in-memory timeout retry sweep failed: ", scheduler_error_detail(exc))' in source


def test_stage1866_inmemory_parent_shutdown_source_has_explicit_recording_failure_evidence():
    source = _source("Virus_Scan/scheduler/orchestration/inmemory_parent_shutdown.py")

    assert "except recoverable_exceptions:\n            return" not in source
    assert "scheduler manager shutdown suppression recording failed" in source
    assert "scheduler_error_detail(record_exc)" in source


def test_stage1866_timeout_config_evidence_source_has_no_index_fstring_and_exact_dict_guard():
    source = _source("Virus_Scan/scheduler/orchestration/inmemory_timeout_config_job_evidence.py")

    assert 'field_name=f"timeout_config_evidence_{index}"' not in source
    assert 'str.__add__("timeout_config_evidence_", int.__str__(index))' in source
    assert "if type(job_records) is not dict:" in source
    assert "for _job_id, record in dict.items(job_records):" in source
