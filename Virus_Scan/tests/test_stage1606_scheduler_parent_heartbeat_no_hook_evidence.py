"""Stage1606 scheduler parent-message/shared-heartbeat no-hook evidence closure."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.workers.inmemory_parent_message_evidence import record_parent_worker_message_failure
from Virus_Scan.scheduler.workers.inmemory_parent_worker_messages import record_unknown_inmemory_worker_message
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publisher import publish_active_worker_heartbeats
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import record_shared_heartbeat_failure


class HostileValue:
    touched = 0

    @property
    def text(self):
        HostileValue.touched += 1
        raise RuntimeError("text hook executed")

    @property
    def value(self):
        HostileValue.touched += 1
        raise RuntimeError("value hook executed")

    def __str__(self):
        HostileValue.touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        HostileValue.touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        HostileValue.touched += 1
        raise RuntimeError("format hook executed")

    def __int__(self):
        HostileValue.touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):
        HostileValue.touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("bool hook executed")

    def __iter__(self):
        HostileValue.touched += 1
        raise RuntimeError("iter hook executed")


class HostileException(Exception):
    touched = 0

    def __str__(self):
        HostileException.touched += 1
        raise RuntimeError("exception str hook executed")

    def __repr__(self):
        HostileException.touched += 1
        raise RuntimeError("exception repr hook executed")


class HostileFlags:
    @property
    def running(self):
        HostileValue.touched += 1
        raise RuntimeError("running hook executed")

    @property
    def cancel_request(self):
        HostileValue.touched += 1
        raise RuntimeError("cancel hook executed")

    @property
    def poisoned_or_retire_mask(self):
        HostileValue.touched += 1
        raise RuntimeError("poison hook executed")


class HostileBool:
    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("result bool hook executed")


class HostileSequence:
    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("sequence bool hook executed")

    def __getitem__(self, _index):
        HostileValue.touched += 1
        raise RuntimeError("sequence getitem hook executed")

    def __repr__(self):
        HostileValue.touched += 1
        raise RuntimeError("sequence repr hook executed")


def _where_values() -> tuple[str, ...]:
    return tuple(record.get("where", "") for record in failure_snapshot().get("records", ()))


def test_stage1606_parent_worker_message_failure_rejects_hostile_message_and_exception_hooks():
    clear_failure_records()
    HostileValue.touched = 0
    HostileException.touched = 0

    record_parent_worker_message_failure(
        operation=HostileValue(),
        message=(HostileValue(), HostileValue()),
        exc=HostileException("hidden"),
    )

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert "inmemory_parent_worker_message_worker_message_failed" in _where_values()


def test_stage1606_unknown_parent_worker_message_does_not_probe_hostile_sequence_hooks():
    clear_failure_records()
    HostileValue.touched = 0

    result = record_unknown_inmemory_worker_message(HostileSequence())

    assert result.handled is False
    assert result.should_continue is False
    assert HostileValue.touched == 0
    assert "inmemory_parent_worker_message_unknown_kind_failed" in _where_values()


def test_stage1606_shared_heartbeat_failure_rejects_hostile_operation_job_generation_and_exception():
    clear_failure_records()
    HostileValue.touched = 0
    HostileException.touched = 0

    record_shared_heartbeat_failure(
        operation=HostileValue(),
        job_id=HostileValue(),
        generation=HostileValue(),
        exc=HostileException("hidden"),
    )

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert "worker_shared_heartbeat_heartbeat_failed" in _where_values()


def test_stage1606_worker_heartbeat_publisher_rejects_hostile_meta_fields_flags_and_bool_results():
    HostileValue.touched = 0
    meta = {
        "job_id": HostileValue(),
        "attempt": HostileValue(),
        "stage": HostileValue(),
        "progress_counter": HostileValue(),
        "bytes_processed": HostileValue(),
        "last_progress_ns": HostileValue(),
    }
    reports: list[str] = []

    stopped = publish_active_worker_heartbeats(
        active_items=((HostileValue(), meta),),
        cfg={"worker_rss_limit_mb": HostileValue()},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=HostileFlags(),
        completed_jobs=HostileValue(),
        cancel_requested=lambda *_args, **_kwargs: HostileBool(),
        update_shared_heartbeat=lambda *_args, **_kwargs: HostileBool(),
        process_id=HostileValue(),
        now_hb=HostileValue(),
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda label, _exc: reports.append(label),
    )

    assert stopped is False
    assert HostileValue.touched == 0
    assert meta["heartbeat_publish_failed"] is True
    evidence = meta["heartbeat_publish_evidence"]
    assert evidence["worker_heartbeat_job_id"] == "unknown"
    assert evidence["worker_heartbeat_attempt"] == 0
    assert evidence["worker_heartbeat_stage"] == "scan"
    assert "unsupported_worker_heartbeat_job_id" in evidence["worker_heartbeat_failure_reason"]
    assert reports == ["worker_heartbeat_publish_failed"]

from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_log_error,
    process_queue_record_suppressed,
    processqueue_default_failure_info,
)


def test_stage1606_process_queue_error_helpers_reject_hostile_text_exception_and_extra_without_hooks():
    clear_failure_records()
    HostileValue.touched = 0
    HostileException.touched = 0

    recorded = process_queue_record_suppressed(
        HostileValue(),
        HostileException("hidden"),
        extra={"unsafe": HostileValue()},
        fatal=HostileValue(),
    )
    logged = process_queue_log_error(HostileValue())
    info = processqueue_default_failure_info(HostileValue(), HostileException("hidden"), unsafe=HostileValue())

    assert recorded is True
    assert logged is True
    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert "process_queue" in _where_values()
    assert info["stage"] == "process_queue_failure"
    assert info["exception_type"] == "HostileException"
    assert info["unsafe"]["unsupported_scheduler_value"] is True
    assert info["unsafe"]["value_type"] == "HostileValue"


def test_stage1838_process_queue_errors_source_has_no_fallback_or_exception_sentinel():
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler"
        / "evidence"
        / "process_queue_errors.py"
    ).read_text(encoding="utf-8")

    assert "fallback=" not in source
    assert "scheduler_text(" not in source
    assert 'return text if reason == "" and text else' not in source
    record_block = source[source.index("def process_queue_record_suppressed"):source.index("def record_scheduler_suppressed")]
    log_block = source[source.index("def process_queue_log_error"):source.index("def processqueue_default_failure_info")]
    assert "return False" not in record_block
    assert "return False" not in log_block
    assert 'default_value="process_queue_failure"' in source


def test_stage1838_process_queue_error_helpers_reject_hostile_text_with_owned_defaults():
    clear_failure_records()
    HostileValue.touched = 0
    HostileException.touched = 0

    assert process_queue_record_suppressed(HostileValue(), HostileException("hidden")) is True
    assert process_queue_log_error(HostileValue()) is True
    info = processqueue_default_failure_info(HostileValue(), HostileException("hidden"))

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert "process_queue" in _where_values()
    assert info["stage"] == "process_queue_failure"
    assert info["exception_type"] == "HostileException"
