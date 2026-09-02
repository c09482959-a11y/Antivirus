
"""Stage 1778 scheduler producer and canonical-route regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.internal.scheduler_config import (
    process_queue_env_float,
    process_queue_env_int,
)
from Virus_Scan.scheduler.evidence.inmemory_result_timeout_support import timeout_int
from Virus_Scan.scheduler.evidence.scheduler_json_writer import (
    raw_chunk_bytes,
    raw_queue_enabled,
    raw_queue_max_chunks,
    raw_queue_min_bytes,
)
from Virus_Scan.scheduler.ownership.raw_queue_claim_validation import (
    repair_and_validate_claim_job,
)
from Virus_Scan.scheduler.queue.claim_failures import claim_failure_info
from Virus_Scan.scheduler.queue.feed_marker import (
    mark_process_queue_feed_complete,
    queue_feed_complete_path,
)
from Virus_Scan.scheduler.queue.identity import queue_job_identity
from Virus_Scan.scheduler.runtime.queue_filesystem_identity import (
    global_raw_file_id,
    process_weight_for_path,
    queue_file_identity_for_path,
    raw_stage_cache_key,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_operations import queue_fs_backoff
from Virus_Scan.scheduler.runtime.loop_guard import (
    SchedulerLoopGuard,
    SchedulerLoopGuardAdvanceRequest,
    SchedulerLoopGuardState,
    advance_scheduler_loop_guard,
)
from Virus_Scan.scheduler.runtime.env_policy import (
    bool_env as scheduler_bool_env,
    float_env as scheduler_float_env,
    int_env as scheduler_int_env,
)
from Virus_Scan.scheduler.queue.inmemory_cancel_evidence import cancel_publication_evidence_from_record
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal
from Virus_Scan.scheduler.queue.terminal_missing_finalization import finalize_missing_file_accounting
from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed import (
    ProcessQueueDynamicFeedDependencies,
    ProcessQueueDynamicFeedRequest,
    advance_process_queue_dynamic_feed,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence_projection import (
    attach_timeout_evidence_to_job_records,
    job_record_for_timeout_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_retry_evidence import evidence_not_already_present
from Virus_Scan.scheduler.timeout.inmemory_timeout_config import build_inmemory_timeout_config
from Virus_Scan.scheduler.workers.heartbeat import (
    cooperative_cancel_requested,
    read_shared_heartbeat,
    update_shared_heartbeat,
)
from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import build_inmemory_heartbeat_flags
from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat import ingest_shared_heartbeats
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message import ingest_worker_heartbeat_message


class HostileSchedulerValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    fspath_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute")

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise RuntimeError("must not execute")


class HostileSchedulerError(RuntimeError):
    def __str__(self):
        HostileSchedulerValue.str_calls += 1
        raise RuntimeError("must not execute")


class HostileSchedulerMapping(dict):
    def get(self, *args, **kwargs):
        HostileSchedulerValue.iter_calls += 1
        raise RuntimeError("must not execute")

    def items(self):
        HostileSchedulerValue.iter_calls += 1
        raise RuntimeError("must not execute")

    def __iter__(self):
        HostileSchedulerValue.iter_calls += 1
        raise RuntimeError("must not execute")


def _reset_hooks() -> None:
    for name in (
        "str_calls",
        "repr_calls",
        "format_calls",
        "bool_calls",
        "iter_calls",
        "float_calls",
        "int_calls",
        "fspath_calls",
    ):
        setattr(HostileSchedulerValue, name, 0)


def _assert_no_hooks() -> None:
    assert HostileSchedulerValue.str_calls == 0
    assert HostileSchedulerValue.repr_calls == 0
    assert HostileSchedulerValue.format_calls == 0
    assert HostileSchedulerValue.bool_calls == 0
    assert HostileSchedulerValue.iter_calls == 0
    assert HostileSchedulerValue.float_calls == 0
    assert HostileSchedulerValue.int_calls == 0
    assert HostileSchedulerValue.fspath_calls == 0


def test_scheduler_env_parsers_reject_hostile_scalars_before_hooks() -> None:
    _reset_hooks()
    records = []

    def record(where, exc, *, extra=None, fatal=False):
        records.append((where, dict(extra or {}), fatal))
        return True

    hostile = HostileSchedulerValue()
    assert process_queue_env_float(
        hostile,
        hostile,
        minimum=hostile,
        record_suppressed=record,
        env_get=lambda name, default=None: hostile,
    ) == 0.0
    assert process_queue_env_int(
        hostile,
        hostile,
        minimum=hostile,
        record_suppressed=record,
        env_get=lambda name, default=None: hostile,
    ) == 0

    _assert_no_hooks()
    assert records
    assert all(record[1]["reason"] for record in records)
    assert {record[1]["value_type"] for record in records} == {"HostileSchedulerValue"}


def test_scheduler_env_parser_rejects_hostile_env_result_with_evidence() -> None:
    _reset_hooks()
    records = []
    hostile = HostileSchedulerValue()

    result = process_queue_env_float(
        "UMIGE_STAGE1778",
        12.5,
        minimum=1.0,
        record_suppressed=lambda where, exc, *, extra=None, fatal=False: records.append(
            (where, dict(extra or {}))
        ),
        env_get=lambda name, default=None: hostile,
    )

    _assert_no_hooks()
    assert result == 12.5
    assert records == [
        (
            "process_queue_env_float_invalid",
            {
                "field": "UMIGE_STAGE1778",
                "name": "UMIGE_STAGE1778",
                "reason": "UMIGE_STAGE1778_rejected",
                "value_type": "HostileSchedulerValue",
            },
        )
    ]


def test_feed_marker_rejects_hostile_path_before_path_hooks() -> None:
    _reset_hooks()
    records = []
    hostile = HostileSchedulerValue()

    with pytest.raises(ValueError, match="rejected before path conversion"):
        queue_feed_complete_path(
            hostile,
            record_suppressed=lambda where, exc, *, extra=None, fatal=False: records.append(
                (where, dict(extra or {}), fatal)
            ),
        )
    assert mark_process_queue_feed_complete(
        hostile,
        record_suppressed=lambda where, exc, *, extra=None, fatal=False: records.append(
            (where, dict(extra or {}), fatal)
        ),
    ) is False

    _assert_no_hooks()
    assert any(where == "queue_feed_complete_path_resolution_failed" and fatal for where, _extra, fatal in records)
    assert any(where == "queue_feed_complete_persist_failed" and fatal for where, _extra, fatal in records)


def test_production_claim_validator_rejects_hostile_nested_fields_without_hooks() -> None:
    _reset_hooks()
    records = []
    hostile = HostileSchedulerValue()

    job, error = repair_and_validate_claim_job(
        "queue",
        {
            "job_type": "raw_stage",
            "file_id": "file-id",
            "file": "sample.bin",
            "collector": hostile,
            "seq": hostile,
        },
        failure_info=lambda **kwargs: dict(kwargs),
        report=lambda where, exc, *, extra=None, fatal=False: records.append(
            (where, dict(extra or {}), fatal)
        ),
        worker_pid=1778,
    )

    _assert_no_hooks()
    assert job["job_type"] == "raw_stage"
    assert error["exception_type"] == "InvalidRawStageQueueJob"
    assert "collector" in error["error"]
    assert "seq" in error["error"]
    assert error["extra"]["field_rejections"]
    assert all(fatal for _where, _extra, fatal in records)


def test_claim_failure_and_identity_projection_do_not_stringify_hostile_values() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    error = HostileSchedulerError(hostile)

    failure = claim_failure_info("queue_claim_probe", error, worker_pid=7)
    identity = queue_job_identity({"file": hostile})

    _assert_no_hooks()
    assert failure["exception_type"] == "HostileSchedulerError"
    assert "diagnostic detail unavailable" in failure["error"]
    assert identity == "invalid:process_queue_identity_missing"


def test_scheduler_claim_validation_has_one_production_implementation() -> None:
    claim_sidecar = read_python_file(Path("Virus_Scan/scheduler/queue/claim_sidecar.py"))
    claim = read_python_file(Path("Virus_Scan/scheduler/queue/claim.py"))
    claim_file = read_python_file(Path("Virus_Scan/scheduler/queue/claim_file_execution.py"))

    assert "def _queue_repair_and_validate_claim_job" not in claim_sidecar
    assert "repair_and_validate_claim_job(" in claim
    assert "repair_and_validate_claim_job(" in claim_file
    assert "_queue_repair_and_validate_claim_job" not in claim
    assert "_queue_repair_and_validate_claim_job" not in claim_file


def test_scheduler_identity_has_one_production_authority() -> None:
    scheduler_root = Path("Virus_Scan/scheduler")
    production_sources = [
        path.read_text(encoding="utf-8")
        for path in scheduler_root.rglob("*.py")
        if "__pycache__" not in path.parts
    ]

    assert not Path("Virus_Scan/scheduler/queue/raw_queue_validation.py").exists()
    assert not Path("Virus_Scan/scheduler/queue/job_identity.py").exists()
    assert not Path("Virus_Scan/scheduler/queue/raw_queue_feed.py").exists()
    assert all("queue.raw_queue_validation" not in source for source in production_sources)
    assert all("queue.job_identity" not in source for source in production_sources)
    assert all("queue.raw_queue_feed" not in source for source in production_sources)


def test_scheduler_raw_policy_defaults_record_hostile_rejections_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    records = []

    def record(where, exc):
        records.append(where)

    runtime_value = lambda name, default: hostile
    assert raw_chunk_bytes(runtime_value=runtime_value, record_suppressed=record) == 65536
    assert raw_queue_max_chunks(runtime_value=runtime_value, record_suppressed=record) == 192
    assert raw_queue_min_bytes(runtime_value=runtime_value, record_suppressed=record) == 0
    assert raw_queue_enabled(runtime_value=runtime_value, record_suppressed=record) is False

    _assert_no_hooks()
    assert records == [
        "raw_queue_chunk_bytes_policy_issue",
        "raw_queue_max_chunks_policy_issue",
        "raw_queue_min_bytes_policy_issue",
        "raw_queue_enabled_policy_issue",
    ]


def test_scheduler_timeout_integer_rejects_nonintegral_values_with_evidence() -> None:
    rejections = []

    assert timeout_int(2.9, default_value=7, field="progress_counter", rejections=rejections) == 7
    assert rejections == [
        {
            "field": "progress_counter",
            "reason": "unsafe_progress_counter",
        }
    ]


def test_scheduler_filesystem_identity_rejects_hostile_paths_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()

    raw_id = global_raw_file_id(hostile)
    file_id = queue_file_identity_for_path(hostile)
    weight = process_weight_for_path(hostile)
    cache_key = raw_stage_cache_key({"file": hostile, "collector": "strings", "start": 0, "size": 4})
    backoff = queue_fs_backoff(hostile, delay=hostile)

    _assert_no_hooks()
    assert len(raw_id) == 24
    assert len(file_id) == 32
    assert weight == 1.0
    assert cache_key is None
    assert backoff == 0.025


def test_scheduler_recovery_journal_rejects_hostile_sequences_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    journal = InMemoryRecoveryEvidenceJournal()

    journal.append_cancel(hostile)
    journal.append_retry(hostile)
    cancel_records = journal.cancel_since(0)
    retry_records = journal.retry_since(0)

    _assert_no_hooks()
    assert cancel_records[0]["reason"] == "recovery_evidence_sequence_rejected"
    assert retry_records[0]["reason"] == "recovery_evidence_sequence_rejected"
    assert all(record["final_json_must_record"] is True for record in cancel_records + retry_records)


def test_scheduler_timeout_projection_uses_builtin_mapping_reads_only() -> None:
    _reset_hooks()
    evidence = HostileSchedulerMapping(
        stage="inmemory_timeout_retry_escalation",
        job_id=9,
        reason="timeout",
        action="retry_or_fail",
    )
    journal = InMemoryRecoveryEvidenceJournal()
    journal.append_retry((evidence,))
    journal.append_cancel((evidence,))

    projected = journal.retry_since(0)
    deduped = evidence_not_already_present(candidates=(evidence,), existing=())
    cancel = journal.cancel_since(0)
    publication = cancel_publication_evidence_from_record(
        HostileSchedulerMapping(cancel_publication_evidence=evidence)
    )

    _assert_no_hooks()
    assert projected[0]["reason"] == "recovery_evidence_record_rejected"
    assert deduped[0]["reason"] == "candidate_evidence_record_rejected"
    assert cancel[0]["reason"] == "recovery_evidence_record_rejected"
    assert publication[0]["reason"] == "cancel_job_record_rejected"


def test_scheduler_timeout_attachment_rejects_hostile_identifiers_and_containers_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    job_records = {9: {"history": ()}}
    evidence = HostileSchedulerMapping(
        stage="inmemory_timeout_retry_escalation",
        job_id=9,
        reason="timeout",
        action="retry_or_fail",
        detail=hostile,
    )

    assert job_record_for_timeout_evidence(hostile, hostile) is None
    attach_timeout_evidence_to_job_records(
        job_records=job_records,
        evidence_records=(evidence,),
    )

    _assert_no_hooks()
    assert "timeout_retry_evidence" not in job_records[9]


def test_scheduler_shared_heartbeat_rejects_hostile_boundaries_with_evidence() -> None:
    _reset_hooks()
    clear_failure_records()
    hostile = HostileSchedulerValue()
    hostile_table = HostileSchedulerMapping()

    assert cooperative_cancel_requested(hostile_table, hostile, hostile) is False
    assert read_shared_heartbeat(hostile_table, hostile, hostile) is None
    assert update_shared_heartbeat(
        hostile_table,
        hostile,
        hostile,
        pid=hostile,
        thread_id=hostile,
        stage=hostile,
        progress_counter=hostile,
        bytes_processed=hostile,
        last_progress_ns=hostile,
        flags=hostile,
        rss_mb=hostile,
        completed_jobs=hostile,
    ) is False

    _assert_no_hooks()
    where = tuple(record["where"] for record in failure_snapshot()["records"])
    assert any("worker_shared_heartbeat_cancel_read_failed" in item for item in where)
    assert any("worker_shared_heartbeat_heartbeat_read_failed" in item for item in where)
    assert any("worker_shared_heartbeat_heartbeat_write_failed" in item for item in where)


def test_scheduler_loop_guard_rejects_hostile_policy_and_counters_with_evidence() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    guard = SchedulerLoopGuard(hostile, hostile, hostile, hostile, hostile)
    state = SchedulerLoopGuardState.start(now=hostile, progress_total=hostile)

    decision = advance_scheduler_loop_guard(SchedulerLoopGuardAdvanceRequest(
        guard,
        state,
        now=hostile,
        progress_total=hostile,
        pending_count=hostile,
        active_count=hostile,
        completed_count=hostile,
        failed_count=hostile,
        worker_live_count=hostile,
        queue_live_count=hostile,
    ))

    _assert_no_hooks()
    assert decision.exhausted is True
    assert decision.reason == "scheduler_loop_guard_input_rejected"
    assert decision.evidence["final_json_must_record"] is True
    assert decision.evidence["context"]["input_evidence"]


def test_scheduler_dynamic_feed_rejects_hostile_request_without_hooks_and_records_issue() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    issues = []
    deps = ProcessQueueDynamicFeedDependencies(
        build_feed_policy=lambda *args, **kwargs: None,
        decide_feed=lambda *args, **kwargs: None,
        write_jobs_slice=lambda *args, **kwargs: (0, 0, 0),
        mark_feed_complete=lambda path: None,
        progress_counts=lambda path: {},
        record_issue=lambda stage, exc, **kwargs: issues.append((stage, kwargs)),
        log_error=lambda message: None,
        log_info=lambda message: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )
    output = advance_process_queue_dynamic_feed(
        ProcessQueueDynamicFeedRequest(
            enabled=hostile,
            queue_dir=hostile,
            ordered_queue_items=hostile,
            queue_feed_cursor=hostile,
            queue_total_enqueued=hostile,
            queue_enqueued_identities=hostile,
            target_workers=hostile,
            file_active_count=hostile,
            file_pending_count=hostile,
            io_pressure=hostile,
            cpu_sample=hostile,
            elastic_io_sample=hostile,
            all_files_count=hostile,
            raw_live=hostile,
            current_time=hostile,
            queue_last_feed_log=hostile,
            env=hostile,
        ),
        deps,
    )

    _assert_no_hooks()
    assert output.queue_feed_cursor == 0
    assert output.queue_total_enqueued == 0
    assert issues[0][0] == "process_queue_dynamic_feed_input_rejected"
    assert issues[0][1]["extra"]["detail"]["issues"]


def test_scheduler_dynamic_feed_valid_path_is_deterministic() -> None:
    decision = type("Decision", (), {})()
    decision.feed_capacity = 1
    marks = []
    output = advance_process_queue_dynamic_feed(
        ProcessQueueDynamicFeedRequest(
            enabled=True,
            queue_dir="queue",
            ordered_queue_items=((0, 0, "a.bin"),),
            queue_feed_cursor=0,
            queue_total_enqueued=0,
            queue_enqueued_identities=("z", "a"),
            target_workers=1,
            file_active_count=0,
            file_pending_count=0,
            io_pressure=False,
            cpu_sample=10.0,
            elastic_io_sample={"pressure": False},
            all_files_count=1,
            raw_live=0,
            current_time=20.0,
            queue_last_feed_log=0.0,
            env={},
        ),
        ProcessQueueDynamicFeedDependencies(
            build_feed_policy=lambda *args, **kwargs: object(),
            decide_feed=lambda *args, **kwargs: decision,
            write_jobs_slice=lambda *args, **kwargs: (1, 1, 0),
            mark_feed_complete=marks.append,
            progress_counts=lambda path: {
                "file_active": 0,
                "file_pending": 0,
                "raw_pending": 0,
                "raw_active": 0,
            },
            record_issue=lambda *args, **kwargs: None,
            log_error=lambda message: None,
            log_info=lambda message: None,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
        ),
    )

    assert output.queue_feed_cursor == 1
    assert output.queue_total_enqueued == 1
    assert output.queue_enqueued_identities == ("a", "z")
    assert marks == ["queue"]


def test_scheduler_terminal_accounting_rejects_hostile_paths_and_containers_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    reports = []
    actions = []

    terminated, had_error = finalize_missing_file_accounting(
        feed_complete=True,
        no_live_queue_work=True,
        accounted_files=0,
        total_files=1,
        idle_elapsed=30.0,
        idle_grace_sec=30.0,
        all_files=(hostile,),
        queue_dir=hostile,
        outputs_dir=hostile,
        procs=hostile,
        load_queue_file_results=lambda path: {},
        worker_error_result=lambda path, exc: {
            "file": path,
            "error": "queue file rejected",
        },
        terminate_worker=lambda *args, **kwargs: actions.append((args, kwargs)),
        report=lambda marker, exc, **kwargs: reports.append((marker, kwargs)),
        log_error=lambda message: None,
        sleep=lambda seconds: None,
    )

    _assert_no_hooks()
    assert terminated is True
    assert had_error is True
    assert actions == []
    assert any(marker == "queue_missing_finalization_file_rejected" for marker, _kwargs in reports)
    assert any(marker == "queue_missing_finalization_write_failed" for marker, _kwargs in reports)
    assert any(marker == "queue_terminal_accounting_sequence_rejected" for marker, _kwargs in reports)


def test_scheduler_environment_policy_records_hostile_defaults_without_hooks() -> None:
    _reset_hooks()
    clear_failure_records()
    hostile = HostileSchedulerMapping(VALUE=HostileSchedulerValue())

    assert scheduler_float_env(hostile, "VALUE", 2.5, (Exception,)) == 2.5
    assert scheduler_int_env(hostile, "VALUE", 7, (Exception,)) == 7
    assert scheduler_bool_env(hostile, "VALUE", True, (Exception,)) is True

    _assert_no_hooks()
    where = tuple(record["where"] for record in failure_snapshot()["records"])
    assert "scheduler_env_float_rejected" in where
    assert "scheduler_env_integer_rejected" in where
    assert "scheduler_env_bool_rejected" in where


def test_scheduler_timeout_config_records_hostile_mapping_and_scalar_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()

    config = build_inmemory_timeout_config(
        HostileSchedulerMapping(),
        per_file_timeout_sec=hostile,
    )

    _assert_no_hooks()
    assert config.base_file_timeout_seconds == 20
    settings = tuple(record["setting"] for record in config.config_evidence)
    assert "per_file_timeout_sec" in settings
    assert "UMIGE_INMEMORY_MAX_JOB_RETRIES" in settings
    assert "UMIGE_INMEMORY_CANCEL_GRACE_SEC" in settings
    assert all(record["final_json_must_record"] is True for record in config.config_evidence)


def test_scheduler_parent_heartbeat_message_validates_before_mutation_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileSchedulerValue()
    job_records = {1: {"attempt": 0, "state": "running"}}
    active = {1: {}}
    worker_heartbeats = {}
    worker_metrics = {}

    with pytest.raises(ValueError, match="scalar rejected"):
        ingest_worker_heartbeat_message(
            message=(
                "heartbeat",
                1,
                "sample.bin",
                hostile,
                1.0,
                0,
                1,
                "scan",
                0,
                0,
                0,
            ),
            job_records=job_records,
            active=active,
            terminal=set(),
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
            heartbeat_flags=build_inmemory_heartbeat_flags(lambda name: None),
            history_transition=lambda *args, **kwargs: args[1],
            cancel_job=lambda *args, **kwargs: None,
            lifecycle_recorder=lambda _request: None,
            wall_time=lambda: 1.0,
        )

    _assert_no_hooks()
    assert job_records == {1: {"attempt": 0, "state": "running"}}
    assert active == {1: {}}
    assert worker_heartbeats == {}
    assert worker_metrics == {}


def test_scheduler_queue_snapshot_rejects_hostile_counts_with_output_evidence() -> None:
    _reset_hooks()
    hostile_counts = HostileSchedulerMapping(pending=HostileSchedulerValue())

    snapshot = QueueBehaviorSnapshot.from_counts(
        HostileSchedulerValue(),
        hostile_counts,
    )
    payload = snapshot.as_dict()

    _assert_no_hooks()
    assert snapshot.phase == "unknown"
    assert snapshot.pending == 0
    assert payload["input_evidence"]
    assert all(item["final_json_must_record"] is True for item in payload["input_evidence"])


def test_scheduler_shared_heartbeat_ingest_rejects_hostile_state_without_hooks() -> None:
    _reset_hooks()
    clear_failure_records()
    hostile_state = HostileSchedulerMapping()

    result = ingest_shared_heartbeats(
        active_job_ids=(),
        job_records=hostile_state,
        active={},
        terminal=set(),
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_table=None,
        heartbeat_flags=build_inmemory_heartbeat_flags(lambda name: None),
        read_heartbeat=lambda *args: None,
        cancel_job=lambda *args, **kwargs: None,
        lifecycle_recorder=lambda _request: None,
        monotonic_ns=lambda: 0,
        wall_time=lambda: 0.0,
    )

    _assert_no_hooks()
    assert result.observed == 0
    assert result.heartbeat_row_failures == 1
    assert any(
        "worker_shared_heartbeat_heartbeat_ingest_state_failed" in record["where"]
        for record in failure_snapshot()["records"]
    )
