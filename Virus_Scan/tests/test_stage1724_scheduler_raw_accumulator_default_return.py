from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from Virus_Scan.scheduler.evidence.scheduler_json_writer import RawQueueJsonDependencies
from Virus_Scan.scheduler.queue.admission_guard import process_queue_enqueue_guard
from Virus_Scan.scheduler.queue.duplicate_guard import queue_duplicate_live_guard
from Virus_Scan.scheduler.queue.identity_lock import acquire_identity_lock_decision as acquire_process_identity_lock_decision
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore
from Virus_Scan.scheduler.queue import raw_accumulator_store as raw_store
from Virus_Scan.scheduler.queue.raw_queue_directory import enqueue_guard
from Virus_Scan.scheduler.queue.raw_queue_duplicates import duplicate_live_guard as raw_duplicate_live_guard
from Virus_Scan.scheduler.queue.raw_queue_identity import collect_existing_identities
from Virus_Scan.scheduler.queue.raw_queue_live_work import normalize_live_accumulator_counts
from Virus_Scan.scheduler.queue.raw_queue_quarantine import quarantine_job_decision, quarantine_sidecar_payload
from Virus_Scan.scheduler.queue.integrity import collect_jobs_by_identity
from Virus_Scan.scheduler.queue.raw_integrity import apply_integrity_tags, mark_raw_integrity_failure, raw_integrity_degraded
from Virus_Scan.scheduler.queue.raw_queue_accumulator import (
    RawAccumulatorDependencies,
    RawAccumulatorStore as CanonicalRawAccumulatorStore,
)


_SOURCE = Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/raw_accumulator_records.py"


class HostileAccumulatorValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("raw accumulator called __bool__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __iter__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __repr__")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __int__")


class HostileResult:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator result called __bool__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator result called __iter__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator result called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator result called __repr__")


class HostileIdentity:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("queue identity called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("queue identity called __str__")

    def startswith(self, *_args, **_kwargs):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("queue identity called startswith")


class HostileRawAccumulatorDependencies(RawAccumulatorDependencies):
    def __bool__(self):  # pragma: no cover
        raise AssertionError("raw accumulator dependencies called __bool__")


class HostileRawJsonDependencies(RawQueueJsonDependencies):
    def __bool__(self):  # pragma: no cover
        raise AssertionError("raw json dependencies called __bool__")


def _hostile_raw_accumulator_dependencies() -> HostileRawAccumulatorDependencies:
    deps = raw_store.raw_accumulator_dependencies()
    return HostileRawAccumulatorDependencies(
        **{field.name: getattr(deps, field.name) for field in fields(RawAccumulatorDependencies)}
    )


def _hostile_raw_json_dependencies() -> HostileRawJsonDependencies:
    deps = raw_store.raw_json_dependencies()
    return HostileRawJsonDependencies(
        **{field.name: getattr(deps, field.name) for field in fields(RawQueueJsonDependencies)}
    )


def test_stage1724_normalize_counts_rejects_non_mapping_without_empty_default_or_hooks() -> None:
    HostileAccumulatorValue.touched = 0

    record = RawAccumulatorStore.normalize_counts(HostileAccumulatorValue())

    assert HostileAccumulatorValue.touched == 0
    assert record["raw_accumulator_unavailable"] is True
    assert record["raw_accumulator_unavailable_reason"] == "raw_accumulator_record_not_mapping"
    assert record["degraded"] is True
    assert record["raw_failures"][0]["evidence"]["unsupported_scheduler_value"] is True
    assert "raw_accumulator_unavailable" in record["tags"]
    assert record != {}


def test_stage1724_normalize_counts_does_not_invoke_numeric_or_truthiness_hooks() -> None:
    HostileAccumulatorValue.touched = 0

    record = RawAccumulatorStore.normalize_counts({
        "expected": HostileAccumulatorValue(),
        "completed": HostileAccumulatorValue(),
        "failed": True,
        "retried": HostileAccumulatorValue(),
        "tags": [],
        "errors": [],
    })

    assert HostileAccumulatorValue.touched == 0
    assert record["failed"] == 1
    assert record["completed"] == 1
    assert record["degraded"] is True
    assert "raw_accumulator_count_reconciled" in record["tags"]


def test_stage1724_append_result_rejects_non_mapping_result_with_explicit_failure(tmp_path) -> None:
    HostileResult.touched = 0
    store = RawAccumulatorStore(tmp_path, "fid-stage1724")
    store.init("sample.bin", expected=1, initial_tags=[], effective_stage="raw", ext_stage="bin")

    record = store.append(HostileResult())

    assert HostileResult.touched == 0
    assert record["degraded"] is True
    assert record["failed"] == 1
    assert "raw_accumulator_result_rejected" in record["tags"]
    assert any("raw_accumulator_result_not_mapping" in item for item in record["errors"])


def test_stage1794_raw_accumulator_dependency_defaults_do_not_truthiness_probe(tmp_path) -> None:
    raw_deps = _hostile_raw_accumulator_dependencies()
    json_deps = _hostile_raw_json_dependencies()

    RawAccumulatorStore.normalize_counts({"expected": 1, "completed": 1}, deps=raw_deps)
    assert RawAccumulatorStore.is_complete({"expected": 1, "completed": 1}, deps=raw_deps) is True
    raw_store.GlobalRawAccumLock(tmp_path / "locks", "stage1794", timeout=0.01, deps=raw_deps)

    def fake_write_json_durable(*_args, **_kwargs):
        return True

    raw_store.write_raw_json_durable(
        tmp_path / "record.tmp",
        tmp_path / "record.json",
        {"job_type": "raw_stage"},
        deps=json_deps,
    )


def test_stage1794_raw_accumulator_is_complete_rejects_hostile_data_without_bool() -> None:
    HostileAccumulatorValue.touched = 0

    assert RawAccumulatorStore.is_complete(HostileAccumulatorValue()) is False

    assert HostileAccumulatorValue.touched == 0


def test_stage2190_raw_accumulator_completion_rejection_records_replayable_reason() -> None:
    HostileAccumulatorValue.touched = 0
    recorded: list[tuple[str, str]] = []
    base_deps = raw_store.raw_accumulator_dependencies()

    def record_completion_unavailable(where: str, exc: BaseException) -> bool:
        recorded.append((where, str(exc)))
        return True

    deps = RawAccumulatorDependencies(
        global_raw_dirs=base_deps.global_raw_dirs,
        read_json_file=base_deps.read_json_file,
        write_json_durable=base_deps.write_json_durable,
        ordered_unique_tags=base_deps.ordered_unique_tags,
        normalize_yara_hits=base_deps.normalize_yara_hits,
        record_scheduler_suppressed=record_completion_unavailable,
        recoverable_exceptions=base_deps.recoverable_exceptions,
    )

    assert CanonicalRawAccumulatorStore.is_complete(HostileAccumulatorValue(), deps) is False

    assert HostileAccumulatorValue.touched == 0
    assert recorded == [(
        "raw_accumulator_completion_raw_accumulator_record_not_mapping",
        "raw_accumulator_record_not_mapping",
    )]


def test_stage1794_queue_identity_defaults_do_not_probe_hostile_identity(tmp_path) -> None:
    HostileIdentity.touched = 0

    assert process_queue_enqueue_guard(tmp_path, {}, identity=HostileIdentity()) is False
    assert enqueue_guard(
        tmp_path,
        {},
        identity=HostileIdentity(),
        job_identity=lambda *_args: "job:ok",
        existing_identities=lambda *_args, **_kwargs: set(),
        record_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(Exception,),
    ) is True
    assert queue_duplicate_live_guard(
        tmp_path,
        tmp_path / "active" / "job.json",
        {},
        queue_job_dirs=lambda _queue_dir: (tmp_path / "pending", tmp_path / "active", tmp_path / "done", tmp_path / "failed"),
        safe_listdir=lambda _directory: [],
        is_job_name=lambda _name: True,
        job_identity=lambda *_args: HostileIdentity(),
        read_json=lambda *_args, **_kwargs: None,
        report=lambda *_args, **_kwargs: None,
    ) is False
    assert HostileIdentity.touched == 0


def test_stage1794_queue_quarantine_identity_default_does_not_truthiness_probe(tmp_path) -> None:
    HostileIdentity.touched = 0
    pending = tmp_path / "pending"
    pending.mkdir()
    job_path = pending / "job.json"
    job_path.write_text("{}", encoding="utf-8")

    assert quarantine_job_decision(
        job_path,
        identity=HostileIdentity(),
        active_claim_is_protected=lambda *_args, **_kwargs: False,
        quarantine_dir=lambda _queue_dir: tmp_path / "quarantine",
        read_json_file=lambda _path: {},
        job_identity=lambda *_args: "job:ok",
        quarantine_destination=lambda path, *, quarantine_root: (Path(quarantine_root) / Path(path).name, "pending"),
        remove_claim_sidecar_for_terminal_move=lambda *_args, **_kwargs: True,
        remove_claim_meta=lambda _path: True,
        cleanup_orphan_claim_sidecars=lambda *_args, **_kwargs: 0,
        cleanup_orphans=lambda *_args, **_kwargs: 0,
        orphan_cleanup_max=0,
        write_quarantine_sidecar=lambda *_args, **_kwargs: None,
        quarantine_sidecar_payload=lambda **_kwargs: {},
        report=lambda *_args, **_kwargs: None,
        report_issue=lambda *_args, **_kwargs: None,
        log_error=lambda *_args, **_kwargs: None,
    ).quarantined is True
    assert HostileIdentity.touched == 0


def test_stage1794_quarantine_sidecar_identity_does_not_stringify_hostile_value() -> None:
    HostileIdentity.touched = 0

    payload = quarantine_sidecar_payload(
        reason="stage1794",
        identity=HostileIdentity(),
        source_state="pending",
        destination="job.json",
        now=1.0,
    )

    assert payload["queue_identity"].startswith("identity_unavailable:")
    assert HostileIdentity.touched == 0


def test_stage1794_queue_identity_locks_reject_hostile_identity_without_hooks(tmp_path) -> None:
    HostileIdentity.touched = 0

    assert acquire_process_identity_lock_decision(tmp_path, HostileIdentity()).acquired is False

    assert HostileIdentity.touched == 0


def test_stage1794_collect_existing_identities_does_not_bool_probe_read_json(tmp_path) -> None:
    HostileAccumulatorValue.touched = 0
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    file_results = tmp_path / "file_results"
    quarantine = tmp_path / "quarantine"
    for directory in (pending, active, done, failed, file_results, quarantine):
        directory.mkdir()

    found = collect_existing_identities(
        tmp_path,
        states=("pending", "file_results"),
        job_dirs=lambda _queue_dir: (pending, active, done, failed),
        quarantine_dir=lambda _queue_dir: quarantine,
        file_results_dir=lambda _queue_dir: file_results,
        safe_listdir=lambda directory: ["job.json"] if Path(directory) in {pending, file_results} else [],
        is_job_json_name=lambda name: name == "job.json",
        read_json=lambda *_args, **_kwargs: HostileAccumulatorValue(),
        job_identity=lambda *_args: "job:ok",
        identity_index_get=lambda *_args, **_kwargs: None,
        identity_index_set=lambda *_args, **_kwargs: None,
    )

    assert found == set()
    assert HostileAccumulatorValue.touched == 0


def test_stage1794_raw_duplicate_guard_rejects_hostile_identity_without_hooks(tmp_path) -> None:
    HostileIdentity.touched = 0

    assert raw_duplicate_live_guard(
        tmp_path,
        tmp_path / "active" / "job.json",
        {},
        job_identity=lambda *_args: HostileIdentity(),
        job_dirs=lambda _queue_dir: (tmp_path / "pending", tmp_path / "active", tmp_path / "done", tmp_path / "failed"),
        safe_listdir=lambda _directory: [],
        is_job_json_name=lambda _name: True,
        read_json=lambda *_args, **_kwargs: None,
        merge_claim_meta=lambda _path, record: record,
        quarantine_job=lambda *_args, **_kwargs: True,
        report=lambda *_args, **_kwargs: None,
    ) is True
    assert HostileIdentity.touched == 0


def test_stage1794_live_accumulator_counts_reject_hostile_data_without_hooks() -> None:
    HostileAccumulatorValue.touched = 0

    assert normalize_live_accumulator_counts(HostileAccumulatorValue()) == {
        "expected": 0,
        "completed": 0,
        "failed": 0,
    }
    assert HostileAccumulatorValue.touched == 0


def test_stage1794_raw_integrity_helpers_do_not_bool_probe_hostile_inputs(tmp_path) -> None:
    HostileAccumulatorValue.touched = 0
    HostileIdentity.touched = 0
    reports = []

    assert raw_integrity_degraded(HostileAccumulatorValue()) is True
    assert apply_integrity_tags(
        ["raw"],
        HostileAccumulatorValue(),
        scanner_degraded_tags=lambda tags: tags + ["scanner_degraded"],
    ) == ["raw", "raw_accumulator_incomplete", "scanner_degraded"]
    info = mark_raw_integrity_failure(
        tmp_path / "sample.bin",
        None,
        marker=HostileIdentity(),
        where=HostileIdentity(),
        exc=RuntimeError("boom"),
        set_scan_integrity=lambda *_args, **_kwargs: None,
        report=lambda where, exc: reports.append(where),
        recoverable_exceptions=(Exception,),
    )

    assert info["stage120_marker"] == "raw_queue"
    assert reports == ["raw_queue"]
    assert HostileAccumulatorValue.touched == 0
    assert HostileIdentity.touched == 0


def test_stage1794_collect_jobs_by_identity_skips_hostile_records_without_bool(tmp_path) -> None:
    HostileAccumulatorValue.touched = 0
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    for directory in (pending, active, done, failed):
        directory.mkdir()

    groups = collect_jobs_by_identity(
        tmp_path,
        job_dirs=lambda _queue_dir: (pending, active, done, failed),
        safe_listdir=lambda directory: ["job.json"] if Path(directory) == pending else [],
        is_job_json_name=lambda name: name == "job.json",
        read_json=lambda *_args, **_kwargs: HostileAccumulatorValue(),
        job_identity=lambda *_args: "job:ok",
        merge_claim_meta=lambda _path, job: job,
        report=lambda *_args, **_kwargs: None,
    )

    assert groups == {}
    assert HostileAccumulatorValue.touched == 0


def test_stage1724_raw_accumulator_normalize_counts_has_no_empty_mapping_return() -> None:
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "normalize_counts":
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and isinstance(child.value, ast.Dict) and len(child.value.keys) == 0:
                    offenders.append(f"{_SOURCE.name}:{child.lineno}:return {{}}")
    assert offenders == []
