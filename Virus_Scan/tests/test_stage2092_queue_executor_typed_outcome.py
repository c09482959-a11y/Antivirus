"""Stage2092 raw queue executor typed outcome contract regressions."""
from __future__ import annotations

from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation

import inspect
from typing import Any

from Virus_Scan.scheduler.execution import queue_executor
from Virus_Scan.scheduler.execution.queue_executor import GlobalRawQueueScanDependencies
from Virus_Scan.scheduler.execution.queue_scan_outcome import GlobalRawQueueScanOutcome


def _deps(**overrides: Any) -> GlobalRawQueueScanDependencies:
    def dep(name: str, default: Any) -> Any:
        return overrides.get(name, default)

    return GlobalRawQueueScanDependencies(
        sniff_file_identity=dep("sniff_file_identity", lambda path: {"tags": []}),
        get_scan_extension=dep("get_scan_extension", lambda path: ".bin"),
        normalize_stage=dep("normalize_stage", lambda ext: "binary"),
        choose_effective_stage=dep("choose_effective_stage", lambda ext_stage, identity: "binary"),
        runtime_value=dep("runtime_value", lambda name, default=None: default),
        global_raw_eligible=dep("global_raw_eligible", lambda path, effective_stage=None: False),
        raw_queue_live_count=dep("raw_queue_live_count", lambda queue_dir: 0),
        global_raw_file_id=dep("global_raw_file_id", lambda path: "fid-stage2092"),
        build_raw_stage_jobs=dep("build_raw_stage_jobs", lambda *args, **kwargs: ()),
        raw_stage_job_build_dependencies=dep("raw_stage_job_build_dependencies", object),
        raw_accumulator_store=dep("raw_accumulator_store", object),
        global_raw_publish_job=dep("global_raw_publish_job", lambda queue_dir, job: False),
        global_raw_process_one_job=dep("global_raw_process_one_job", lambda queue_dir, only_file_id=None: False),
        ordered_unique_tags=dep("ordered_unique_tags", lambda tags: list(tags or [])),
        finalize_tag_evidence_generation=dep("finalize_tag_evidence_generation", finalize_tag_evidence_generation),
        apply_integrity_tags=dep("apply_integrity_tags", lambda tags, integrity, marker="raw_accumulator_incomplete": list(tags or [])),
        normalize_tags=dep("normalize_tags", lambda tags: list(tags or [])),
        staged_enrichment_score=dep("staged_enrichment_score", lambda *args, **kwargs: (0.0, [])),
        scanner_degraded_tags=dep("scanner_degraded_tags", lambda tags: list(tags or [])),
        mark_raw_integrity_failure=dep("mark_raw_integrity_failure", lambda path, integrity, **kwargs: dict(integrity or {})),
        remember_scan_evidence=dep("remember_scan_evidence", lambda *args, **kwargs: None),
        normalize_yara_hits=dep("normalize_yara_hits", lambda hits: list(hits or [])),
        set_scan_integrity=dep("set_scan_integrity", lambda *args, **kwargs: None),
        log_error=dep("log_error", lambda message: None),
        record_issue=dep("record_issue", lambda where, exc: None),
        record_degradation=dep("record_degradation", lambda path, exc, where: None),
    )


def test_stage2092_global_raw_queue_uses_typed_outcome_for_missing_queue_dir() -> None:
    outcome = queue_executor.scan_file_via_global_raw_queue("sample.bin", "", deps=_deps())

    assert isinstance(outcome, GlobalRawQueueScanOutcome)
    assert outcome.ok is False
    assert outcome.status == "rejected"
    assert outcome.reason == "queue_dir_missing"
    assert outcome.result is None


def test_stage2092_global_raw_queue_outer_failure_is_replayable_typed_status(tmp_path) -> None:
    outcome = queue_executor.scan_file_via_global_raw_queue(
        "sample.bin",
        tmp_path,
        pretriage_tags=["force"],
        pretriage_suspicious=True,
        deps=_deps(sniff_file_identity=lambda path: (_ for _ in ()).throw(OSError("identity denied"))),
    )

    assert outcome.ok is False
    assert outcome.status == "failed"
    assert outcome.reason == "global_raw_scan_file_via_queue_failed"
    assert outcome.exception_type == "OSError"


def test_stage2092_queue_executor_source_has_no_none_sentinel_returns() -> None:
    source = inspect.getsource(queue_executor)

    assert "record_queue_failure_and_return_none" not in source
    assert "return None" not in source
    assert len(inspect.getsource(queue_executor.scan_file_via_global_raw_queue).splitlines()) < 40
