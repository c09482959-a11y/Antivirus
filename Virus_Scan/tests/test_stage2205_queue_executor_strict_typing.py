"""Stage2205 queue executor strict-typing contract regressions."""
from __future__ import annotations

from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation

import inspect

from Virus_Scan.scheduler.execution import queue_executor


class CompletedAccumulatorHandle:
    def __init__(self) -> None:
        self.initialized: dict[str, object] = {}

    def init(
        self,
        path: object,
        *,
        expected: int,
        initial_tags: list[object],
        effective_stage: str,
        ext_stage: str,
        identity: object,
    ) -> None:
        self.initialized = {
            "path": path,
            "expected": expected,
            "initial_tags": tuple(initial_tags),
            "effective_stage": effective_stage,
            "ext_stage": ext_stage,
            "identity": identity,
        }

    def reconcile_expected(self, published: int, *, reason: str) -> None:
        self.initialized["reconciled"] = (published, reason)

    def load(self) -> dict[str, object]:
        return {
            "expected": 4,
            "completed": 4,
            "failed": 0,
            "retried": 0,
            "degraded": False,
            "tags": ["raw_identity"],
            "strings_parts": ["hello"],
            "effective_stage": "binary",
            "suspicious": True,
            "yara_hits": [],
            "errors": [],
        }


class CompletedAccumulatorFactory:
    def __init__(self) -> None:
        self.handle = CompletedAccumulatorHandle()

    def __call__(self, queue_dir: object, file_id: str) -> CompletedAccumulatorHandle:
        return self.handle

    def is_complete(self, accum: object) -> bool:
        return True


def _deps(store: CompletedAccumulatorFactory) -> queue_executor.GlobalRawQueueScanDependencies:
    return queue_executor.GlobalRawQueueScanDependencies(
        sniff_file_identity=lambda path: {"tags": ["identity"]},
        get_scan_extension=lambda path: ".bin",
        normalize_stage=lambda ext: "binary",
        choose_effective_stage=lambda ext_stage, identity: "binary",
        runtime_value=lambda name, default=None: default,
        global_raw_eligible=lambda path, effective_stage: True,
        raw_queue_live_count=lambda queue_dir: 0,
        global_raw_file_id=lambda path: "fid-stage2205",
        build_raw_stage_jobs=lambda path, file_id, effective_stage, ext_stage, identity, *, deps: tuple(
            {"file": path, "file_id": file_id, "collector": "identity", "seq": index}
            for index in range(4)
        ),
        raw_stage_job_build_dependencies=lambda: object(),
        raw_accumulator_store=store,
        global_raw_publish_job=lambda queue_dir, job: True,
        global_raw_process_one_job=lambda queue_dir, *, only_file_id: False,
        ordered_unique_tags=lambda tags: list(dict.fromkeys(tags)),
        finalize_tag_evidence_generation=finalize_tag_evidence_generation,
        apply_integrity_tags=lambda tags, integrity, marker="raw_accumulator_incomplete": list(tags),
        normalize_tags=lambda tags: list(tags or []),
        staged_enrichment_score=lambda tags, stage, score: (0.0, []),
        scanner_degraded_tags=lambda tags: list(tags or []) + ["scanner_degraded"],
        mark_raw_integrity_failure=lambda path, integrity, **kwargs: dict(integrity),
        remember_scan_evidence=lambda *args, **kwargs: None,
        normalize_yara_hits=lambda hits: list(hits or []),
        set_scan_integrity=lambda path, integrity: None,
        log_error=lambda message: None,
        record_issue=lambda where, exc: None,
        record_degradation=lambda path, exc, where: None,
    )


def test_stage2205_queue_executor_boundary_has_no_any_or_variadic_callable() -> None:
    source = inspect.getsource(queue_executor)
    assert "typing import Any" not in source
    assert ": Any" not in source
    assert "Mapping[str, Any]" not in source
    assert "Callable[...," not in source
    assert "raw_accumulator_store: Any" not in source


def test_stage2205_queue_executor_contracts_preserve_completed_scan_outcome() -> None:
    store = CompletedAccumulatorFactory()

    outcome = queue_executor.scan_file_via_global_raw_queue(
        "sample.bin",
        "queue-dir",
        timeout_sec=1,
        pretriage_tags=["pretriage"],
        pretriage_suspicious=True,
        deps=_deps(store),
    )

    assert outcome.ok is True
    assert outcome.status == "completed"
    result = outcome.require_result()
    assert result["file_id"] == "fid-stage2205"
    assert result["effective_stage"] == "binary"
    assert result["suspicious"] is True
    assert store.handle.initialized["expected"] == 4
    assert "global_raw_queue_scan" in store.handle.initialized["initial_tags"]
