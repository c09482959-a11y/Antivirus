"""Stage1850 raw queue execution no-hook closure regressions."""
from __future__ import annotations

from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation

import inspect
from dataclasses import dataclass
from typing import Any

from Virus_Scan.scheduler.execution import queue_executor
from Virus_Scan.scheduler.execution.queue_executor import GlobalRawQueueScanDependencies
from Virus_Scan.scheduler.execution.raw_stage_collector_dispatch import dispatch_raw_stage_collector
from Virus_Scan.scheduler.execution.raw_stage_failure import raw_stage_failure_result
from Virus_Scan.scheduler.execution.raw_stage_input import build_raw_stage_input
from Virus_Scan.scheduler.execution.raw_work_executor import envelope_from_raw_result
from Virus_Scan.scheduler.execution.scan_job_executor import RawQueueJobExecutionDependencies, process_one_raw_stage_job


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("must not stringify")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("must not repr")

    def __format__(self, spec: str) -> str:
        type(self).touched += 1
        raise RuntimeError("must not format")

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("must not bool")

    def __int__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("must not int")

    def __float__(self) -> float:
        type(self).touched += 1
        raise RuntimeError("must not float")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("must not iterate")


class RawInputDeps:
    def __init__(self, chunk_bytes: Any = 1024, cache_value: Any = 2048) -> None:
        self.chunk_bytes = chunk_bytes
        self.cache_value = cache_value

    def raw_chunk_bytes(self) -> Any:
        return self.chunk_bytes

    def runtime_value(self, name: str, default: Any = None) -> Any:
        return self.cache_value if name == "RAW_STAGE_EXEC_CACHE_MAX" else default

    def normalize_raw_collector_value(self, value: Any) -> dict[str, Any]:
        return {"tags": []}


@dataclass(frozen=True)
class Envelope:
    error: str = ""

    def to_accumulator_record(self) -> dict[str, Any]:
        return {"collector": "identity", "tags": []}


class BadAccumulator:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def append(self, payload: Any) -> None:
        raise RuntimeError("accumulator denied")


class CollectorDispatchDeps:
    def raw_stage_failure_result(self, out: dict[str, Any], collector: Any, exc: BaseException, *, stage: str) -> dict[str, Any]:
        out["failure_stage"] = stage
        out["error"] = type(exc).__name__ + ":" + BaseException.__getattribute__(exc, "args")[0]
        return out


def scanner_degraded_tags(tags: Any) -> list[str]:
    return list(tags or []) + ["scanner_failure", "scanner_degraded", "scan_incomplete"]


def _queue_deps(stage_value: Any, issues: list[tuple[str, str]]) -> GlobalRawQueueScanDependencies:
    return GlobalRawQueueScanDependencies(
        sniff_file_identity=lambda path: {"tags": []},
        get_scan_extension=lambda path: ".bin",
        normalize_stage=lambda ext: "binary",
        choose_effective_stage=lambda ext_stage, identity: stage_value,
        runtime_value=lambda name, default=None: default,
        global_raw_eligible=lambda path, effective_stage=None: True,
        raw_queue_live_count=lambda queue_dir: 0,
        global_raw_file_id=lambda path: "fid-stage1850",
        build_raw_stage_jobs=lambda *args, **kwargs: [{"file": "sample.bin", "collector": "identity", "file_id": "fid-stage1850", "seq": index} for index in range(4)],
        raw_stage_job_build_dependencies=lambda: object(),
        raw_accumulator_store=lambda *args, **kwargs: None,
        global_raw_publish_job=lambda queue_dir, job: True,
        global_raw_process_one_job=lambda queue_dir, only_file_id=None: False,
        ordered_unique_tags=lambda tags: list(tags),
        finalize_tag_evidence_generation=finalize_tag_evidence_generation,
        apply_integrity_tags=lambda tags, integrity, marker="raw_accumulator_incomplete": list(tags),
        normalize_tags=lambda tags: list(tags or []),
        staged_enrichment_score=lambda *args, **kwargs: 0,
        scanner_degraded_tags=scanner_degraded_tags,
        mark_raw_integrity_failure=lambda *args, **kwargs: None,
        remember_scan_evidence=lambda *args, **kwargs: None,
        normalize_yara_hits=lambda hits: list(hits or []),
        set_scan_integrity=lambda *args, **kwargs: None,
        log_error=lambda message: None,
        record_issue=lambda where, exc: issues.append((where, type(exc).__name__)),
        record_degradation=lambda path, exc, where: None,
    )


def _job_deps(job: dict[str, Any], finish_calls: list[tuple[bool, Any, Any]]) -> RawQueueJobExecutionDependencies:
    return RawQueueJobExecutionDependencies(
        claim_matching=lambda *args, **kwargs: (job, "claim.json"),
        execute_stage_job=lambda raw_job: {"tags": ["identity"]},
        envelope_from_raw_result=lambda raw_job, result: Envelope(),
        result_has_infra_error=lambda value: False,
        classify_recovery=lambda *args, **kwargs: object(),
        default_failure_info=lambda **kwargs: kwargs,
        prepare_raw_retry=lambda *args, **kwargs: False,
        accumulator_store=BadAccumulator,
        record_suppressed=lambda where, exc: None,
        safe_exception_info=lambda *args, **kwargs: {"unsafe": True},
        finish_job=lambda queue_dir, claim_path, ok=True, error_info=None, job=None: finish_calls.append((ok, error_info, job)),
        recoverable_exceptions=(RuntimeError,),
    )


def test_stage1850_queue_effective_stage_rejects_hostile_scalar_before_tags(tmp_path) -> None:
    HostileScalar.reset()
    issues: list[tuple[str, str]] = []

    result = queue_executor.scan_file_via_global_raw_queue(
        "sample.bin",
        tmp_path,
        pretriage_tags=["suspicious"],
        pretriage_suspicious=True,
        deps=_queue_deps(HostileScalar(), issues),
    )

    assert result.ok is False
    assert result.status == "rejected"
    assert result.reason == "raw_queue_effective_stage_rejected"
    assert HostileScalar.touched == 0
    assert ("raw_queue_effective_stage_rejected", "ValueError") in issues


def test_stage1850_raw_stage_failure_and_input_reject_hostile_scalars_without_hooks() -> None:
    HostileScalar.reset()
    hostile = HostileScalar()

    failed = raw_stage_failure_result(
        {"file": hostile, "file_id": hostile, "tags": []},
        hostile,
        RuntimeError("collector failed"),
        stage="raw_stage_identity",
        scanner_degraded_tags=scanner_degraded_tags,
    )
    raw_input = build_raw_stage_input({"file": "sample.bin", "collector": hostile, "start": hostile, "size": hostile}, RawInputDeps())

    assert HostileScalar.touched == 0
    assert failed["error"].startswith("raw_stage:")
    assert raw_input.boundary_failed is True
    assert "collector_unavailable" in raw_input.out["raw_stage_boundary_evidence"]
    assert "start_unavailable" in raw_input.out["raw_stage_boundary_evidence"]
    assert "size_unavailable" in raw_input.out["raw_stage_boundary_evidence"]


def test_stage1850_raw_work_and_scan_job_exception_paths_do_not_call_hostile_hooks(tmp_path) -> None:
    HostileScalar.reset()
    hostile = HostileScalar()
    env = envelope_from_raw_result(
        {"file": "sample.bin", "collector": hostile, "attempt": hostile, "seq": hostile},
        {"error": hostile},
    )
    finish_calls: list[tuple[bool, Any, Any]] = []
    job = {"job_type": "raw_stage", "file": "sample.bin", "collector": hostile, "file_id": "fid-stage1850", "attempt": hostile}

    processed = process_one_raw_stage_job(tmp_path, deps=_job_deps(job, finish_calls))

    assert HostileScalar.touched == 0
    assert env.collector == "raw_stage"
    assert env.ok is False
    assert processed is True
    assert finish_calls and finish_calls[0][0] is False
    assert finish_calls[0][1]["stage"] == "raw_stage_exception"
    assert finish_calls[0][1]["exception_type"] == "RuntimeError"


def test_stage1850_unknown_collector_uses_scheduler_owned_error() -> None:
    out = dispatch_raw_stage_collector(job={}, path="sample.bin", collector="unknown", start=0, size=1, out={}, deps=CollectorDispatchDeps())

    assert out["failure_stage"] == "raw_stage_unknown_collector"
    assert "unknown_global_raw_collector:unknown" in out["error"]


def test_stage1850_removed_exact_proven_unsafe_snippets() -> None:
    queue_source = inspect.getsource(queue_executor)
    raw_failure_source = inspect.getsource(raw_stage_failure_result)
    raw_input_source = inspect.getsource(build_raw_stage_input)
    raw_work_source = inspect.getsource(envelope_from_raw_result)
    scan_source = inspect.getsource(process_one_raw_stage_job)

    assert 'fallback="unknown"' not in queue_source
    assert 'f"router_stage_{effective_stage}"' not in queue_source
    assert 'float(timeout_sec or 0)' not in queue_source
    assert 'f"{scheduler_evidence_path(path, field_name=' not in queue_source
    assert 'f"completed={accum.get(' not in queue_source
    assert 'f"{scheduler_exception_text(exc)}; raw scan marked incomplete"' not in queue_source
    assert 'fallback=default' not in raw_failure_source
    assert 'f"{coll}:{err_text}"' not in raw_failure_source
    assert 'fallback=' not in raw_input_source
    assert 'scheduler_int(' not in raw_input_source
    assert 'scheduler_text(' not in raw_input_source
    assert 'fallback=' not in raw_work_source
    assert 'scheduler_int(' not in raw_work_source
    assert 'scheduler_text(' not in raw_work_source
    assert 'fallback=' not in scan_source
    assert 'return deps.safe_exception_info' not in scan_source
    assert 'fallback_error' not in scan_source
