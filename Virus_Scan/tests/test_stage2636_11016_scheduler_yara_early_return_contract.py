"""Stage2636.11016 scheduler-owned exact YARA result publication regressions."""
from __future__ import annotations

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from contextlib import nullcontext
from types import SimpleNamespace

from Virus_Scan.contracts.yara_hits import YaraScanResult, yara_scan_result_record
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.reporting.result_schema import make_terminal_asset_result
from Virus_Scan.runtime.yara_rules_state import yara_rules_state
from Virus_Scan.scheduler.execution.raw_stage_collector_dispatch import (
    dispatch_raw_stage_collector,
)
from Virus_Scan.scheduler.execution.scheduler_file_job import execute_scheduler_file_job
from Virus_Scan.scheduler.execution.scheduler_file_job_types import (
    SchedulerFileExecutionDependencies,
    SchedulerFileExecutionRequest,
)
from Virus_Scan.scheduler.execution.scheduler_yara_result import (
    cached_scheduler_yara_result,
    obtain_scheduler_yara_result,
)
from Virus_Scan.scheduler.workers.inmemory_file_scan_analysis_steps import (
    build_inmemory_full_analysis_inputs,
)
from Virus_Scan.scheduler.workers.inmemory_file_scan_execution import (
    prefilter_inmemory_context,
    terminal_inmemory_triage_result,
)
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    canonical_test_yara_no_match_result,
)
from Virus_Scan.tests.support.scan_cache_fixtures import (
    verified_scan_cache_identity,
)


class _Budget:
    hard_timeout_seconds = 20.0

    def as_evidence(self) -> dict[str, object]:
        return {"hard_timeout_seconds": self.hard_timeout_seconds}


class _RouteOutcome:
    identity = "route-test"
    tag_evidence = TagEvidence.from_records(())

    def __iter__(self):
        return iter((("media_asset",), False))


class _CountingScan:
    def __init__(self, result: YaraScanResult | None = None) -> None:
        self.calls = 0
        self.result = result or canonical_test_yara_no_match_result()

    def __call__(self, _path: object, *, compiled_rules: object) -> YaraScanResult:
        assert compiled_rules == "selected-rules"
        self.calls += 1
        return self.result


def _direct_terminal_dependencies(scan: _CountingScan) -> SchedulerFileExecutionDependencies:
    times = iter((10.0, 10.1, 10.2))
    return SchedulerFileExecutionDependencies(
        current_thread=lambda: "thread",
        main_thread=lambda: "thread",
        nullcontext_factory=nullcontext,
        per_file_timeout=lambda _seconds: nullcontext(),
        compute_timeout_budget=lambda *_args, **_kwargs: _Budget(),
        scan_file_by_type=lambda _path, **_kwargs: _RouteOutcome(),
        effective_stage_for_path=lambda _tags, _path: "stage-test",
        normalize_tags=lambda tags: tuple(tags),
        terminal_asset_triage=lambda *_args, **_kwargs: True,
        make_terminal_asset_result=make_terminal_asset_result,
        attach_routing_evidence_to_record=lambda record, *_args, **_kwargs: record,
        should_escalate_after_triage=lambda *_args, **_kwargs: False,
        get_scan_extension=lambda _path: ".bin",
        deep_scan_thorough=lambda: False,
        contextual_dangerous_anchor_hits=lambda _hits: [],
        record_runtime_suppressed=lambda _label, _exc: None,
        normalize_yara_hits=lambda hits: tuple(hits),
        yara_scan_with_optional_zip=scan,
        analyze_file_full_observe_only=lambda *_args, **_kwargs: {},
        get_detector_errors=lambda **_kwargs: (),
        make_timeout_result=lambda *_args, **_kwargs: {},
        annotate_timeout_result=lambda result, *_args, **_kwargs: result,
        make_worker_error_result=lambda _path, exc: {
            "error": type(exc).__name__,
            "message": str(exc),
        },
        log_error=lambda _message: None,
        time=lambda: next(times),
        basename=lambda path: str(path).rsplit("/", 1)[-1],
        warn_slow_file=lambda _message: None,
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        timeout_exception_type=TimeoutError,
    )


def test_direct_terminal_path_executes_and_publishes_one_canonical_result() -> None:
    scan = _CountingScan()
    path, result = execute_scheduler_file_job(
        SchedulerFileExecutionRequest(
            path="sample.bin",
            root="root",
            compiled_rules="selected-rules",
            yara_enabled=True,

            scan_session_snapshot=scan_session_snapshot_fixture(),
            artifact_read_snapshot=artifact_read_snapshot_fixture("sample.bin"),
        ),
        _direct_terminal_dependencies(scan),
    )

    assert path == "sample.bin"
    assert scan.calls == 1
    assert result["yara_hits"] == []
    assert result["yara_evidence"]["status"] == "complete_no_match"
    skipped = result["explanation"]["constraints"]["heavy_layers_skipped"]
    assert "full_yara" not in skipped


def test_inmemory_prefilter_candidate_cannot_bypass_canonical_terminal_path() -> None:
    scan = _CountingScan()
    fast_result = make_terminal_asset_result("sample.bin", ("media_asset",))

    prefilter = prefilter_inmemory_context(
        path="sample.bin",
        compiled_rules="selected-rules",
        artifact_read_snapshot=artifact_read_snapshot_fixture("sample.bin"),
        strict_fast_prefilter=lambda *_args, **_kwargs: {
            "fast_result": fast_result,
            "tags": (),
            "meta": {},
        },
    )

    assert prefilter["fast_result"] is None
    assert prefilter["meta"]["scheduler_terminal_shortcut_rejected"] == "mode_semantic_equivalence_required"
    assert scan.calls == 0


def test_inmemory_terminal_path_executes_once_before_scheduler_retention() -> None:
    scan = _CountingScan()

    _tags, _suspicious, _stage, completed, _evidence = terminal_inmemory_triage_result(
        path="sample.bin",
        prefilter_info={},
        prev_stage="unknown",
        cache_sha256="",
        active_timeout_budget=_Budget(),
        compiled_rules="selected-rules",
        yara_enabled=True,
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=artifact_read_snapshot_fixture("sample.bin"),
        yara_scan_with_optional_zip=scan,
        scan_file_by_type=lambda _path, **_kwargs: _RouteOutcome(),
        effective_stage_for_path=lambda _tags, _path: "stage-test",
        is_terminal_clean_asset_triage=lambda *_args, **_kwargs: True,
        make_terminal_asset_result=make_terminal_asset_result,
    )

    assert completed is not None
    assert scan.calls == 1
    assert completed[1]["yara_evidence"]["status"] == "complete_no_match"


def test_inmemory_full_analysis_reuses_raw_yara_result_without_second_scan() -> None:
    scan = _CountingScan()
    existing = canonical_test_yara_no_match_result()

    outputs = build_inmemory_full_analysis_inputs(
        path="sample.bin",
        tags=(),
        tag_evidence=TagEvidence.from_records(()),
        suspicious=False,
        curr_stage="stage-test",
        per_file_timeout_sec=20,
        timeout_budget_factory=lambda *_args, **_kwargs: _Budget(),
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        should_escalate_after_inmemory_triage=lambda *_args: True,
        get_scan_extension=lambda _path: ".bin",
        scan_file_inmemory_raw=lambda *_args, **_kwargs: {
            "yara_evidence": yara_scan_result_record(existing),
            "tags": (),
            "suspicious": False,
            "effective_stage": "stage-test",
        },
        inmemory_raw_scan_dependencies=lambda: object(),
        compiled_rules="selected-rules",
        yara_enabled=True,
        yara_scan_with_optional_zip=scan,
        progress=lambda _state: None,
    )

    yara_result = outputs[6]
    assert scan.calls == 0
    assert yara_result is existing or yara_result.to_record() == existing.to_record()
    assert yara_result.scan_pass_id == existing.scan_pass_id


def test_inmemory_full_analysis_nonraw_path_scans_exactly_once() -> None:
    scan = _CountingScan()

    outputs = build_inmemory_full_analysis_inputs(
        path="sample.bin",
        tags=(),
        tag_evidence=TagEvidence.from_records(()),
        suspicious=False,
        curr_stage="stage-test",
        per_file_timeout_sec=20,
        timeout_budget_factory=lambda *_args, **_kwargs: _Budget(),
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        should_escalate_after_inmemory_triage=lambda *_args: False,
        get_scan_extension=lambda _path: ".bin",
        scan_file_inmemory_raw=lambda *_args, **_kwargs: {},
        inmemory_raw_scan_dependencies=lambda: object(),
        compiled_rules="selected-rules",
        yara_enabled=True,
        yara_scan_with_optional_zip=scan,
        progress=lambda _state: None,
    )

    assert scan.calls == 1
    assert outputs[6].status == "complete_no_match"


def test_disabled_scheduler_result_never_calls_engine() -> None:
    scan = _CountingScan()
    result = obtain_scheduler_yara_result(
        path="sample.bin",
        yara_enabled=False,
        compiled_rules="selected-rules",
        yara_scan_with_optional_zip=scan,
    )

    assert scan.calls == 0
    assert result.status == "disabled"


def test_cache_reuse_requires_exact_current_yara_identity() -> None:
    result = canonical_test_yara_no_match_result()
    record = {"yara_evidence": yara_scan_result_record(result)}
    exact_identity = verified_scan_cache_identity(
        package_kind="custom",
        source_seed="a",
        compiled_seed="b",
        catalog_seed="d",
    )
    stale_identity = verified_scan_cache_identity(
        package_kind="custom",
        source_seed="1",
        compiled_seed="b",
        catalog_seed="d",
    )

    assert cached_scheduler_yara_result(record, exact_identity) is not None
    assert cached_scheduler_yara_result(record, stale_identity) is None
    assert cached_scheduler_yara_result({}, exact_identity) is None


def test_raw_yara_failure_publishes_failed_not_clean_no_match() -> None:
    class _RawDeps:
        def yara_rules_state(self):
            return yara_rules_state()

        def yara_scan_with_optional_zip(self, *_args, **_kwargs):
            raise RuntimeError("engine failed")

        def raw_stage_failure_result(
            self,
            out: dict[str, object],
            collector: str,
            error: BaseException,
            *,
            stage: str,
        ) -> dict[str, object]:
            out["failure"] = {
                "collector": collector,
                "error": type(error).__name__,
                "stage": stage,
            }
            return out

        def normalize_yara_hits(self, value: object):
            return tuple(value)

    out = dispatch_raw_stage_collector(
        job={"collector": "yara"},
        path="sample.bin",
        collector="yara",
        start=0,
        size=0,
        out={},
        deps=_RawDeps(),
    )

    assert out["failure"]["stage"] == "raw_stage_yara"
    assert out["yara_evidence"]["status"] == "failed"
    assert out["yara_hits"] == []
