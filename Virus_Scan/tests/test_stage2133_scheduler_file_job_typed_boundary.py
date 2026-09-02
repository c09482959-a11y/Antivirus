from __future__ import annotations

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from contextlib import nullcontext

import pytest

from Virus_Scan.scheduler.execution.scheduler_file_job import (
    SchedulerFileExecutionDependencies,
    SchedulerFileExecutionRequest,
    _fast_result_decision,
    execute_scheduler_file_job,
)


class HostileSequence:
    iter_calls = 0
    bool_calls = 0
    str_calls = 0
    repr_calls = 0
    getattribute_calls = 0

    def __iter__(self):
        type(self).iter_calls += 1
        return iter(())

    def __bool__(self):
        type(self).bool_calls += 1
        return True

    def __str__(self):
        type(self).str_calls += 1
        return "hostile"

    def __repr__(self):
        type(self).repr_calls += 1
        return "HostileSequence()"

    def __getattribute__(self, name):
        if name not in {"__class__", "iter_calls", "bool_calls", "str_calls", "repr_calls", "getattribute_calls"}:
            type(self).getattribute_calls += 1
        return object.__getattribute__(self, name)


class FakeBudget:
    hard_timeout_seconds = 7.0

    def as_evidence(self):
        return {"hard_timeout_seconds": self.hard_timeout_seconds}


class HostileRouteOutcome:
    identity = "hostile-route"

    def __iter__(self):
        return iter((HostileSequence(), False))


def _reset_hostile() -> None:
    HostileSequence.iter_calls = 0
    HostileSequence.bool_calls = 0
    HostileSequence.str_calls = 0
    HostileSequence.repr_calls = 0
    HostileSequence.getattribute_calls = 0


def _assert_hostile_not_touched() -> None:
    assert HostileSequence.iter_calls == 0
    assert HostileSequence.bool_calls == 0
    assert HostileSequence.str_calls == 0
    assert HostileSequence.repr_calls == 0
    assert HostileSequence.getattribute_calls == 0


class FakeDeps(SchedulerFileExecutionDependencies):
    def __init__(self) -> None:
        super().__init__(
            current_thread=lambda: "thread",
            main_thread=lambda: "thread",
            nullcontext_factory=nullcontext,
            per_file_timeout=lambda _seconds: nullcontext(),
            compute_timeout_budget=lambda *_args, **_kwargs: FakeBudget(),
            scan_file_by_type=lambda _path, **_kwargs: HostileRouteOutcome(),
            effective_stage_for_path=lambda _tags, _path: "blocked",
            normalize_tags=lambda tags: tuple(tags),
            terminal_asset_triage=lambda *_args, **_kwargs: False,
            make_terminal_asset_result=lambda *_args, **_kwargs: {},
            attach_routing_evidence_to_record=lambda record, *_args, **_kwargs: record,
            should_escalate_after_triage=lambda *_args, **_kwargs: False,
            get_scan_extension=lambda _path: ".bin",
            deep_scan_thorough=lambda: False,
            contextual_dangerous_anchor_hits=lambda _hits: [],
            record_runtime_suppressed=lambda _label, _exc: None,
            normalize_yara_hits=lambda hits: tuple(hits),
            yara_scan_with_optional_zip=lambda *_args, **_kwargs: (),
            analyze_file_full_observe_only=lambda *_args, **_kwargs: {},
            get_detector_errors=lambda **_kwargs: (),
            make_timeout_result=lambda *_args, **_kwargs: {},
            annotate_timeout_result=lambda result, *_args, **_kwargs: result,
            make_worker_error_result=lambda _path, exc: {"error": type(exc).__name__, "message": str(exc)},
            log_error=lambda _message: None,
            time=lambda: 10.0,
            basename=lambda path: str(path).rsplit("/", 1)[-1],
            warn_slow_file=lambda _message: None,
            recoverable_exceptions=(ValueError,),
            timeout_exception_type=TimeoutError,
        )


def test_stage2133_absent_prefilter_fast_result_is_replayable_decision() -> None:
    decision = _fast_result_decision("sample.bin", 9.0, {"fast_result": None}, FakeDeps())

    assert decision.available is False
    assert decision.result is None
    assert decision.reason == "prefilter_fast_result_absent"


def test_stage2133_hostile_route_tags_are_rejected_without_caller_hooks() -> None:
    _reset_hostile()

    path, result = execute_scheduler_file_job(
        SchedulerFileExecutionRequest(
            path="sample.bin", root="root",
            scan_session_snapshot=scan_session_snapshot_fixture(),
            artifact_read_snapshot=artifact_read_snapshot_fixture("sample.bin"),
        ),
        FakeDeps(),
    )

    assert path == "sample.bin"
    assert result["error"] == "ValueError"
    assert "route_tags_sequence_rejected" in result["message"]
    _assert_hostile_not_touched()


def test_stage2133_non_mapping_fast_result_is_rejected_without_hooks() -> None:
    _reset_hostile()

    with pytest.raises(ValueError) as exc:
        _fast_result_decision("sample.bin", 9.0, {"fast_result": HostileSequence()}, FakeDeps())

    assert "prefilter_fast_result_mapping_rejected" in str(exc.value)
    _assert_hostile_not_touched()
