from __future__ import annotations

from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from contextlib import nullcontext
from pathlib import Path

import pytest

from Virus_Scan.scheduler.execution.process_queue_runner import run_process_queue
from Virus_Scan.scheduler.execution.scheduler_file_job import SchedulerFileExecutionDependencies
from Virus_Scan.scheduler.orchestration.process_queue_completion import ProcessQueueCompletionRequest
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import SchedulerModeDispatchRequest
from Virus_Scan.scheduler.orchestration.scheduler_pipeline_profile_finalization import (
    SchedulerPipelineRunFinalizationRequest,
    SchedulerProfilePolicyRequest,
    configure_scheduler_profile_policy,
    finalize_scheduler_pipeline_run,
)

from Virus_Scan.scheduler.orchestration.scheduler_file_worker import (
    SchedulerWorkerBuildRequest,
    build_scheduler_file_worker,
)
from Virus_Scan.scheduler.orchestration.scheduler_pipeline_runtime import (
    SchedulerPipelineRunState,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).getattribute_calls += 1
            raise AssertionError("__class__ hook must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("__str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("__repr__ hook must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise AssertionError("__format__ hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("__bool__ hook must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("__iter__ hook must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("__float__ hook must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("__int__ hook must not execute")


class FakeProfileRuntime:
    def __init__(self) -> None:
        self.configured = None
        self.restored = False

    def configure_profile_policy(self, **kwargs):
        self.configured = kwargs
        return {"snapshot": "profile"}

    def restore_profile_policy(self, _snapshot) -> None:
        self.restored = True


class FakeProfileDependencies:
    def __init__(self) -> None:
        self.frozen = False

    def freeze_profile_scoring_snapshot(self) -> None:
        self.frozen = True


class FakeFinalizeDependencies:
    def __init__(self) -> None:
        self.finalized_request = None
        self.environ_get = lambda _name, _default=None: _default
        self.persist_parent_learning_from_results = lambda _results: None
        self.flush_all_persistent_models = lambda: None
        self.clear_profile_scoring_snapshot = lambda: None
        self.log_error = lambda _message: None

    def finalize_scheduler_pipeline(self, request, _dependencies) -> None:
        self.finalized_request = request


class CapturingFinalizationRequest:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs


class CapturingFinalizationDependencies:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs


class FakeIntegrityDependencies:
    def __init__(self) -> None:
        self.cleared = []
        self.integrity = None

    @staticmethod
    def time() -> float:
        return 1.0

    def clear_scan_integrity(self, path) -> None:
        self.cleared.append(path)

    def set_scan_integrity(self, _path, integrity) -> None:
        self.integrity = integrity


class FakeBudget:
    hard_timeout_seconds = 20.0

    def as_evidence(self):
        return {"timeout": 20.0}


class FakeRouteOutcome:
    identity = "fake-router"

    def __iter__(self):
        return iter((("terminal",), True))


_THREAD = object()


class FakeFileExecutionDependencies(SchedulerFileExecutionDependencies):
    def __init__(self) -> None:
        super().__init__(
            current_thread=lambda: _THREAD,
            main_thread=lambda: _THREAD,
            nullcontext_factory=nullcontext,
            per_file_timeout=lambda _seconds: nullcontext(),
            compute_timeout_budget=lambda *_args, **_kwargs: FakeBudget(),
            scan_file_by_type=lambda _path, **_kwargs: FakeRouteOutcome(),
            effective_stage_for_path=lambda _tags, _path: "terminal",
            normalize_tags=lambda tags: tuple(tags),
            terminal_asset_triage=lambda _tags, suspicious=False: True,
            make_terminal_asset_result=self.make_terminal_asset_result,
            attach_routing_evidence_to_record=lambda record, *_args, **_kwargs: record,
            should_escalate_after_triage=lambda *_args, **_kwargs: False,
            get_scan_extension=lambda _path: ".bin",
            deep_scan_thorough=lambda: False,
            contextual_dangerous_anchor_hits=lambda _hits: False,
            record_runtime_suppressed=lambda _context, _exc: None,
            normalize_yara_hits=lambda hits: tuple(hits),
            yara_scan_with_optional_zip=lambda *_args, **_kwargs: (),
            analyze_file_full_observe_only=lambda *_args, **_kwargs: {},
            get_detector_errors=lambda **_kwargs: (),
            make_timeout_result=lambda *_args, **_kwargs: {},
            annotate_timeout_result=lambda result, *_args, **_kwargs: result,
            make_worker_error_result=lambda _path, _exc: {},
            log_error=lambda _message: None,
            time=lambda: 1.0,
            basename=lambda path: Path(path).name,
            warn_slow_file=lambda _message: None,
            recoverable_exceptions=(RuntimeError,),
            timeout_exception_type=TimeoutError,
        )

    def make_terminal_asset_result(self, _path, tags, **_kwargs):
        return {
            "tags": tuple(tags),
            "trusted_benign": False,
            "scan_integrity": HostileValue(),
        }


def _reset() -> None:
    HostileValue.str_calls = 0
    HostileValue.repr_calls = 0
    HostileValue.format_calls = 0
    HostileValue.bool_calls = 0
    HostileValue.iter_calls = 0
    HostileValue.float_calls = 0
    HostileValue.int_calls = 0
    HostileValue.getattribute_calls = 0


def _assert_no_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0


def test_stage1798_profile_policy_rejects_hostile_scalars_without_hooks() -> None:
    _reset()

    with pytest.raises(ValueError) as exc:
        configure_scheduler_profile_policy(
            SchedulerProfilePolicyRequest(
                scheduler_runtime=FakeProfileRuntime(),
            dependencies=FakeProfileDependencies(),
            defer_profile_flush=HostileValue(),
            freeze_existing_baselines=False,
            profile_flush_every=25,
                bulk_profile_flush_every=1000000000,
            )
        )

    assert "scheduler_profile_defer_flush_rejected" in str(exc.value)
    _assert_no_hooks()


def test_stage1798_profile_policy_accepts_exact_scalars_without_hooks() -> None:
    _reset()
    runtime = FakeProfileRuntime()
    deps = FakeProfileDependencies()

    snapshot = configure_scheduler_profile_policy(
        SchedulerProfilePolicyRequest(
            scheduler_runtime=runtime,
        dependencies=deps,
        defer_profile_flush="true",
        freeze_existing_baselines="true",
        profile_flush_every="7",
            bulk_profile_flush_every="11",
        )
    )

    assert snapshot == {"snapshot": "profile"}
    assert runtime.configured == {
        "defer_profile_writes": True,
        "profile_flush_every": 7,
        "bulk_profile_flush_every": 11,
    }
    assert deps.frozen is True
    _assert_no_hooks()


def test_stage1798_dispatch_request_rejects_hostile_control_scalars_without_hooks() -> None:
    _reset()

    with pytest.raises(ValueError) as exc:
        SchedulerModeDispatchRequest(
            scheduler="serial",
            workers=1,
            root=Path("root"),
            all_files=("game.exe",),
            total_files=HostileValue(),
            scan_started_at=0.0,
            strict=False,
            yara_enabled=False,
            progress_every=10,
            throttle_sec=0.0,
            partial_output_path=None,
            partial_output_every=10,
            slow_file_warn_sec=2.0,
            per_file_timeout_sec=20.0,
            work_queue_dir=None,
            worker_output_path=None,

            scan_session_snapshot=scan_session_snapshot_fixture(),        )

    assert "scheduler_dispatch_total_files_rejected" in str(exc.value)
    _assert_no_hooks()


def test_stage1798_process_queue_runner_rejects_hostile_file_sequence_without_hooks() -> None:
    _reset()

    with pytest.raises(ValueError) as exc:
        run_process_queue(Path("root"), HostileValue(), 1, scan_session_snapshot=scan_session_snapshot_fixture())

    assert "process_queue_runner_all_files_rejected" in str(exc.value)
    _assert_no_hooks()


def test_stage1798_completion_request_rejects_hostile_status_scalars_without_hooks() -> None:
    _reset()

    with pytest.raises(ValueError) as exc:
        ProcessQueueCompletionRequest(
            queue_dir=Path("queue"),
            runtime_dir=Path("runtime"),
            worker_pool=object(),
            all_files=("game.exe",),
            partial_output_path=None,
            strict=HostileValue(),
            had_error=False,
        )

    assert "process_queue_completion_strict_rejected" in str(exc.value)
    _assert_no_hooks()


def test_stage1798_finalization_rejects_hostile_flags_without_hooks() -> None:
    _reset()

    with pytest.raises(ValueError) as exc:
        finalize_scheduler_pipeline_run(SchedulerPipelineRunFinalizationRequest(
            state=SchedulerPipelineRunState(results={}),
            dependencies=FakeFinalizeDependencies(),
            scheduler_runtime=FakeProfileRuntime(),
            finalization_request_factory=CapturingFinalizationRequest,
            finalization_dependencies_factory=CapturingFinalizationDependencies,
            scheduler_mode="serial",
            strict=HostileValue(),
            freeze_existing_baselines=False,
            profile_policy_snapshot={"snapshot": "profile"},
            write_partial=lambda **_kwargs: None,
            recoverable_exceptions=(RuntimeError,),
        ))

    assert "scheduler_finalization_strict_rejected" in str(exc.value)
    _assert_no_hooks()


def test_stage1798_worker_scan_integrity_rejects_hostile_mapping_without_hooks() -> None:
    _reset()
    integrity_deps = FakeIntegrityDependencies()
    worker = build_scheduler_file_worker(
        request=SchedulerWorkerBuildRequest(
            root=Path("root"),
            compiled_rules=None,
            per_file_timeout_sec=20.0,
            slow_file_warn_sec=2.0,
            strict=False,
            yara_enabled=False,
            routing_evidence_context=None,

            scan_session_snapshot=scan_session_snapshot_fixture(),        ),
        dependencies=integrity_deps,
        file_execution_dependencies=FakeFileExecutionDependencies(),
    )

    executed_path, result = worker("game.exe")

    assert executed_path == "game.exe"
    assert result["scan_integrity"]["unsupported_scheduler_value"] is True
    assert result["scan_integrity"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert integrity_deps.integrity == result["scan_integrity"]
    _assert_no_hooks()
