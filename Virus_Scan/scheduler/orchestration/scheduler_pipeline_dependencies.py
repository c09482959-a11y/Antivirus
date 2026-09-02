"""Scheduler pipeline dependency contract and production bindings.

This module owns the scheduler pipeline's callable dependency snapshot so the
runner can remain thin orchestration and tests can inject explicit callables
without mutating module globals.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast
import time

from Virus_Scan.contracts.env_config import str_env
from Virus_Scan.routing.engine_detect import freeze_profile_scoring_snapshot
from Virus_Scan.runtime.api import log_error as runtime_log_error
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe as _umige_make_json_safe
from Virus_Scan.scheduler.runtime.queue_filesystem import (
    clear_scan_integrity as _clear_scan_integrity,
    set_scan_integrity as _set_scan_integrity,
)
from Virus_Scan.scheduler.evidence.scheduler_json_writer import write_partial_scheduler_results
from Virus_Scan.scheduler.orchestration.finalization import finalize_scheduler_pipeline
from Virus_Scan.scheduler.orchestration.scheduler_file_execution_context import build_scheduler_file_execution_dependencies
from Virus_Scan.scheduler.orchestration.scheduler_mode_dispatch import run_scheduler_mode
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import (
    SchedulerModeDispatchDependencies,
    SchedulerModeDispatchRequest,
)
from Virus_Scan.scheduler.orchestration.scheduler_target_planning import (
    SchedulerTargetPlanningRequest,
    SchedulerTargetPlanningResult,
    plan_scheduler_targets,
)
from Virus_Scan.orchestration.scan_session import build_scan_session_snapshot
from Virus_Scan.publication.api import (
    clear_profile_scoring_snapshot,
    flush_all_persistent_models,
    persist_parent_learning_from_results,
    write_partial_scan_results as publication_write_partial_scan_results,
)


PipelineRecord = dict[object, object]

from Virus_Scan.scheduler.orchestration.scheduler_pipeline_partial_contracts import (
    EnvironmentGetter,
    ErrorLogger,
    JsonSafeMaterializer,
    PartialScanWriter,
    PartialSchedulerWriter,
    PipelineResults,
    TimeProvider,
)


class NullaryPipelineCallback(Protocol):
    def __call__(self) -> object: ...


class PersistentModelFlusher(Protocol):
    def __call__(self, *, force: bool = False) -> object: ...


class ParentLearningPersister(Protocol):
    def __call__(self, results: object) -> object: ...



class TargetPlanner(Protocol):
    def __call__(
        self,
        request: SchedulerTargetPlanningRequest,
        *,
        log_error: ErrorLogger,
        logging_module: object,
    ) -> SchedulerTargetPlanningResult: ...


class ScanSessionSnapshotBuilder(Protocol):
    def __call__(self, **kwargs: object) -> object: ...


class FileExecutionDependencyBuilder(Protocol):
    def __call__(self) -> object: ...


class ScanIntegrityClearer(Protocol):
    def __call__(self, path: object) -> object: ...


class ScanIntegritySetter(Protocol):
    def __call__(self, path: object, integrity: object) -> object: ...


class SchedulerModeRunner(Protocol):
    def __call__(
        self,
        request: SchedulerModeDispatchRequest,
        deps: SchedulerModeDispatchDependencies,
    ) -> dict[object, object]: ...


class PipelineFinalizer(Protocol):
    def __call__(self, request: object, dependencies: object) -> object: ...


@dataclass(frozen=True)
class SchedulerPipelineDependencies:
    """Explicit side-effect dependencies for the public scheduler pipeline."""

    time: TimeProvider
    environ_get: EnvironmentGetter
    freeze_profile_scoring_snapshot: NullaryPipelineCallback
    clear_profile_scoring_snapshot: NullaryPipelineCallback
    flush_all_persistent_models: PersistentModelFlusher
    persist_parent_learning_from_results: ParentLearningPersister
    write_partial_scheduler_results: PartialSchedulerWriter
    write_partial_scan_results: PartialScanWriter
    make_json_safe: JsonSafeMaterializer
    log_error: ErrorLogger
    plan_scheduler_targets: TargetPlanner
    build_scheduler_file_execution_dependencies: FileExecutionDependencyBuilder
    build_scan_session_snapshot: ScanSessionSnapshotBuilder
    clear_scan_integrity: ScanIntegrityClearer
    set_scan_integrity: ScanIntegritySetter
    run_scheduler_mode: SchedulerModeRunner
    finalize_scheduler_pipeline: PipelineFinalizer


def default_scheduler_pipeline_dependencies() -> SchedulerPipelineDependencies:
    """Return production scheduler pipeline dependencies without runtime mutation."""

    return SchedulerPipelineDependencies(
        time=time.time,
        environ_get=cast("EnvironmentGetter", str_env),
        freeze_profile_scoring_snapshot=freeze_profile_scoring_snapshot,
        clear_profile_scoring_snapshot=clear_profile_scoring_snapshot,
        flush_all_persistent_models=flush_all_persistent_models,
        persist_parent_learning_from_results=cast("ParentLearningPersister", persist_parent_learning_from_results),
        write_partial_scheduler_results=cast("PartialSchedulerWriter", write_partial_scheduler_results),
        write_partial_scan_results=cast("PartialScanWriter", publication_write_partial_scan_results),
        make_json_safe=_umige_make_json_safe,
        log_error=cast("ErrorLogger", runtime_log_error),
        plan_scheduler_targets=cast("TargetPlanner", plan_scheduler_targets),
        build_scheduler_file_execution_dependencies=build_scheduler_file_execution_dependencies,
        build_scan_session_snapshot=build_scan_session_snapshot,
        clear_scan_integrity=_clear_scan_integrity,
        set_scan_integrity=cast("ScanIntegritySetter", _set_scan_integrity),
        run_scheduler_mode=run_scheduler_mode,
        finalize_scheduler_pipeline=cast("PipelineFinalizer", finalize_scheduler_pipeline),
    )


__all__ = (
    "EnvironmentGetter",
    "ErrorLogger",
    "FileExecutionDependencyBuilder",
    "JsonSafeMaterializer",
    "NullaryPipelineCallback",
    "ParentLearningPersister",
    "PartialScanWriter",
    "PartialSchedulerWriter",
    "PersistentModelFlusher",
    "PipelineFinalizer",
    "PipelineRecord",
    "PipelineResults",
    "ScanIntegrityClearer",
    "ScanSessionSnapshotBuilder",
    "ScanIntegritySetter",
    "SchedulerModeRunner",
    "SchedulerPipelineDependencies",
    "TargetPlanner",
    "TimeProvider",
    "default_scheduler_pipeline_dependencies",
)
