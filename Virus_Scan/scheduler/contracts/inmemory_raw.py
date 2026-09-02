"""Immutable contracts for in-memory raw worker enrichment."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import time
from typing import Protocol, TypeAlias

RawIdentity: TypeAlias = Mapping[str, object]
RawJob: TypeAlias = Mapping[str, object]
RawJobSequence: TypeAlias = Sequence[RawJob]
RawResult: TypeAlias = Mapping[str, object]
RawTagSequence: TypeAlias = Sequence[object]


class GlobalRawEligible(Protocol):
    def __call__(self, path: object, *, effective_stage: str) -> bool: ...


class RawStageJobBuilder(Protocol):
    def __call__(
        self,
        path: object,
        file_id: str,
        effective_stage: str,
        ext_stage: str,
        identity: RawIdentity,
        *,
        deps: object,
    ) -> RawJobSequence: ...


class StageJobExecutor(Protocol):
    def __call__(self, job: dict[str, object]) -> RawResult | dict[str, object]: ...


class SchedulerExecutor(Protocol):
    def submit(self, fn: Callable[[RawJob], RawResult | dict[str, object]], job: RawJob) -> object: ...


class SchedulerThreadPoolFactory(Protocol):
    def __call__(self, *, max_workers: int, thread_name_prefix: str) -> SchedulerExecutor: ...


class IssueRecorder(Protocol):
    def __call__(
        self,
        issue: str,
        exc: BaseException,
        *,
        fatal: bool = False,
        extra: Mapping[str, object] | None = None,
    ) -> object: ...


class RememberScanEvidence(Protocol):
    def __call__(self, path: object, **items: object) -> object: ...


class FinalizeTagEvidenceGeneration(Protocol):
    def __call__(
        self,
        inputs: object,
        *,
        path: object,
        strings_blob: object,
        source: str,
        previous_generation: object = None,
    ) -> object: ...


class IntegrityTagApplicator(Protocol):
    def __call__(
        self,
        tags: Sequence[object],
        integrity: Mapping[str, object],
        *,
        marker: str,
    ) -> RawTagSequence: ...


@dataclass(frozen=True, slots=True)
class InMemoryRawScanDependencies:
    deep_scan_thorough: Callable[[], bool]
    sniff_file_identity: Callable[[object], RawIdentity]
    get_scan_extension: Callable[[object], str]
    runtime_value: Callable[[str, object], object]
    normalize_stage: Callable[[object], str]
    choose_effective_stage: Callable[[str, RawIdentity], object]
    global_raw_eligible: GlobalRawEligible
    global_raw_file_id: Callable[[object], str]
    build_raw_stage_jobs: RawStageJobBuilder
    raw_stage_job_build_dependencies: Callable[[], object]
    execute_stage_job: StageJobExecutor
    scheduler_thread_pool: SchedulerThreadPoolFactory
    environ_get: Callable[[str, str], str]
    record_issue: IssueRecorder
    scanner_degraded_tags: Callable[[], RawTagSequence]
    finalize_tag_evidence_generation: FinalizeTagEvidenceGeneration
    normalize_tags: Callable[[object], RawTagSequence]
    staged_enrichment_score: Callable[[object, str, float], tuple[float, RawTagSequence]]
    record_suppressed: Callable[[str, BaseException], object]
    set_scan_integrity: Callable[[object, Mapping[str, object]], object]
    remember_scan_evidence: RememberScanEvidence
    apply_integrity_tags: IntegrityTagApplicator
    normalize_yara_hits: Callable[[object], object]
    log_error: Callable[[object], object]
    recoverable_exceptions: tuple[type[BaseException], ...]
    now: Callable[[], float] = time.time

