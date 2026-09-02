"""Typed contracts for global raw queue execution dependencies."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass
import time
from typing import Protocol, TypeAlias

RawQueueValue: TypeAlias = object
RawQueueList: TypeAlias = list[RawQueueValue]
RawQueueRecord: TypeAlias = Mapping[str, object]
RawQueueMapping: TypeAlias = Mapping[str, RawQueueValue]
MutableRawQueueRecord: TypeAlias = MutableMapping[str, object]
RawQueueMutableMapping: TypeAlias = MutableMapping[str, RawQueueValue]
RawQueueJobRows: TypeAlias = Iterable[RawQueueRecord]
RawQueueTagNormalizer: TypeAlias = Callable[[RawQueueValue], RawQueueList]
RawQueueStageScorer: TypeAlias = Callable[[object, object, str, float], tuple[float, RawQueueList]]
RawQueueIntegrityMarker: TypeAlias = Callable[..., RawQueueMutableMapping]
RawQueueIntegritySetter: TypeAlias = Callable[[str, RawQueueMapping], RawQueueValue]


class ObjectCallback(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> object: ...


class ScanIdentitySniffer(Protocol):
    def __call__(self, path: object) -> RawQueueRecord: ...


class PathValueReader(Protocol):
    def __call__(self, path: object) -> object: ...


class StageChooser(Protocol):
    def __call__(self, ext_stage: str, identity: RawQueueRecord) -> object: ...


class RuntimeValueReader(Protocol):
    def __call__(self, name: str, default: object = None) -> object: ...


class GlobalRawEligibility(Protocol):
    def __call__(self, path: object, *, effective_stage: str) -> bool: ...


class RawQueueLiveCount(Protocol):
    def __call__(self, queue_dir: object) -> int: ...


class RawQueueFileId(Protocol):
    def __call__(self, path: object) -> str: ...


class RawStageJobBuilder(Protocol):
    def __call__(self, path: object, file_id: str, effective_stage: str, ext_stage: str, identity: RawQueueRecord, *, deps: object) -> RawQueueJobRows: ...


class ObjectFactory(Protocol):
    def __call__(self) -> object: ...


class RawAccumulatorHandle(Protocol):
    def init(self, path: object, *, expected: int, initial_tags: list[object], effective_stage: str, ext_stage: str, identity: RawQueueRecord) -> None: ...
    def reconcile_expected(self, published: int, *, reason: str) -> None: ...
    def load(self) -> RawQueueRecord: ...


class RawAccumulatorStoreFactory(Protocol):
    def __call__(self, queue_dir: object, file_id: str) -> RawAccumulatorHandle: ...
    def is_complete(self, accum: RawQueueRecord) -> bool: ...


class RawJobPublisher(Protocol):
    def __call__(self, queue_dir: object, job: RawQueueRecord) -> bool: ...


class RawJobProcessor(Protocol):
    def __call__(self, queue_dir: object, *, only_file_id: str) -> bool: ...


class QueueIssueRecorder(Protocol):
    def __call__(self, where: str, exc: BaseException) -> object: ...


class QueueErrorLogger(Protocol):
    def __call__(self, message: str) -> object: ...


class QueueDegradationRecorder(Protocol):
    def __call__(self, path: object, exc: BaseException, *, where: str) -> object: ...


class QueueClock(Protocol):
    def __call__(self) -> float: ...


class QueueSleeper(Protocol):
    def __call__(self, delay: float) -> None: ...


RawQueueFinalizeTags: TypeAlias = Callable[..., RawQueueList]
RawQueueFinalizeEvidenceGeneration: TypeAlias = Callable[..., object]
RawQueueEvidenceRecorder: TypeAlias = Callable[..., RawQueueValue]


def queue_sleep(delay: float) -> None:
    time.sleep(delay)


@dataclass(frozen=True)
class GlobalRawQueueScanDependencies:
    sniff_file_identity: ScanIdentitySniffer
    get_scan_extension: PathValueReader
    normalize_stage: PathValueReader
    choose_effective_stage: StageChooser
    runtime_value: RuntimeValueReader
    global_raw_eligible: GlobalRawEligibility
    raw_queue_live_count: RawQueueLiveCount
    global_raw_file_id: RawQueueFileId
    build_raw_stage_jobs: RawStageJobBuilder
    raw_stage_job_build_dependencies: ObjectFactory
    raw_accumulator_store: RawAccumulatorStoreFactory
    global_raw_publish_job: RawJobPublisher
    global_raw_process_one_job: RawJobProcessor
    ordered_unique_tags: RawQueueTagNormalizer
    finalize_tag_evidence_generation: RawQueueFinalizeEvidenceGeneration
    apply_integrity_tags: RawQueueFinalizeTags
    normalize_tags: RawQueueTagNormalizer
    staged_enrichment_score: RawQueueStageScorer
    scanner_degraded_tags: RawQueueTagNormalizer
    mark_raw_integrity_failure: RawQueueIntegrityMarker
    remember_scan_evidence: RawQueueEvidenceRecorder
    normalize_yara_hits: RawQueueTagNormalizer
    set_scan_integrity: RawQueueIntegritySetter
    log_error: QueueErrorLogger
    record_issue: QueueIssueRecorder
    record_degradation: QueueDegradationRecorder
    now: QueueClock = time.time
    sleep: QueueSleeper = queue_sleep
