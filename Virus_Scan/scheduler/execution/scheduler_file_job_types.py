"""Typed contracts for scheduler single-file execution."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeAlias, TYPE_CHECKING

from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadSnapshot
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from collections.abc import Callable, Iterable, Iterator, Mapping


SchedulerPath: TypeAlias = object
SchedulerRoot: TypeAlias = object
SchedulerTags: TypeAlias = tuple[object, ...]
SchedulerRecord: TypeAlias = dict[str, object]
SchedulerJobResult: TypeAlias = tuple[SchedulerPath, SchedulerRecord]
SchedulerPrefilterInfo: TypeAlias = dict[str, object]


class SchedulerTimeoutBudget(Protocol):
    """Timeout budget contract consumed by scheduler file execution."""

    @property
    def hard_timeout_seconds(self) -> int | float: ...

    def as_evidence(self) -> Mapping[str, object]: ...


class SchedulerRouteOutcome(Protocol):
    """Route outcome contract consumed by scheduler file execution."""

    identity: object
    tag_evidence: object

    def __iter__(self) -> Iterator[object]: ...


@dataclass(frozen=True)
class FastResultDecision:
    """Typed decision for optional prefilter fast-result publication."""

    available: bool
    result: SchedulerJobResult | None
    reason: str


@dataclass(frozen=True)
class SchedulerFileExecutionRequest:
    """Immutable request for one public scheduler file execution."""

    path: SchedulerPath
    root: SchedulerRoot
    scan_session_snapshot: ScanSessionSnapshot
    artifact_read_snapshot: ArtifactReadSnapshot
    previous_stage: str = "unknown"
    compiled_rules: object = None
    per_file_timeout_sec: int | float = 20
    slow_file_warn_sec: float = 2.0
    strict: bool = False
    yara_enabled: bool = True
    use_signal_timeout: bool = True
    routing_evidence_context: object = None

    def __post_init__(self) -> None:
        if type(self.scan_session_snapshot) is not ScanSessionSnapshot:
            raise TypeError("scheduler_scan_session_snapshot_required")
        if type(self.artifact_read_snapshot) is not ArtifactReadSnapshot:
            raise TypeError("scheduler_artifact_read_snapshot_required")


@dataclass(frozen=True)
class SchedulerFileExecutionDependencies:
    """Explicit dependencies for one scheduler-owned file execution."""

    current_thread: Callable[[], object]
    main_thread: Callable[[], object]
    nullcontext_factory: Callable[[], AbstractContextManager[object]]
    per_file_timeout: Callable[[int | float], AbstractContextManager[object]]
    compute_timeout_budget: Callable[..., SchedulerTimeoutBudget]
    scan_file_by_type: Callable[..., SchedulerRouteOutcome]
    effective_stage_for_path: Callable[[object, SchedulerPath], str]
    normalize_tags: Callable[[object], object]
    terminal_asset_triage: Callable[..., bool]
    make_terminal_asset_result: Callable[..., SchedulerRecord]
    attach_routing_evidence_to_record: Callable[..., SchedulerRecord]
    should_escalate_after_triage: Callable[..., bool]
    get_scan_extension: Callable[[SchedulerPath], str]
    deep_scan_thorough: Callable[[], bool]
    contextual_dangerous_anchor_hits: Callable[[Iterable[object] | None], list[str]]
    record_runtime_suppressed: Callable[[str, BaseException], None]
    normalize_yara_hits: Callable[[object], object]
    yara_scan_with_optional_zip: Callable[..., object]
    analyze_file_full_observe_only: Callable[..., SchedulerRecord]
    get_detector_errors: Callable[..., Iterable[Mapping[str, object]]]
    make_timeout_result: Callable[..., SchedulerRecord]
    annotate_timeout_result: Callable[..., SchedulerRecord]
    make_worker_error_result: Callable[[SchedulerPath, BaseException], SchedulerRecord]
    log_error: Callable[[str], None]
    time: Callable[[], float]
    basename: Callable[[SchedulerPath], str]
    warn_slow_file: Callable[[str], None]
    recoverable_exceptions: tuple[type[BaseException], ...]
    timeout_exception_type: type[BaseException]
