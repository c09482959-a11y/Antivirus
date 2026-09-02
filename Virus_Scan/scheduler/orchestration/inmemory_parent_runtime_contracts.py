"""Immutable in-memory parent runtime setup contracts."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, MutableSet
from typing import Protocol

from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_recoverable_exceptions
from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths



EvidenceRecord = Mapping[str, object]
JobRecord = dict[str, object]
JobRecords = MutableMapping[int, JobRecord]
ActiveJobs = MutableMapping[int, Mapping[str, object]]
StartWaitBudget = Callable[[Mapping[str, object] | None, float], float]


class InMemoryRecoveryMaintenanceProtocol(Protocol):
    completed: int

    def retry_or_fail(self, job_id: int, reason: object, *, pid: object = None) -> bool: ...
    def requeue_missing_after_empty_drain(self) -> tuple[int, int]: ...
    def request_cancel_only(self, job_id: int, reason: object, *, pid: object = None) -> bool: ...
    def record_lifecycle_request(self, request: InMemoryLifecycleRecordRequest) -> object: ...
    def retry_evidence_count(self) -> int: ...
    def retry_evidence_since(self, cursor: object) -> tuple[EvidenceRecord, ...]: ...
    def retry_evidence_snapshot(self) -> tuple[EvidenceRecord, ...]: ...
    def cancel_evidence_count(self) -> int: ...
    def cancel_evidence_since(self, cursor: object) -> tuple[EvidenceRecord, ...]: ...
    def cancel_evidence_snapshot(self) -> tuple[EvidenceRecord, ...]: ...
    def empty_drain_evidence_snapshot(self) -> tuple[EvidenceRecord, ...]: ...
    def append_empty_drain_evidence(self, records: object) -> int: ...


class InMemoryMemoryPolicyProtocol(Protocol):
    @property
    def rss_limit_mb(self) -> float: ...


@dataclass(frozen=True)
class InMemoryParentRuntimeSetupRequest:
    root: object
    all_files: tuple[object, ...]
    process_count: int
    strict: bool
    yara_enabled: bool
    per_file_timeout_sec: int | float
    slow_file_warn_sec: int | float
    recoverable_exceptions: tuple[type[BaseException], ...]
    scan_session_snapshot: ScanSessionSnapshot
    environ: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))
        if type(self.scan_session_snapshot) is not ScanSessionSnapshot:
            raise TypeError("inmemory_parent_scan_session_snapshot_invalid")
        if self.environ is not None:
            object.__setattr__(self, "environ", immutable_mapping(self.environ))


@dataclass(frozen=True)
class InMemoryParentRuntimeSetupResult:
    requested: int
    workers: int
    ctx: object
    manager: object
    worker_threads: int
    base_worker_threads: int
    thread_scale_cpu: object
    logical_slots: int
    queue_depth: int
    task_q: object
    result_q: object
    live_state: object
    state_index: object
    ewma_state: dict[str, float]
    cfg: object
    heartbeat_flags: object
    stage_limits: Mapping[str, object]
    heartbeat_table: object
    routing_evidence_context: object
    memory_policy: InMemoryMemoryPolicyProtocol
    timeout_config_evidence: tuple[object, ...]
    max_job_retries: int
    base_pf_timeout: float
    queued_start_timeout_sec: float
    assigned_start_timeout_sec: float
    heartbeat_stale_sec: float
    progress_stale_sec: float
    cancel_grace_sec: float
    pending: object
    job_records: JobRecords
    active: ActiveJobs
    worker_heartbeats: dict[object, object]
    worker_metrics: dict[object, object]
    done: MutableSet[int]
    failed: MutableSet[int]
    terminal: MutableSet[int]
    results: MutableMapping[object, object]
    procs: MutableSequence[object]
    lifecycle_epoch: int
    max_inflight: int
    max_queued_unstarted: int
    recovery: object

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage_limits", immutable_mapping(self.stage_limits))
