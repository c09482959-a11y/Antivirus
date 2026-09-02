"""Immutable in-memory scheduler runtime configuration ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.runtime_function_identity import is_runtime_native_function
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.orchestration.worker_runtime_descriptors import (
    WorkerYaraRuntimeDescriptor,
)
from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_runtime_config_snapshot_steps import (
    build_runtime_config_ipc_state,
    parse_runtime_config_scalars,
)
from Virus_Scan.scheduler.workers.inmemory_runtime_env import env_float, env_int, env_text


@dataclass(frozen=True, slots=True)
class InMemoryRuntimeConfigSnapshot:
    strict: bool
    yara_enabled: bool
    scan_cache_enabled: bool
    yara_runtime_descriptor: WorkerYaraRuntimeDescriptor
    scan_session_snapshot: ScanSessionSnapshot
    routing_evidence_context: RoutingEvidenceContext
    per_file_timeout_sec: int
    slow_file_warn_sec: float
    deep_scan_mode: str
    worker_threads: int
    worker_threads_base: int
    worker_threads_max: int
    cancel_table: Mapping[str, object] | None
    heartbeat_table: Mapping[str, object] | None
    heartbeat_interval_sec: float
    stage_semaphores: Mapping[str, object]
    stage_limits: Mapping[str, int]
    max_jobs_per_worker: int
    worker_rss_limit_mb: float
    heartbeat_flags: InMemoryHeartbeatFlags
    timeout_budget_factory: object
    timeout_result_annotator: object
    timeout_error_type: type[BaseException]
    mitre_initializer: object
    mitre_root: str
    mitre_enabled: bool
    mitre_available: bool
    mitre_repository_digest: str
    mitre_dataset_version: str
    mitre_unavailable_reason: str
    scheduler_config_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if type(self.scan_session_snapshot) is not ScanSessionSnapshot:
            raise TypeError("inmemory_scan_session_snapshot_invalid")
        if type(self.routing_evidence_context) is not RoutingEvidenceContext:
            raise TypeError("inmemory_routing_evidence_context_invalid")
        if type(self.yara_runtime_descriptor) is not WorkerYaraRuntimeDescriptor:
            raise TypeError("inmemory_yara_runtime_descriptor_invalid")
        if type(self.yara_enabled) is not bool:
            raise TypeError("inmemory_yara_enabled_invalid")
        if type(self.scan_cache_enabled) is not bool:
            raise TypeError("inmemory_scan_cache_enabled_invalid")
        if self.yara_runtime_descriptor.available and not self.yara_enabled:
            raise ValueError("inmemory_yara_available_while_scan_disabled")
        if not is_runtime_native_function(self.mitre_initializer):
            raise TypeError("inmemory_mitre_initializer_invalid")
        if type(self.mitre_root) is not str or self.mitre_root == "" or len(self.mitre_root) > 4096:
            raise ValueError("inmemory_mitre_root_invalid")
        if type(self.mitre_enabled) is not bool or type(self.mitre_available) is not bool:
            raise TypeError("inmemory_mitre_flags_invalid")
        if type(self.mitre_repository_digest) is not str or type(self.mitre_dataset_version) is not str:
            raise TypeError("inmemory_mitre_identity_invalid")
        if type(self.mitre_unavailable_reason) is not str or len(self.mitre_unavailable_reason) > 256:
            raise ValueError("inmemory_mitre_reason_invalid")
        if self.mitre_available:
            if not self.mitre_enabled or len(self.mitre_repository_digest) != 64 or len(self.mitre_dataset_version) != 40:
                raise ValueError("inmemory_mitre_available_identity_invalid")
        elif self.mitre_repository_digest != "" or self.mitre_dataset_version != "":
            raise ValueError("inmemory_mitre_unavailable_identity_present")
        object.__setattr__(self, "stage_limits", immutable_mapping(self.stage_limits))
        object.__setattr__(self, "stage_semaphores", immutable_mapping(self.stage_semaphores))
        object.__setattr__(self, "scheduler_config_evidence", tuple(
            immutable_mapping(item) for item in self.scheduler_config_evidence
        ))

    def as_worker_config(self) -> dict[str, object]:
        """Return the process-transfer payload consumed by worker execution."""
        return {
            "strict": self.strict,
            "yara_enabled": self.yara_enabled,
            "scan_cache_enabled": self.scan_cache_enabled,
            "yara_runtime_descriptor": self.yara_runtime_descriptor,
            "scan_session_manifest": self.scan_session_snapshot.to_record(),
            "routing_evidence_context": self.routing_evidence_context,
            "per_file_timeout_sec": self.per_file_timeout_sec,
            "slow_file_warn_sec": self.slow_file_warn_sec,
            "deep_scan_mode": self.deep_scan_mode,
            "worker_threads": self.worker_threads,
            "worker_threads_base": self.worker_threads_base,
            "worker_threads_max": self.worker_threads_max,
            "cancel_table": self.cancel_table,
            "heartbeat_table": self.heartbeat_table,
            "heartbeat_interval_sec": self.heartbeat_interval_sec,
            "stage_semaphores": self.stage_semaphores,
            "stage_limits": dict(self.stage_limits),
            "max_jobs_per_worker": self.max_jobs_per_worker,
            "worker_rss_limit_mb": self.worker_rss_limit_mb,
            "heartbeat_flags": self.heartbeat_flags,
            "timeout_budget_factory": self.timeout_budget_factory,
            "timeout_result_annotator": self.timeout_result_annotator,
            "timeout_error_type": self.timeout_error_type,
            "mitre_initializer": self.mitre_initializer,
            "mitre_root": self.mitre_root,
            "mitre_enabled": self.mitre_enabled,
            "mitre_available": self.mitre_available,
            "mitre_repository_digest": self.mitre_repository_digest,
            "mitre_dataset_version": self.mitre_dataset_version,
            "mitre_unavailable_reason": self.mitre_unavailable_reason,
            "scheduler_config_evidence": self.scheduler_config_evidence,
        }


def build_inmemory_runtime_config_snapshot(
    *, ctx: object, ctypes_module: object, environ: Mapping[str, str],
    recoverable_exceptions: tuple[type[BaseException], ...], get_init_value: object | None = None,
    file_count: int, workers: int, logical_slots: int, strict: bool, yara_enabled: bool,
    scan_cache_enabled: bool, yara_runtime_descriptor: WorkerYaraRuntimeDescriptor,
    scan_session_snapshot: ScanSessionSnapshot, routing_evidence_context: RoutingEvidenceContext,
    per_file_timeout_sec: float, slow_file_warn_sec: float, worker_threads: int,
    worker_threads_base: int, worker_threads_max: int, timeout_budget_factory: object,
    timeout_result_annotator: object, timeout_error_type: type[BaseException],
    mitre_initializer: object, mitre_root: str, mitre_enabled: bool, mitre_available: bool,
    mitre_repository_digest: str, mitre_dataset_version: str, mitre_unavailable_reason: str,
) -> InMemoryRuntimeConfigSnapshot:
    """Build the immutable in-memory scheduler configuration snapshot."""
    if get_init_value is None:
        get_init_value = lambda _name: None
    ipc_state = build_runtime_config_ipc_state(
        ctx=ctx, ctypes_module=ctypes_module, environ=environ,
        recoverable_exceptions=recoverable_exceptions, get_init_value=get_init_value,
        file_count=file_count, workers=workers, logical_slots=logical_slots,
    )
    scalar_state = parse_runtime_config_scalars(
        strict=strict, per_file_timeout_sec=per_file_timeout_sec,
        slow_file_warn_sec=slow_file_warn_sec, worker_threads=worker_threads,
        worker_threads_base=worker_threads_base, worker_threads_max=worker_threads_max,
    )
    if type(yara_enabled) is not bool:
        raise TypeError("inmemory_yara_enabled_exact_bool_required")
    if type(scan_cache_enabled) is not bool:
        raise TypeError("inmemory_scan_cache_enabled_exact_bool_required")
    return InMemoryRuntimeConfigSnapshot(
        strict=scalar_state.strict, yara_enabled=yara_enabled,
        scan_cache_enabled=scan_cache_enabled,
        yara_runtime_descriptor=yara_runtime_descriptor,
        scan_session_snapshot=scan_session_snapshot,
        routing_evidence_context=routing_evidence_context,
        per_file_timeout_sec=scalar_state.per_file_timeout_sec,
        slow_file_warn_sec=scalar_state.slow_file_warn_sec,
        deep_scan_mode=env_text(environ, "UMIGE_DEEP_SCAN_MODE", "auto"),
        worker_threads=scalar_state.worker_threads,
        worker_threads_base=scalar_state.worker_threads_base,
        worker_threads_max=scalar_state.worker_threads_max,
        cancel_table=ipc_state.cancel_table, heartbeat_table=ipc_state.heartbeat_table,
        heartbeat_interval_sec=env_float(environ, "UMIGE_INMEMORY_HEARTBEAT_INTERVAL_SEC", 0.5),
        stage_semaphores=ipc_state.stage_semaphores, stage_limits=ipc_state.stage_limits,
        max_jobs_per_worker=env_int(environ, "UMIGE_INMEMORY_MAX_JOBS_PER_WORKER", 75),
        worker_rss_limit_mb=env_float(environ, "UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB", 2048.0),
        heartbeat_flags=ipc_state.heartbeat_flags, timeout_budget_factory=timeout_budget_factory,
        timeout_result_annotator=timeout_result_annotator, timeout_error_type=timeout_error_type,
        mitre_initializer=mitre_initializer, mitre_root=mitre_root,
        mitre_enabled=mitre_enabled, mitre_available=mitre_available,
        mitre_repository_digest=mitre_repository_digest,
        mitre_dataset_version=mitre_dataset_version,
        mitre_unavailable_reason=mitre_unavailable_reason,
        scheduler_config_evidence=ipc_state.failure_evidence,
    )


__all__ = ("InMemoryRuntimeConfigSnapshot", "build_inmemory_runtime_config_snapshot")
