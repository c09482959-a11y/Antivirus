"""Worker-owned bootstrap contract for in-memory scheduler worker processes.

This module owns deterministic worker-process bootstrap state.  The worker loop
receives an immutable bootstrap result and does not own profile-policy setup,
logging policy, console handler installation, heartbeat table discovery, or
stage-table configuration inline.
"""
from __future__ import annotations

from dataclasses import dataclass
from Virus_Scan.contracts.scan_session_snapshot import scan_session_snapshot_from_record
from Virus_Scan.orchestration.scan_session import validate_scan_session_runtime
from Virus_Scan.orchestration.runtime_dependency_activation import (
    activate_runtime_scan_dependency_providers,
)
from Virus_Scan.models.profiles.persistence import resolved_profiles_dir
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.runtime.api import RuntimeEnvironmentOwner
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.workers.inmemory_worker_bootstrap_steps import (
    build_worker_bootstrap_snapshot,
    configure_worker_mitre_runtime,
    configure_worker_yara_metric_logging,
    configure_worker_yara_runtime,
    configure_worker_stage_tables,
    materialize_worker_bootstrap_config,
    silence_child_logging,
)
import signal
from typing import Callable, Mapping


@dataclass(frozen=True)
class InMemoryWorkerBootstrap:
    """Immutable bootstrap snapshot consumed by the in-memory worker loop."""

    cancel_table: object
    heartbeat_table: object
    heartbeat_flags: object
    heartbeat_interval: float
    max_jobs_per_worker: int
    worker_config: dict[str, object]


def configure_inmemory_worker_bootstrap(
    *,
    cfg: Mapping[str, object] | None,
    scheduler_runtime: object,
    install_child_console_handlers: Callable[..., object],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> InMemoryWorkerBootstrap:
    """Configure process-local worker state and return immutable loop inputs."""
    worker_config = materialize_worker_bootstrap_config(cfg)
    manifest = worker_config.pop("scan_session_manifest", None)
    snapshot = scan_session_snapshot_from_record(manifest)
    worker_config["scan_session_snapshot"] = snapshot
    activate_runtime_scan_dependency_providers()
    initialized_yara = configure_worker_yara_runtime(worker_config)
    descriptor = worker_config.get("yara_runtime_descriptor")
    if descriptor is None:
        raise RuntimeError("inmemory_worker_yara_descriptor_missing")
    worker_config["compiled_rules"] = initialized_yara if descriptor.available else None
    configure_worker_mitre_runtime(worker_config)
    cache_enabled = worker_config.get("scan_cache_enabled")
    if type(cache_enabled) is not bool:
        raise RuntimeError("inmemory_worker_scan_cache_enabled_missing")
    profiles_dir = resolved_profiles_dir()
    if cache_enabled:
        scan_cache_repository().configure_reader(profiles_dir)
        cache_generation = sqlite_lifecycle().generation("cache")
        if (
            cache_generation.generation_id != snapshot.cache_database_generation
            or cache_generation.schema_digest != snapshot.cache_database_schema_digest
        ):
            raise RuntimeError("inmemory_worker_scan_cache_identity_mismatch")
    else:
        scan_cache_repository().configure(profiles_dir, enabled=False)
    validate_scan_session_runtime(snapshot)
    metric_logging_enabled = RuntimeEnvironmentOwner().bool_flag(
        "UMIGE_YARA_SCAN_METRIC_LOGGING",
    )

    def record_bootstrap_suppressed(context: str, exc: BaseException) -> None:
        try:
            record_scheduler_suppressed(context, exc)
        except recoverable_exceptions as report_exc:
            _ = report_exc

    try:
        RuntimeEnvironmentOwner().publish({"UMIGE_PROCESS_SHARD": "1", "UMIGE_INMEMORY_WORKER": "1"})
        scheduler_runtime.configure_profile_policy(
            defer_profile_writes=True,
            profile_flush_every=25,
            bulk_profile_flush_every=1000000000,
        )
        silence_child_logging(
            record_bootstrap_suppressed=record_bootstrap_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        configure_worker_yara_metric_logging(
            enabled=metric_logging_enabled,
            record_bootstrap_suppressed=record_bootstrap_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        install_child_console_handlers(
            environ=scheduler_environment_snapshot(),
            signal_module=signal,
            record_suppressed=record_scheduler_suppressed,
        )
    except recoverable_exceptions as bootstrap_exc:
        record_bootstrap_suppressed("suppressed_exception", bootstrap_exc)

    configure_worker_stage_tables(
        worker_config=worker_config,
        scheduler_runtime=scheduler_runtime,
        record_bootstrap_suppressed=record_bootstrap_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return build_worker_bootstrap_snapshot(worker_config, bootstrap_type=InMemoryWorkerBootstrap)


__all__ = ("InMemoryWorkerBootstrap", "configure_inmemory_worker_bootstrap")
