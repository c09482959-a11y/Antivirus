"""Bounded bootstrap steps for in-memory scheduler workers."""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.runtime_function_identity import is_runtime_native_function
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.orchestration.worker_runtime_descriptors import WorkerYaraRuntimeDescriptor


_YARA_SCAN_METRIC_LOGGER_NAME = "Virus_Scan.yara.match"
_YARA_SCAN_METRIC_HANDLER_NAME = "umige_yara_scan_metric_stderr"


def materialize_worker_bootstrap_config(cfg: Mapping[str, object] | None) -> dict[str, object]:
    """Return a plain worker config from exact mapping items without hooks."""
    config_items = no_hook_mapping_items(cfg)
    return scheduler_str_key_mapping_from_items(config_items)


def configure_worker_yara_runtime(worker_config: Mapping[str, object]) -> object:
    """Initialize process-local YARA from the exact parent-approved descriptor."""
    descriptor = worker_config.get("yara_runtime_descriptor")
    if type(descriptor) is not WorkerYaraRuntimeDescriptor:
        raise RuntimeError("inmemory_worker_yara_descriptor_missing")
    return descriptor.initializer(
        root=descriptor.root,
        enabled=descriptor.enabled,
        available=descriptor.available,
        scan_mode=descriptor.scan_mode,
        package_kind=descriptor.package_kind,
        source_path=descriptor.source_path,
        expected_source_digest=descriptor.source_digest,
        expected_compiled_cache_digest=descriptor.compiled_cache_digest,
        expected_rule_catalog_digest=descriptor.rule_catalog_digest,
        unavailable_reason=descriptor.unavailable_reason,
    )


def configure_worker_mitre_runtime(worker_config: Mapping[str, object]) -> object:
    """Initialize the process-local MITRE runtime from the parent activation descriptor."""
    initializer = worker_config.get("mitre_initializer")
    if not is_runtime_native_function(initializer):
        raise RuntimeError("inmemory_worker_mitre_initializer_missing")
    return initializer(
        root=worker_config.get("mitre_root"),
        enabled=worker_config.get("mitre_enabled"),
        available=worker_config.get("mitre_available"),
        expected_repository_digest=worker_config.get("mitre_repository_digest"),
        expected_dataset_version=worker_config.get("mitre_dataset_version"),
        unavailable_reason=worker_config.get("mitre_unavailable_reason"),
    )


def silence_child_logging(
    *,
    record_bootstrap_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Force quiet worker logging while recording any failure as suppressed evidence."""
    try:
        logging.getLogger().setLevel(logging.ERROR)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.ERROR)
    except recoverable_exceptions as logging_exc:
        record_bootstrap_suppressed("suppressed_exception", logging_exc)


def configure_worker_yara_metric_logging(
    *,
    enabled: bool,
    record_bootstrap_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Publish canonical YARA diagnostic metrics from quiet process workers."""
    if type(enabled) is not bool:
        raise TypeError("worker_yara_metric_logging_enabled_invalid")
    if not enabled:
        return
    try:
        logger = logging.getLogger(_YARA_SCAN_METRIC_LOGGER_NAME)
        matching = tuple(
            handler for handler in logger.handlers
            if handler.get_name() == _YARA_SCAN_METRIC_HANDLER_NAME
        )
        if matching:
            handler = matching[0]
            for duplicate in matching[1:]:
                logger.removeHandler(duplicate)
        else:
            handler = logging.StreamHandler()
            handler.set_name(_YARA_SCAN_METRIC_HANDLER_NAME)
            logger.addHandler(handler)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.setLevel(logging.INFO)
        logger.propagate = False
    except recoverable_exceptions as logging_exc:
        record_bootstrap_suppressed("suppressed_exception", logging_exc)


def configure_worker_stage_tables(
    *,
    worker_config: Mapping[str, object],
    scheduler_runtime: object,
    record_bootstrap_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Install worker-owned stage limit/semaphore tables."""
    try:
        stage_semaphores = worker_config.get("stage_semaphores")
        stage_limits = worker_config.get("stage_limits")
        scheduler_runtime.configure_worker_stage_tables(
            stage_semaphores={} if stage_semaphores is None else stage_semaphores,
            stage_limits={} if stage_limits is None else stage_limits,
            failure_evidence=worker_config.get("scheduler_config_evidence", ()),
        )
    except recoverable_exceptions as stage_exc:
        record_bootstrap_suppressed("suppressed_exception", stage_exc)


def build_worker_bootstrap_snapshot(
    worker_config: Mapping[str, object],
    *,
    bootstrap_type: Callable[..., object],
) -> object:
    """Build immutable loop bootstrap inputs from the materialized config."""
    heartbeat_interval = max(0.25, float(worker_config.get("heartbeat_interval_sec", 1.0) or 1.0))
    max_jobs_per_worker = int(
        worker_config.get("max_jobs_per_worker")
        or int_env("UMIGE_INMEMORY_MAX_JOBS_PER_WORKER", 75, 1, None)
        or "75"
    )
    return bootstrap_type(
        cancel_table=worker_config.get("cancel_table"),
        heartbeat_table=worker_config.get("heartbeat_table"),
        heartbeat_flags=worker_config.get("heartbeat_flags"),
        heartbeat_interval=heartbeat_interval,
        max_jobs_per_worker=max_jobs_per_worker,
        worker_config=dict(worker_config),
    )


__all__ = (
    "build_worker_bootstrap_snapshot",
    "configure_worker_mitre_runtime",
    "configure_worker_yara_metric_logging",
    "configure_worker_yara_runtime",
    "configure_worker_stage_tables",
    "materialize_worker_bootstrap_config",
    "silence_child_logging",
)
