"""Runtime resource-priority profile ownership for scheduler startup.

Owns static profile configuration and deterministic environment publication only.
"""

from __future__ import annotations

import logging
from types import MappingProxyType
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot, scheduler_environment_writer
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text

from Virus_Scan.runtime.api import publish_init_values


RESOURCE_PRIORITY_SETTINGS = MappingProxyType({
    "high": MappingProxyType({"process_queue_max_children": 100, "elastic_io_target_workers": 64, "elastic_min_workers": 24, "dynamic_queue_pending_multiplier": 8.0, "dynamic_queue_feed_burst_max": 160, "queue_latency_warn_sec": 0.75, "io_pressure_queue_files": 30000, "io_pressure_disk_busy": 96, "result_flush_batch_max": 512, "output_flush_interval_sec": 8.0, "global_raw_queue_max_chunks": 512, "raw_live_soft_cap": 1400, "raw_live_hard_cap": 2600, "raw_live_high_cap": 2200, "raw_live_extreme_cap": 3200, "raw_publish_batch_max": 192, "raw_per_file_active_cap": 256, "raw_global_active_cap": 2200, "raw_decode_cap": 224, "raw_payload_cap": 224, "raw_pe_api_cap": 256, "raw_binary_context_cap": 224, "raw_renpy_cap": 256, "stage_parallel_workers": 8, "raw_worker_pool_cap": 48, "worker_threads_per_process": 8, "worker_threads_max_per_process": 16, "raw_threads_per_process": 8, "adaptive_worker_threads": 1, "scale_up_step": 32, "scale_down_step": 6}),
    "medium": MappingProxyType({"process_queue_max_children": 64, "elastic_io_target_workers": 32, "elastic_min_workers": 12, "dynamic_queue_pending_multiplier": 4.0, "dynamic_queue_feed_burst_max": 96, "queue_latency_warn_sec": 0.35, "io_pressure_queue_files": 15000, "io_pressure_disk_busy": 90, "result_flush_batch_max": 192, "output_flush_interval_sec": 4.0, "global_raw_queue_max_chunks": 384, "raw_live_soft_cap": 800, "raw_live_hard_cap": 1600, "raw_live_high_cap": 1400, "raw_live_extreme_cap": 2000, "raw_publish_batch_max": 128, "raw_per_file_active_cap": 192, "raw_global_active_cap": 1536, "raw_decode_cap": 160, "raw_payload_cap": 160, "raw_pe_api_cap": 192, "raw_binary_context_cap": 160, "raw_renpy_cap": 192, "stage_parallel_workers": 6, "raw_worker_pool_cap": 24, "worker_threads_per_process": 2, "worker_threads_max_per_process": 4, "raw_threads_per_process": 4, "adaptive_worker_threads": 0, "scale_up_step": 20, "scale_down_step": 10}),
    "low": MappingProxyType({"process_queue_max_children": 24, "elastic_io_target_workers": 12, "elastic_min_workers": 4, "dynamic_queue_pending_multiplier": 2.0, "dynamic_queue_feed_burst_max": 48, "queue_latency_warn_sec": 0.15, "io_pressure_queue_files": 7000, "io_pressure_disk_busy": 82, "result_flush_batch_max": 64, "output_flush_interval_sec": 2.0, "global_raw_queue_max_chunks": 192, "raw_live_soft_cap": 350, "raw_live_hard_cap": 700, "raw_live_high_cap": 650, "raw_live_extreme_cap": 900, "raw_publish_batch_max": 64, "raw_per_file_active_cap": 96, "raw_global_active_cap": 768, "raw_decode_cap": 96, "raw_payload_cap": 96, "raw_pe_api_cap": 128, "raw_binary_context_cap": 96, "raw_renpy_cap": 128, "stage_parallel_workers": 4, "raw_worker_pool_cap": 8, "worker_threads_per_process": 1, "worker_threads_max_per_process": 2, "raw_threads_per_process": 2, "adaptive_worker_threads": 0, "scale_up_step": 8, "scale_down_step": 16}),
})
RESOURCE_PRIORITY_PROFILE = "high"



def _resource_priority_setting_text(value: object, *, default_text: object="high") -> object:
    text, reason = scheduler_text(
        value,
        replacement_text=default_text,
        unsupported_reason="resource_priority_profile_rejected",
    )
    if reason or text == "":
        return default_text
    return text.strip().lower()


def _resource_priority_normalize(priority: object="high", *, env: object=None) -> object:
    source = scheduler_environment_snapshot(env)
    priority_text = _resource_priority_setting_text(priority, default_text="")
    if priority_text == "":
        priority_text = _resource_priority_setting_text(
            scheduler_mapping_value(source, "UMIGE_RESOURCE_PRIORITY", default="high"),
            default_text="high",
        )
    return priority_text if priority_text in RESOURCE_PRIORITY_SETTINGS else "high"



def resource_priority_snapshot(priority: object=None, *, env: object=None) -> object:
    source = scheduler_environment_snapshot(env)
    env_priority = scheduler_mapping_value(
        source,
        "UMIGE_RESOURCE_PRIORITY",
        default=RESOURCE_PRIORITY_PROFILE,
    )
    profile = _resource_priority_normalize(
        priority if priority is not None else env_priority,
        env=source,
    )
    return MappingProxyType({
        "profile": profile,
        "config": MappingProxyType(
            dict(
                RESOURCE_PRIORITY_SETTINGS[_resource_priority_normalize(profile, env=source)]
            )
        ),
    })


def apply_resource_priority_profile(priority: object="high", *, explicit_stage_workers: object=None, env: object=None) -> object:
    """Apply High/Medium/Low resource profile to an explicit runtime environment.

    Production defaults to the scheduler-owned environment writer. Tests and callers that need isolated
    policy publication can pass a mapping-like object directly instead of
    mutating process-global state.
    """
    target_env = scheduler_environment_writer(env)
    profile = _resource_priority_normalize(priority, env=target_env)
    cfg = dict(
        RESOURCE_PRIORITY_SETTINGS[_resource_priority_normalize(profile, env=target_env)]
    )
    target_env["UMIGE_RESOURCE_PRIORITY"] = profile

    env_pairs = (
        ("process_queue_max_children", "UMIGE_PROCESS_QUEUE_MAX_CHILDREN"),
        ("elastic_io_target_workers", "UMIGE_ELASTIC_IO_TARGET_WORKERS"),
        ("elastic_min_workers", "UMIGE_ELASTIC_MIN_WORKERS"),
        ("dynamic_queue_pending_multiplier", "UMIGE_DYNAMIC_QUEUE_PENDING_MULTIPLIER"),
        ("dynamic_queue_feed_burst_max", "UMIGE_DYNAMIC_QUEUE_FEED_BURST_MAX"),
        ("queue_latency_warn_sec", "UMIGE_QUEUE_LATENCY_WARN_SEC"),
        ("io_pressure_queue_files", "UMIGE_IO_PRESSURE_QUEUE_FILES"),
        ("io_pressure_disk_busy", "UMIGE_IO_PRESSURE_DISK_BUSY"),
        ("result_flush_batch_max", "UMIGE_RESULT_FLUSH_BATCH_MAX"),
        ("output_flush_interval_sec", "UMIGE_OUTPUT_FLUSH_INTERVAL_SEC"),
        ("global_raw_queue_max_chunks", "UMIGE_GLOBAL_RAW_QUEUE_MAX_CHUNKS"),
        ("raw_live_soft_cap", "UMIGE_RAW_LIVE_SOFT_CAP"),
        ("raw_live_hard_cap", "UMIGE_RAW_LIVE_HARD_CAP"),
        ("raw_live_high_cap", "UMIGE_RAW_LIVE_HIGH_CAP"),
        ("raw_live_extreme_cap", "UMIGE_RAW_LIVE_EXTREME_CAP"),
        ("raw_publish_batch_max", "UMIGE_RAW_PUBLISH_BATCH_MAX"),
        ("raw_per_file_active_cap", "UMIGE_RAW_PER_FILE_ACTIVE_CAP"),
        ("raw_global_active_cap", "UMIGE_RAW_GLOBAL_ACTIVE_CAP"),
        ("raw_decode_cap", "UMIGE_RAW_DECODE_CAP"),
        ("raw_payload_cap", "UMIGE_RAW_PAYLOAD_CAP"),
        ("raw_pe_api_cap", "UMIGE_RAW_PE_API_CAP"),
        ("raw_binary_context_cap", "UMIGE_RAW_BINARY_CONTEXT_CAP"),
        ("raw_renpy_cap", "UMIGE_RAW_RENPY_CAP"),
        ("scale_up_step", "UMIGE_ELASTIC_SCALE_UP_STEP"),
        ("scale_down_step", "UMIGE_ELASTIC_SCALE_DOWN_STEP"),
        ("raw_worker_pool_cap", "UMIGE_RAW_WORKER_POOL_CAP"),
        ("worker_threads_per_process", "UMIGE_INMEMORY_WORKER_THREADS_PER_PROCESS"),
        ("worker_threads_max_per_process", "UMIGE_INMEMORY_WORKER_THREADS_MAX_PER_PROCESS"),
        ("adaptive_worker_threads", "UMIGE_INMEMORY_ADAPTIVE_WORKER_THREADS"),
        ("raw_threads_per_process", "UMIGE_INMEMORY_RAW_THREADS_PER_PROCESS"),
    )
    for key, env_name in env_pairs:
        target_env[env_name] = _resource_priority_setting_text(cfg[key], default_text="0")
    if explicit_stage_workers is None:
        target_env["UMIGE_STAGE_PARALLEL_WORKERS"] = _resource_priority_setting_text(
            cfg["stage_parallel_workers"],
            default_text="0",
        )

    logging.info(
        "Resource priority: %s max_children=%s io_target=%s raw_soft=%s "
        "raw_hard=%s pending_multiplier=%s",
        profile,
        cfg["process_queue_max_children"],
        cfg["elastic_io_target_workers"],
        cfg["raw_live_soft_cap"],
        cfg["raw_live_hard_cap"],
        cfg["dynamic_queue_pending_multiplier"],
    )
    return profile, cfg


def init_scheduler_resources() -> object:
    publish_init_values((
        ('RESOURCE_PRIORITY_PROFILE', RESOURCE_PRIORITY_PROFILE),
        ('RESOURCE_PRIORITY_SETTINGS', RESOURCE_PRIORITY_SETTINGS),
    ))
    return publish_init_values(())

__all__ = (
    'RESOURCE_PRIORITY_PROFILE',
    'RESOURCE_PRIORITY_SETTINGS',
    'apply_resource_priority_profile',
    'init_scheduler_resources',
    'resource_priority_snapshot',
)
