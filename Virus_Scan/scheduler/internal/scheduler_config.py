"""Immutable scheduler configuration snapshots."""
from __future__ import annotations

from Virus_Scan.contracts.env_config import bool_env, float_env, int_env
from Virus_Scan.scheduler.context.config_snapshot import (
    SchedulerConfigSnapshot,
    SchedulerConfigSnapshotRequest,
    build_scheduler_config_snapshot,
)
from Virus_Scan.scheduler.internal.scheduler_config_values import (
    process_queue_env_float,
    process_queue_env_int,
)


# Raw scheduler defaults initialization now belongs to internal scheduler config.
from Virus_Scan.runtime.api import publish_init_values
from Virus_Scan.runtime.api import scheduler_runtime_state


def init_raw_scheduler_defaults() -> object:
    STAGE_PARALLEL_DEFAULT_WORKERS = int_env('UMIGE_STAGE_PARALLEL_WORKERS', 6, 1, None)
    INTRASTAGE_PARALLEL_VERSION = 'intrastage_continuous_queue_strings_yara_decode_v10'
    INTRASTAGE_MIN_TEXT_CHARS = int_env('UMIGE_INTRASTAGE_MIN_TEXT_CHARS', 65536, 1, None)
    INTRASTAGE_CHUNK_CHARS = int_env('UMIGE_INTRASTAGE_CHUNK_CHARS', 65536, 1, None)
    INTRASTAGE_CHUNK_OVERLAP = int_env('UMIGE_INTRASTAGE_CHUNK_OVERLAP', 4096, 0, None)
    INTRASTAGE_MAX_CHUNKS = int_env('UMIGE_INTRASTAGE_MAX_CHUNKS', 128, 1, None)
    GLOBAL_RAW_QUEUE_ENABLED = bool_env('UMIGE_GLOBAL_RAW_QUEUE', default=True)
    GLOBAL_RAW_QUEUE_MIN_BYTES = int_env('UMIGE_GLOBAL_RAW_QUEUE_MIN_BYTES', 64 * 1024, 1, None)
    GLOBAL_RAW_QUEUE_CHUNK_BYTES = int_env('UMIGE_GLOBAL_RAW_QUEUE_CHUNK_BYTES', 64 * 1024, 1, None)
    GLOBAL_RAW_QUEUE_MAX_CHUNKS = int_env('UMIGE_GLOBAL_RAW_QUEUE_MAX_CHUNKS', 384, 1, None)
    RAW_LIVE_SOFT_CAP = int_env('UMIGE_RAW_LIVE_SOFT_CAP', 1000, 1, None)
    RAW_LIVE_HARD_CAP = int_env('UMIGE_RAW_LIVE_HARD_CAP', 1800, 1, None)
    RAW_PUBLISH_BATCH_MAX = int_env('UMIGE_RAW_PUBLISH_BATCH_MAX', 128, 1, None)
    RAW_PER_FILE_ACTIVE_CAP = int_env('UMIGE_RAW_PER_FILE_ACTIVE_CAP', 192, 1, None)
    RPA_USE_GLOBAL_RAW_QUEUE = bool_env('UMIGE_RPA_GLOBAL_RAW_QUEUE', default=False)
    RPA_ZIP_MAX_MEMBERS = int_env('UMIGE_RPA_ZIP_MAX_MEMBERS', 64, 1, None)
    RPA_ZIP_MAX_DEPTH = int_env('UMIGE_RPA_ZIP_MAX_DEPTH', 1, 0, None)
    RPA_ZIP_MAX_MEMBER_SIZE = int_env('UMIGE_RPA_ZIP_MAX_MEMBER_SIZE', 8 * 1024 * 1024, 1, None)
    RPA_RAW_BACKPRESSURE_TAG = 'rpa_raw_backpressure_bounded'
    RESOURCE_PROFILE_TAG = 'aggressive_resource_profile'
    RAW_GLOBAL_ACTIVE_CAP = int_env('UMIGE_RAW_GLOBAL_ACTIVE_CAP', 1536, 1, None)
    RAW_DECODE_CAP = int_env('UMIGE_RAW_DECODE_CAP', 160, 1, None)
    RAW_PAYLOAD_CAP = int_env('UMIGE_RAW_PAYLOAD_CAP', 160, 1, None)
    RAW_PE_API_CAP = int_env('UMIGE_RAW_PE_API_CAP', 192, 1, None)
    RAW_BINARY_CONTEXT_CAP = int_env('UMIGE_RAW_BINARY_CONTEXT_CAP', 160, 1, None)
    RAW_RENPY_CAP = int_env('UMIGE_RAW_RENPY_CAP', 192, 1, None)
    GLOBAL_RAW_QUEUE_IDLE_GRACE_SEC = float_env('UMIGE_GLOBAL_RAW_QUEUE_IDLE_GRACE_SEC', 8.0, 0.0, None)
    GLOBAL_RAW_CONTEXT_ANCHORS = ('powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'curl', 'wget', 'invoke-webrequest', 'downloadstring', 'urlopen', 'http://', 'https://', 'ftp://', 'virtualalloc', 'virtualprotect', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext', 'lsass', 'mimikatz', 'amsi', 'etw', 'frombase64string', 'encodedcommand', 'base64', 'subprocess', 'os.system', 'pickle.loads', 'marshal.loads', 'eval(', 'exec(', 'schtasks', 'currentversion\run')
    GLOBAL_RAW_DECODE_ANCHORS = ('frombase64string', 'encodedcommand', '-enc', 'base64', 'gzipstream', 'memorystream', 'iex', 'invoke-expression', 'certutil', 'decode', 'payload', 'shellcode')
    RAW_STAGE_EXEC_CACHE_MAX = int_env('UMIGE_RAW_STAGE_EXEC_CACHE_MAX', 2048, 1, None)
    scheduler_runtime_state().configure_raw_stage_cache(max_entries=RAW_STAGE_EXEC_CACHE_MAX)
    publish_init_values((
        ('STAGE_PARALLEL_DEFAULT_WORKERS', STAGE_PARALLEL_DEFAULT_WORKERS),
        ('INTRASTAGE_PARALLEL_VERSION', INTRASTAGE_PARALLEL_VERSION),
        ('INTRASTAGE_MIN_TEXT_CHARS', INTRASTAGE_MIN_TEXT_CHARS),
        ('INTRASTAGE_CHUNK_CHARS', INTRASTAGE_CHUNK_CHARS),
        ('INTRASTAGE_CHUNK_OVERLAP', INTRASTAGE_CHUNK_OVERLAP),
        ('INTRASTAGE_MAX_CHUNKS', INTRASTAGE_MAX_CHUNKS),
        ('GLOBAL_RAW_QUEUE_ENABLED', GLOBAL_RAW_QUEUE_ENABLED),
        ('GLOBAL_RAW_QUEUE_MIN_BYTES', GLOBAL_RAW_QUEUE_MIN_BYTES),
        ('GLOBAL_RAW_QUEUE_CHUNK_BYTES', GLOBAL_RAW_QUEUE_CHUNK_BYTES),
        ('GLOBAL_RAW_QUEUE_MAX_CHUNKS', GLOBAL_RAW_QUEUE_MAX_CHUNKS),
        ('RAW_LIVE_SOFT_CAP', RAW_LIVE_SOFT_CAP),
        ('RAW_LIVE_HARD_CAP', RAW_LIVE_HARD_CAP),
        ('RAW_PUBLISH_BATCH_MAX', RAW_PUBLISH_BATCH_MAX),
        ('RAW_PER_FILE_ACTIVE_CAP', RAW_PER_FILE_ACTIVE_CAP),
        ('RPA_USE_GLOBAL_RAW_QUEUE', RPA_USE_GLOBAL_RAW_QUEUE),
        ('RPA_ZIP_MAX_MEMBERS', RPA_ZIP_MAX_MEMBERS),
        ('RPA_ZIP_MAX_DEPTH', RPA_ZIP_MAX_DEPTH),
        ('RPA_ZIP_MAX_MEMBER_SIZE', RPA_ZIP_MAX_MEMBER_SIZE),
        ('RPA_RAW_BACKPRESSURE_TAG', RPA_RAW_BACKPRESSURE_TAG),
        ('RESOURCE_PROFILE_TAG', RESOURCE_PROFILE_TAG),
        ('RAW_GLOBAL_ACTIVE_CAP', RAW_GLOBAL_ACTIVE_CAP),
        ('RAW_DECODE_CAP', RAW_DECODE_CAP),
        ('RAW_PAYLOAD_CAP', RAW_PAYLOAD_CAP),
        ('RAW_PE_API_CAP', RAW_PE_API_CAP),
        ('RAW_BINARY_CONTEXT_CAP', RAW_BINARY_CONTEXT_CAP),
        ('RAW_RENPY_CAP', RAW_RENPY_CAP),
        ('GLOBAL_RAW_QUEUE_IDLE_GRACE_SEC', GLOBAL_RAW_QUEUE_IDLE_GRACE_SEC),
        ('GLOBAL_RAW_CONTEXT_ANCHORS', GLOBAL_RAW_CONTEXT_ANCHORS),
        ('GLOBAL_RAW_DECODE_ANCHORS', GLOBAL_RAW_DECODE_ANCHORS),
        ('RAW_STAGE_EXEC_CACHE_MAX', RAW_STAGE_EXEC_CACHE_MAX),
    ))
    return publish_init_values(())

__all__ = ("SchedulerConfigSnapshot", "SchedulerConfigSnapshotRequest", "build_scheduler_config_snapshot", "init_raw_scheduler_defaults", "process_queue_env_float", "process_queue_env_int")
