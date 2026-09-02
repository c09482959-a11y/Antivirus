"""Public runtime contracts for orchestration and startup boundaries.

Runtime owns mutable process/runtime state, path/config snapshots, lifecycle
state, and dependency provider registration.  Orchestration and bootstrap code
enter those runtime-owned capabilities through this bounded public API instead
of importing runtime implementation modules directly.
"""
from __future__ import annotations

from Virus_Scan.runtime.cluster_state import ClusterStateNotConfigured, RuntimeClusterState, cluster_state, configure_runtime_cluster_state
from Virus_Scan.contracts.telemetry import log_error, record_detector_error
from Virus_Scan.contracts.unity_behavior import detect_unity_runtime_behavior
from Virus_Scan.runtime.config import ArchiveScanLimits, RuntimeConfig, StageConcurrencyLimits
from Virus_Scan.runtime.config_state import configure_deep_scan_mode, configure_profile_corruption_policy, get_deep_scan_mode, get_profiles_dir
from Virus_Scan.runtime.context import RuntimeContext
from Virus_Scan.runtime.constants import DECODE_LAYER_MAX_DEPTH, FAST_FINGERPRINT_SAMPLE, STAGE_PARALLEL_DEFAULT_WORKERS
from Virus_Scan.runtime.environment import RuntimeEnvironmentOwner, runtime_worker_shared_persistence_writes_disabled
from Virus_Scan.runtime.analytical_calibration import ANALYTICAL_EVIDENCE_SCHEMA_VERSION, build_analytical_calibration_bundle
from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.runtime.determinism import VOLATILE_RESULT_KEYS, canonicalize_result_mapping, deterministic_mode_enabled
from Virus_Scan.runtime.detection_state import (
    RuntimeDetectionState,
    configure_runtime_detection_state,
    detection_state,
)
from Virus_Scan.runtime.fault_domains import EXTRACTION_FAILURE, PERSISTENCE_FAILURE, REPORTING_FAILURE, append_failure_domain, contain_fault, failure_tag
from Virus_Scan.runtime.filesystem_alias_integrity import (
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
    windows_file_attributes_indicate_alias,
)
from Virus_Scan.runtime.graph_state import graph_vector_node_key
from Virus_Scan.runtime.immutable_core import (
    RuntimeStateReducer,
    RuntimeTransition,
    freeze_runtime_value,
    materialize_runtime_value,
)
from Virus_Scan.runtime.init_state import get_init_value, init_state_snapshot, publish_init_value, publish_init_values
from Virus_Scan.runtime.cache_state import runtime_cache_by_name
from Virus_Scan.runtime.runtime_economics_ledger import get_runtime_economics_ledger, observe_runtime_economics
from Virus_Scan.runtime.runtime_flags import runtime_flag_mark
from Virus_Scan.runtime.structured_failures import record_scheduler_suppressed, record_suppressed_failure
from Virus_Scan.runtime.lifecycle_state import get_lifecycle_state
from Virus_Scan.runtime.model_state import configure_runtime_model_state, load_runtime_model_baselines
from Virus_Scan.runtime.mitre_state import (
    MitreRuntimeSnapshot, configure_mitre_runtime, mitre_runtime_snapshot,
    release_mitre_runtime,
)
from Virus_Scan.runtime.profile_persistence_state import ProfilePersistenceState, profile_persistence_state
from Virus_Scan.runtime.profile_scoring_state import profile_scoring_state
from Virus_Scan.runtime.path_runtime_state import path_runtime_owner
from Virus_Scan.runtime.platform_filesystem_durability import (
    FilesystemDurabilityError,
    durable_activate_directory,
    durable_replace_regular_file,
    flush_directory,
    flush_existing_regular_file,
    flush_open_writable_file,
)
from Virus_Scan.runtime.provenance import append_provenance_event, stable_digest
from Virus_Scan.runtime.progress import clear_progress_callback, report_progress, set_progress_callback
from Virus_Scan.runtime.resource_economics import adaptive_reprice_cost, apply_repricing_inertia, archive_ecosystem_score, confidence_inertia, queue_cost
from Virus_Scan.runtime.resource_lock import ResourceFileLock, ResourceLockSet
from Virus_Scan.runtime.resource_quotas import ExtractionQuotaTracker, ResourceQuotaExceeded, extract_zip_member_with_quota, quota_tag
from Virus_Scan.runtime.resource_paths import (
    ScanLogOutputPlan,
    build_scan_log_output_plan,
    derive_scan_log_scan_id,
    mitre_dir,
    program_root,
    resource_root_snapshot,
    scan_logs_dir,
    temp_dir,
    work_queue_dir,
    yara_dir,
)
from Virus_Scan.runtime.scan_dependencies import (
    deep_scan_auto_enabled,
    deep_scan_fast_assets_enabled,
    deep_scan_thorough_enabled,
    ensure_graph_node,
    has_any_tag,
    intrastage_enabled,
    read_file_bytes,
    register_engine_context_detector,
    register_intrastage_provider,
    register_raw_string_stage_provider,
    register_scan_strings_provider,
    register_string_event_provider,
    report_scan_stage_progress,
    run_raw_task_queue,
    safe_read_text,
    scan_strings,
    stage_parallel_workers,
)
from Virus_Scan.runtime.scanner_governance import is_programmer_error, scanner_failure_tags
from Virus_Scan.runtime.scan_integrity_state import (
    RuntimeScanIntegrityState,
    configure_runtime_scan_integrity_state,
    scan_integrity_state,
)
from Virus_Scan.runtime.scan_run_guard import acquire_parent_scan_guard, release_parent_scan_guard
from Virus_Scan.runtime.scheduler_runtime_state import scheduler_runtime_state
from Virus_Scan.runtime.yara_rules_state import (
    YaraRuntimeSnapshot, release_yara_runtime, yara_rules_state, yara_runtime_snapshot,
)
from Virus_Scan.runtime.scheduler_state import publish_workload_queue_plan

__all__ = (
    "materialize_runtime_value",
    "freeze_runtime_value",
    "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
    "DECODE_LAYER_MAX_DEPTH",
    "EXTRACTION_FAILURE",
    "FAST_FINGERPRINT_SAMPLE",
    "PERSISTENCE_FAILURE",
    "REPORTING_FAILURE",
    "STAGE_PARALLEL_DEFAULT_WORKERS",
    "VOLATILE_RESULT_KEYS",
    "YaraRuntimeSnapshot",
    "ArchiveScanLimits",
    "ClusterStateNotConfigured",
    "ExtractionQuotaTracker",
    "FilesystemDurabilityError",
    "MitreRuntimeSnapshot",
    "ProfilePersistenceState",
    "ResourceFileLock",
    "ResourceLockSet",
    "ResourceQuotaExceeded",
    "RuntimeClusterState",
    "RuntimeConfig",
    "RuntimeContext",
    "RuntimeDetectionState",
    "RuntimeEnvironmentOwner",
    "RuntimeScanIntegrityState",
    "RuntimeStateReducer",
    "RuntimeTransition",
    "ScanLogOutputPlan",
    "StageConcurrencyLimits",
    "acquire_parent_scan_guard",
    "adaptive_reprice_cost",
    "append_failure_domain",
    "append_provenance_event",
    "apply_repricing_inertia",
    "archive_ecosystem_score",
    "build_analytical_calibration_bundle",
    "build_scan_log_output_plan",
    "canonicalize_result_mapping",
    "clear_progress_callback",
    "cluster_state",
    "confidence_inertia",
    "configure_deep_scan_mode",
    "configure_mitre_runtime",
    "configure_profile_corruption_policy",
    "configure_runtime_cluster_state",
    "configure_runtime_detection_state",
    "configure_runtime_model_state",
    "configure_runtime_scan_integrity_state",
    "contain_fault",
    "deep_scan_auto_enabled",
    "deep_scan_fast_assets_enabled",
    "deep_scan_thorough_enabled",
    "detect_unity_runtime_behavior",
    "derive_scan_log_scan_id",
    "detection_state",
    "deterministic_mode_enabled",
    "durable_activate_directory",
    "durable_replace_regular_file",
    "ensure_graph_node",
    "extract_zip_member_with_quota",
    "failure_tag",
    "flush_directory",
    "flush_existing_regular_file",
    "flush_open_writable_file",
    "get_deep_scan_mode",
    "get_init_value",
    "get_lifecycle_state",
    "get_profiles_dir",
    "get_runtime_economics_ledger",
    "graph_vector_node_key",
    "has_any_tag",
    "init_state_snapshot",
    "intrastage_enabled",
    "is_programmer_error",
    "load_runtime_model_baselines",
    "mitre_dir",
    "mitre_runtime_snapshot",
    "log_error",
    "observe_runtime_economics",
    "path_runtime_owner",
    "path_contains_filesystem_alias",
    "profile_persistence_state",
    "profile_scoring_state",
    "program_root",
    "resource_root_snapshot",
    "publish_init_value",
    "publish_init_values",
    "publish_workload_queue_plan",
    "queue_cost",
    "quota_tag",
    "read_file_bytes",
    "record_detector_error",
    "record_scheduler_suppressed",
    "record_suppressed_failure",
    "register_engine_context_detector",
    "register_intrastage_provider",
    "register_raw_string_stage_provider",
    "register_scan_strings_provider",
    "register_string_event_provider",
    "release_parent_scan_guard",
    "release_mitre_runtime",
    "release_yara_runtime",
    "report_progress",
    "report_scan_stage_progress",
    "run_raw_task_queue",
    "runtime_cache_by_name",
    "runtime_flag_mark",
    "runtime_value",
    "runtime_worker_shared_persistence_writes_disabled",
    "safe_read_text",
    "scan_integrity_state",
    "scan_logs_dir",
    "scan_strings",
    "scanner_failure_tags",
    "scheduler_runtime_state",
    "set_progress_callback",
    "stable_digest",
    "stat_result_is_filesystem_alias",
    "stage_parallel_workers",
    "temp_dir",
    "work_queue_dir",
    "windows_file_attributes_indicate_alias",
    "yara_dir",
    "yara_runtime_snapshot",
    "yara_rules_state",
)
