"""Frozen detection constant defaults owned by detection constants registry."""

from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value


CONTEXTUAL_BASELINE_VERSION = 1
CONTEXTUAL_BASELINE_MIN_FILES = 25
CONTEXTUAL_BASELINE_COMMON_TAG_PROB = 0.7
CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB = 0.85
CONTEXTUAL_BASELINE_MAX_REDUCTION = 24.0
CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR = 8.0
CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR = 32.0
CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS = True

TRIAGE_LEARNING_BLOCK_TAGS = frozenset({
    "asset_deep_scan_escalated", "asset_extension_magic_mismatch",
    "extension_magic_type_mismatch", "asset_embedded_payload_signature",
    "asset_embedded_script_or_url", "embedded_command_or_url",
    "embedded_pe_signature", "embedded_archive_signature",
    "possible_appended_payload", "asset_high_entropy_tail",
    "filetype_misclassification", "filetype_misclassification_medium",
    "filetype_misclassification_high",
})

CONTEXTUAL_DANGEROUS_ANCHOR_TAGS = frozenset({'powershell_exec', 'encoded_powershell', 'cmd_exec', 'process_exec', 'script_execution', 'bash_exec', 'python_exec', 'wmi_exec', 'wmic_exec', 'win32_process_create', 'schtasks_create', 'scheduled_task', 'remote_scheduled_task', 'run_key_mod', 'registry_run_key', 'startup_persistence', 'service_create', 'remote_payload_download', 'network_download', 'http_upload', 'lolbin_download', 'network_exfiltration', 'dns_tunneling', 'token_exfiltration', 'remote_command_channel', 'network_c2', 'credential_dump_attempt', 'lsass_access', 'memory_dump', 'token_secret_access', 'credential_api_access', 'dpapi_access', 'process_injection', 'process_hollowing', 'remote_thread_create', 'write_process_memory', 'memory_write', 'thread_execution', 'shellcode_exec', 'defender_disable', 'shadowcopy_delete', 'amsi_bypass_attempt', 'etw_bypass_attempt'})

CONTEXTUAL_WEAK_NOISE_BUCKETS = frozenset({
    "entropy_or_packing", "asset_or_container", "file_metadata",
    "renpy_script_logic", "unity_managed_code", "rpgm_node_runtime",
    "other_behavior",
})

BEHAVIOR_MODEL_VERSION = "engine_extension_bucket_vector_v4"
VECTOR_FEATURE_NAMES = (
    "tag_count", "scoreable_count", "support_only_count", "chain_count",
    "os_exec_count", "network_count", "credential_count",
    "persistence_count", "injection_count", "evasion_count", "entropy_count",
    "renpy_script_count", "unity_managed_count", "rpgm_node_count",
    "weak_evidence_count", "strong_evidence_count", "rare_high_risk_count",
    "global_passive_asset", "global_container_asset", "global_script_asset",
    "global_mixed_asset", "nonexec_execution_violation", "engine_filetype_risk",
    "risk_scaled",
)

NON_EXECUTION_CAPABILITIES = frozenset({"none", "data", "limited"})
CONTAINER_EXECUTION_CAPABILITIES = frozenset({"container"})
QUALITY_GATE_VERSION = "explainability_quality_gates_v1"
ENGINE_BASELINE_CONFIDENCE_THRESHOLD = 0.8
BASELINE_MATURITY_COLD_FILES = 25
BASELINE_MATURITY_WARM_FILES = 100
TAG_REPORTING_CANONICAL_NAMES = freeze_registry_value({'memory_protection': 'memory_protect', 'high_entropy_section': 'high_entropy_sections', 'wmic_exec': 'wmi_exec', 'scheduled_task': 'schtasks_create', 'run_key_mod': 'registry_run_key', 'create_remote_thread': 'remote_thread_create'})
CONFIRMED_API_HINTS = frozenset({
    "createprocess", "shellexecute", "winexec", "win32_process.create",
    "writeprocessmemory", "createremotethread", "virtualallocex",
    "virtualprotect", "readprocessmemory", "openprocess", "schtasks",
    "regsetvalue", "createservice", "urldownloadtofile", "internetreadfile",
    "urlmon", "bitsadmin", "certutil",
})


__all__ = (
    'BASELINE_MATURITY_COLD_FILES',
    'BASELINE_MATURITY_WARM_FILES',
    'BEHAVIOR_MODEL_VERSION',
    'CONFIRMED_API_HINTS',
    'CONTAINER_EXECUTION_CAPABILITIES',
    'CONTEXTUAL_BASELINE_COMMON_TAG_PROB',
    'CONTEXTUAL_BASELINE_MAX_REDUCTION',
    'CONTEXTUAL_BASELINE_MIN_FILES',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR',
    'CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS',
    'CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB',
    'CONTEXTUAL_BASELINE_VERSION',
    'CONTEXTUAL_DANGEROUS_ANCHOR_TAGS',
    'CONTEXTUAL_WEAK_NOISE_BUCKETS',
    'ENGINE_BASELINE_CONFIDENCE_THRESHOLD',
    'NON_EXECUTION_CAPABILITIES',
    'QUALITY_GATE_VERSION',
    'TAG_REPORTING_CANONICAL_NAMES',
    'TRIAGE_LEARNING_BLOCK_TAGS',
    'VECTOR_FEATURE_NAMES',
)
