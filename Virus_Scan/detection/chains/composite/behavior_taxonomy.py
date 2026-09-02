"""Immutable atomic-observation taxonomy for engine negative reasoning.

This module does not define chains, aliases, scores, floors, or match policy.
Canonical chain identity is owned exclusively by the validated chain registry.
"""

DOWNLOAD_OBSERVATION_TAGS = frozenset({
    "network_download", "remote_payload_download", "lolbin_download",
    "download_file", "http_download", "url_download",
})
EXECUTION_OBSERVATION_TAGS = frozenset({
    "process_exec", "script_execution", "powershell_exec", "cmd_exec",
    "wscript_exec", "mshta_exec", "regsvr32_exec", "rundll32_exec",
    "bitsadmin_exec", "certutil_exec", "fileless_execution",
    "in_memory_execution", "pickle_reduce_opcode",
    "pickle_callable_reference", "pickle_dangerous_global",
})
COMMAND_OBSERVATION_TAGS = frozenset({
    "network_c2", "backdoor_or_c2", "remote_command_channel", "c2_beacon",
    "stratum_protocol", "mining_pool_connection",
})
EXFILTRATION_OBSERVATION_TAGS = frozenset({
    "network_exfiltration", "http_upload", "token_exfiltration",
    "dns_tunneling", "cloud_upload", "ftp_transfer",
})
CREDENTIAL_OBSERVATION_TAGS = frozenset({
    "credential_dump_attempt", "credential_access", "lsass_access",
    "mimikatz_credential_dump", "token_secret_access", "dpapi_access",
    "browser_credential_access", "high_confidence_credential_theft",
    "high_confidence_browser_credential_theft",
})
PERSISTENCE_OBSERVATION_TAGS = frozenset({
    "scheduled_task", "schtasks_create", "registry_persistence",
    "startup_persistence", "service_create", "service_persistence",
    "run_key_mod", "registry_run_key", "remote_scheduled_task",
    "remote_service_creation", "persistence",
})
INJECTION_OBSERVATION_TAGS = frozenset({
    "process_injection", "memory_write", "write_process_memory",
    "thread_execution", "remote_thread_create", "create_remote_thread",
    "memory_protect", "memory_allocate", "shellcode_exec",
})
BLOCKCHAIN_ABUSE_TAGS = frozenset({
    "stratum_protocol", "mining_pool_connection", "cryptomining_behavior",
    "crypto_wallet_clipboard_replace", "blockchain_c2_polling",
})
BLOCKCHAIN_REPORT_ONLY_TAGS = frozenset({
    "blockchain_api_access", "wallet_address_observed", "crypto_wallet_pattern",
})
GAME_ENGINE_WEAK_TEXT_ENCODED_TAGS = frozenset({
    "encoded_data_context", "payload_decode_candidate",
    "decoded_payload_observed", "decoded_base64_blob", "high_entropy_packed",
})

__all__ = (
    "BLOCKCHAIN_ABUSE_TAGS",
    "BLOCKCHAIN_REPORT_ONLY_TAGS",
    "COMMAND_OBSERVATION_TAGS",
    "CREDENTIAL_OBSERVATION_TAGS",
    "DOWNLOAD_OBSERVATION_TAGS",
    "EXECUTION_OBSERVATION_TAGS",
    "EXFILTRATION_OBSERVATION_TAGS",
    "GAME_ENGINE_WEAK_TEXT_ENCODED_TAGS",
    "INJECTION_OBSERVATION_TAGS",
    "PERSISTENCE_OBSERVATION_TAGS",
)
