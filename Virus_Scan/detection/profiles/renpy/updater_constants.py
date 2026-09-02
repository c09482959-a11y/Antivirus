"""Frozen Ren'Py updater baseline and hard-anchor constants."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.detection.registries.context import detection_registry_value

RENPY_UPDATER_FILENAMES = frozenset({"00updater.rpy", "00updater.rpyc"})
RENPY_UPDATER_SUPPRESS_TAGS = frozenset(detection_registry_value("_RENPY_UPDATER_SUPPRESS_TAGS", {
    "archive_dropper", "dropper_behavior", "network_download_execute",
    "embedded_archive_payload", "obfuscation_pack",
    "packed_or_obfuscated", "packer_marker", "stage_hit:archive dropper",
    "stage_hit:explicit packer marker", "staged_detection", "remote_payload_download",
}))
RENPY_UPDATER_REPLACEMENTS = MappingProxyType(dict(detection_registry_value("_RENPY_UPDATER_REPLACEMENTS", {
    "network_download": "renpy_update_download_capability",
    "network_activity": "renpy_update_download_capability",
    "process_exec": "renpy_zsync_process_capability",
    "python_process_exec": "renpy_zsync_process_capability",
    "bytecode_subprocess": "renpy_zsync_process_capability",
    "save_archive_access": "renpy_update_archive_apply_capability",
    "persistent_save_data": "persistent_update_state",
    "dynamic_execution": "renpy_updater_runtime_execution_capability",
})))
RENPY_UPDATER_HARD_ANCHOR_TAGS = frozenset(detection_registry_value("_RENPY_UPDATER_HARD_ANCHOR_TAGS", {
    "yara_malware", "known_bad_hash", "malware_family", "powershell_encoded",
    "encoded_powershell", "cmd_shell_exec", "cmd_exec", "powershell_exec",
    "credential_access", "credential_dump_attempt", "token_theft", "token_secret_access",
    "discord_webhook", "telegram_bot_api", "pastebin_raw_download", "suspicious_ip_url",
    "autorun_persistence", "registry_run_key", "scheduled_task_create", "schtasks_create",
    "process_injection", "embedded_pe_payload", "decoded_pe_payload",
    "confirmed_embedded_pe_payload", "payload_decode_confirmed", "c2_beacon", "network_c2",
    "backdoor_or_c2", "remote_command_channel", "network_exfiltration", "http_upload",
    "token_exfiltration", "renpy_updater_external_process_abuse",
    "renpy_updater_download_exec_abuse", "renpy_updater_persistence_abuse",
    "renpy_updater_suspicious_endpoint", "renpy_updater_payload_staging_abuse",
}))
RENPY_UPDATER_HARD_ANCHOR_TEXT = tuple(detection_registry_value("_RENPY_UPDATER_HARD_ANCHOR_TEXT", (
    "powershell -enc", "-encodedcommand", "invoke-expression", "cmd.exe /c",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "discord.com/api/webhooks",
    "api.telegram.org", "currentversion\\run", "schtasks /create", "writeprocessmemory",
    "createremotethread",
)))
RENPY_FAILSAFE_ONLY_MAX_SCORE = float(detection_registry_value("RENPY_FAILSAFE_ONLY_MAX_SCORE", 12.0))
RENPY_CONTEXT_TAGS = frozenset(detection_registry_value("RENPY_CONTEXT_TAGS", ("renpy", "renpy_bytecode", "renpy_script")))
RENPY_FAILSAFE_ONLY_TAGS = frozenset(detection_registry_value("RENPY_FAILSAFE_ONLY_TAGS", (
    "binary_failover_scan", "scan_failsafe_applied", "magic_binary_blob",
    "magic_type_unknown_binary_blob", "unknown_binary_blob", "high_entropy_section",
    "high_entropy_sections", "possible_packed_or_encrypted_blob", "possible_xor_encoded_blob",
    "encoded_payload_candidate", "packed_or_obfuscated", "low_string_visibility",
)))
PICKLE_GRAPH_PROOF_TAGS = frozenset(detection_registry_value("PICKLE_GRAPH_PROOF_TAGS", (
    "pickle_opcode_graph_analyzed", "pickle_dangerous_global", "pickle_callable_reference",
    "pickle_reduce_opcode",
)))
RPYC_HIGH_RISK_TAGS = frozenset(detection_registry_value("RPYC_HIGH_RISK_TAGS", (
    "pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode",
    "pickle_deserialization_context",
)))
BROAD_UNVALIDATED_TAGS = frozenset(detection_registry_value("BROAD_UNVALIDATED_TAGS", (
    "network_activity", "url_present", "reference_url", "encoded_data_context",
    "payload_decode_candidate", "packed_or_obfuscated", "high_entropy_packed",
)))

__all__ = (
    "BROAD_UNVALIDATED_TAGS",
    "PICKLE_GRAPH_PROOF_TAGS",
    "RENPY_CONTEXT_TAGS",
    "RENPY_FAILSAFE_ONLY_MAX_SCORE",
    "RENPY_FAILSAFE_ONLY_TAGS",
    "RENPY_UPDATER_FILENAMES",
    "RENPY_UPDATER_HARD_ANCHOR_TAGS",
    "RENPY_UPDATER_HARD_ANCHOR_TEXT",
    "RENPY_UPDATER_REPLACEMENTS",
    "RENPY_UPDATER_SUPPRESS_TAGS",
    "RPYC_HIGH_RISK_TAGS",
)
