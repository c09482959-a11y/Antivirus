"""Canonical detection classification owner for clustering tag context."""

from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.tags.heuristics.tag_phase import norm_lower_set
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.utils.tagging import TAG_NORMALIZATION_FAILURE_EVIDENCE


PLR2004N55_0 = 55.0


def cluster_kind_for_tags(tags: object, risk: object=None) -> object:
    """Separate benign/malicious/mixed clusters using conservative anchors."""
    normalized_tags = normalize_tags(()) if tags is None else normalize_tags(tags)
    tagset = {tag.lower() for tag in normalized_tags}
    malicious_markers = {
        "malicious", "high_confidence", "pickle_opcode_graph_analyzed",
        "pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode",
        "pickle_external_executable_reference", "process_injection",
        "confirmed_injection_chain", "credential_access", "credential_dump_attempt",
        "credential_stealer_behavior", "ransomware_behavior", "remote_payload_download",
        "network_exfiltration", "amsi_bypass_attempt", "etw_bypass_attempt",
        "fileless_execution", "shellcode_loader", "memory_dump", "lsass_access",
    }
    suspicious_markers = {
        "script_execution", "process_exec", "encoded_payload", "payload_decode_candidate",
        "network_download", "archive_dropper", "embedded_archive_payload",
        "scheduled_task", "startup_persistence", "packed_or_obfuscated", "anti_vm",
        "anti_sandbox",
    }
    if tagset & malicious_markers:
        return "malicious"
    try:
        if risk is not None and float(risk) >= PLR2004N55_0:
            return "malicious"
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return "mixed"
    if tagset & suspicious_markers:
        return "mixed"
    return "benign"


def cluster_relevant_tags(tags: object) -> object:
    """Remove volatile path/filetype bookkeeping tags before cluster comparison."""
    drop_prefixes = (
        "ext_", "filetype_", "magic_", "observed_stage_", "router_stage_",
        "actual_stage_", "claimed_stage_", "stage_hit:", "cluster_decoded_",
        "cluster_timeline_",
    )
    drop_exact = {
        "file_seen", "extension_consistent", "extension_mismatch", "extension_untrusted",
        "binary_failover_scan", "scan_failsafe_applied", "text_file", "text_config_file",
        "script_file", "executable_file", "native_pe", "pe_file", "pe_exe", "pe_dll",
        "dll_file",
    }
    out = set()
    normalized_tags = normalize_tags(()) if tags is None else normalize_tags(tags)
    for tag_value in (tag.strip().lower() for tag in normalized_tags):
        if not tag_value or tag_value in drop_exact:
            continue
        if any(tag_value.startswith(prefix) for prefix in drop_prefixes):
            continue
        out.add(tag_value)
    return out


def high_gate_norm(tags: object) -> object:
    """Normalize high-gate tags without mutating caller-owned tag state."""
    try:
        return norm_lower_set(normalize_tags(()) if tags is None else normalize_tags(tags))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return {TAG_NORMALIZATION_FAILURE_EVIDENCE}
