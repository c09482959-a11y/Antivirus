"""Canonical detection classification owner for primary behavior mapping."""

from __future__ import annotations

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.utils.tagging import canonical_raw_tag_name



_PRIMARY_BEHAVIOR_GROUPS = (
    ("process_injection", frozenset({"process_injection"})),
    ("memory_or_thread_primitive", frozenset({"memory_write", "memory_protect", "thread_execution", "remote_thread"})),
    ("exfiltration", frozenset({"network_exfiltration", "token_exfiltration"})),
    ("network", frozenset({"network_download", "network_activity", "http_upload"})),
    ("persistence", frozenset({"scheduled_task", "schtasks", "schtasks_create", "registry_run_key", "service_create", "persistence"})),
    ("credential_access", frozenset({"credential_access", "credential_api_access", "credential_dump_attempt", "dpapi_access", "browser_profile_access"})),
    ("execution", frozenset({"powershell_exec", "cmd_exec", "process_exec", "shell_execute", "execution"})),
    ("defense_evasion", frozenset({"defense_evasion", "amsi_bypass", "etw_bypass"})),
    ("collection", frozenset({"collection", "input_capture", "keylogging_behavior", "screen_capture", "screenshot_capture"})),
)


def _primary_behavior_bucket(normalized_tags: set[str]) -> str | None:
    for behavior, members in _PRIMARY_BEHAVIOR_GROUPS:
        if members & normalized_tags:
            return behavior
    return None


def primary_behavior_for_tag(tag: object) -> object:
    """Map a concrete or normalized tag to one stable behavior bucket."""
    try:
        low = canonical_raw_tag_name(tag)
        normalized = set(normalize_tags([low]))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        low = canonical_raw_tag_name(tag)
        normalized = {low}
    behavior = _primary_behavior_bucket(normalized)
    return behavior if behavior is not None else low
