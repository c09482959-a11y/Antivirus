"""Detection-owned runtime/library tag gating policy."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.library_baseline import (
    RUNTIME_STRONG_ATTACK_CONTEXT,
    is_known_python_runtime_library_path,
    is_python_runtime_binary_path,
    is_renpy_engine_runtime_source_path,
    is_runtime_or_engine_library_path,
)
from Virus_Scan.utils.tagging import ordered_unique_tags as ordered_unique_detection_tags
from Virus_Scan.utils.text_match import has_any_text
from Virus_Scan.utils.text_validation import tag_validation_text

RUNTIME_CAPABILITY_NOISE_TAGS = frozenset({
    "archive_dropper", "dropper_behavior", "embedded_archive_payload", "base64", "payload_decode_candidate",
    "embedded_base64_payload", "encoded_payload_candidate", "dll_hijack", "dll_sideload", "dll_load",
    "dll_load_capability", "assembly_load", "reflection", "il_reflection", "network_download", "network_activity", "http_upload", "backdoor_or_c2", "network_c2",
    "remote_command_channel", "c2_or_remote_command", "c2_beacon", "exfiltration", "network_exfiltration",
    "collection", "input_capture", "keylogging_behavior", "clipboard_access",
    "macro_office", "office_macro_execution", "script_execution", "memory_allocate", "memory_allocation",
    "memory_access", "memory_read", "memory_write", "memory_protect", "memory_protection", "thread_execution",
    "process_injection", "in_memory_execution", "shellcode_exec", "anti_debug",
    "anti_vm", "anti_sandbox", "defense_evasion", "remote_execution", "lateral_movement",
    "overlay_payload_after_eof", "obfuscated_script", "crypto_wallet_pattern", "crypto_address_display",
    "il_invoke", "IL_INVOKE", "obfuscation_pack", "packed_or_obfuscated", "packer_marker",
})
RUNTIME_HARD_PROOF_TAGS = frozenset({
    "yara_malware", "known_bad_hash", "malware_family", "confirmed_embedded_pe_payload", "decoded_pe_payload",
    "embedded_pe_payload", "mimikatz_credential_dump", "lsass_access", "credential_dump_attempt",
    "amsi_scanbuffer_patch", "etw_eventwrite_patch", "write_process_memory", "create_remote_thread",
    "remote_thread_create", "process_injection", "encoded_powershell", "powershell_exec",
    "network_c2", "remote_command_channel", "backdoor_or_c2", "network_exfiltration", "token_exfiltration", "http_upload",
})
RENPY_RUNTIME_REPLACEMENTS = MappingProxyType({
    "input_capture": "input_event_handling",
    "keylogging_behavior": "input_event_handling",
    "user_activity_monitoring": "input_event_handling",
    "screenshot_capture": "screen_capture_capability",
    "screen_capture": "screen_capture_capability",
    "collection": "collection_capability",
    "network_activity": "network_capability",
    "persistent_save_data": "runtime_state_capability",
    "renpy_save_location": "runtime_state_capability",
})
LIBRARY_BASELINE_REPLACEMENTS = MappingProxyType({
    "input_capture": "input_event_handling",
    "keylogging_behavior": "input_event_handling",
    "network_activity": "network_capability",
    "persistent_save_data": "runtime_state_capability",
    "save_archive_access": "runtime_state_capability",
})


def _has_hard_proof(tags: object, strings_blob: object="") -> bool:
    tagset = {str(tag).lower() for tag in tags or ()}
    return bool(tagset & RUNTIME_HARD_PROOF_TAGS) or has_any_text(tag_validation_text(strings_blob), RUNTIME_STRONG_ATTACK_CONTEXT)


def suppress_runtime_binary_capability_noise(tags: object, path: object=None, strings_blob: object="") -> object:
    if not (is_runtime_or_engine_library_path(path) or is_known_python_runtime_library_path(path, strings_blob)):
        return ordered_unique_detection_tags(tags)
    if _has_hard_proof(tags, strings_blob):
        return ordered_unique_detection_tags(tags)
    cleaned = []
    removed = False
    for tag in tags or ():
        if str(tag).lower() in RUNTIME_CAPABILITY_NOISE_TAGS:
            removed = True
            continue
        cleaned.append(tag)
    if is_known_python_runtime_library_path(path, strings_blob):
        cleaned.extend(["python_runtime_library", "renpy_runtime_library"])
    elif is_python_runtime_binary_path(path):
        cleaned.append("python_runtime_binary")
    else:
        cleaned.append("engine_runtime_library")
    if removed:
        cleaned.append("runtime_capability_noise_suppressed")
    return ordered_unique_detection_tags(cleaned)


def enforce_runtime_library_post_derive_gate(tags: object, path: object=None, strings_blob: object="") -> object:
    if not (is_runtime_or_engine_library_path(path) or is_known_python_runtime_library_path(path, strings_blob)):
        return ordered_unique_detection_tags(tags)
    if _has_hard_proof(tags, strings_blob):
        return ordered_unique_detection_tags(tags)
    block = set(RUNTIME_CAPABILITY_NOISE_TAGS) | {"credential_access"}
    cleaned = [tag for tag in tags or () if str(tag).lower() not in block]
    if is_known_python_runtime_library_path(path, strings_blob):
        cleaned.extend(["python_runtime_library", "renpy_runtime_library"])
    elif is_python_runtime_binary_path(path):
        cleaned.append("python_runtime_binary")
    else:
        cleaned.append("engine_runtime_library")
    cleaned.append("runtime_post_derive_gate")
    return ordered_unique_detection_tags(cleaned)


def apply_engine_runtime_capability_tags(tags: object, path: object=None, strings_blob: object="") -> object:
    if not is_renpy_engine_runtime_source_path(path, strings_blob):
        return ordered_unique_detection_tags(tags)
    if _has_hard_proof(tags, strings_blob):
        return ordered_unique_detection_tags(tags)
    out = []
    changed = False
    for tag in tags or ():
        replacement = RENPY_RUNTIME_REPLACEMENTS.get(str(tag).lower())
        if replacement:
            out.append(replacement)
            changed = True
        else:
            out.append(tag)
    out.extend(["renpy_runtime_library", "renpy_display_runtime", "engine_capability_context"])
    if changed:
        out.append("renpy_runtime_capability_downgraded")
    return ordered_unique_detection_tags(out)


def apply_detection_library_behavior_baseline(tags: object, path: object=None, strings_blob: object="") -> object:
    if not (is_runtime_or_engine_library_path(path) or is_known_python_runtime_library_path(path, strings_blob)):
        return ordered_unique_detection_tags(tags)
    if _has_hard_proof(tags, strings_blob):
        return ordered_unique_detection_tags([*list(tags or ()), 'library_behavior_baseline_hard_proof_bypass'])
    cleaned = []
    extras = ["library_behavior_baseline:runtime_engine_binary"]
    suppressed = False
    for tag in tags or ():
        replacement = LIBRARY_BASELINE_REPLACEMENTS.get(str(tag).lower())
        if replacement:
            extras.append(replacement)
            suppressed = True
            continue
        cleaned.append(tag)
    if suppressed:
        extras.append("library_baseline_normal_behavior_suppressed")
    return ordered_unique_detection_tags(cleaned + extras)


__all__ = (
    "apply_detection_library_behavior_baseline",
    "apply_engine_runtime_capability_tags",
    "enforce_runtime_library_post_derive_gate",
    "is_known_python_runtime_library_path",
    "is_python_runtime_binary_path",
    "is_renpy_engine_runtime_source_path",
    "is_runtime_or_engine_library_path",
    "suppress_runtime_binary_capability_noise",
)
