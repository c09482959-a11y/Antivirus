"""Canonical contextual string tag scan orchestration."""

from Virus_Scan.detection.profiles.renpy.updater_identity import is_renpy_official_updater_path
from Virus_Scan.detection.enrichment.strings.contextual import js_execution_model
from Virus_Scan.detection.enrichment.strings.contextual.command_rules import (
    collect_command_execution_tags,
    command_context_flags,
)
from Virus_Scan.detection.enrichment.strings.contextual.heuristic_models import collect_central_heuristic_tags
from Virus_Scan.detection.enrichment.strings.contextual.lateral_collection import collect_lateral_collection_and_dotnet_tags
from Virus_Scan.detection.enrichment.strings.contextual.memory_evasion import collect_memory_and_evasion_tags
from Virus_Scan.detection.enrichment.strings.contextual.persistence_credentials import collect_persistence_and_credential_tags
from Virus_Scan.detection.evidence.relationships.evidence_links import umige_evidence_link_tags
from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.detection.profiles.family_scan import explicit_missed_family_tag_scan
from Virus_Scan.detection.profiles.profile_policy import profile_updater_behavior_abuse_tags
from Virus_Scan.detection.tags.heuristics.blockchain_behavior import detect_blockchain_abuse_tags
from Virus_Scan.detection.tags.obfuscation.anchors import obfuscated_anchor_tags
from Virus_Scan.detection.contracts.string_predicates import context_any, context_regex
from Virus_Scan.detection.contracts.string_predicates import is_renpy_tts_wscript_context, build_extraction_view
from Virus_Scan.detection.enrichment.strings.boundaries import enrichment_text_or_empty


from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ContextualTagScanRequest:
    """Immutable input for one contextual string-tag scan."""

    strings_blob: object
    path: object = None
    source: object = "strings"
    data: object = None
    finalize: object = True
    decoded_payloads: object = None


def contextual_tag_scan(request: ContextualTagScanRequest) -> object:
    """Context-gated tag extraction from one immutable request contract."""
    if type(request) is not ContextualTagScanRequest:
        raise TypeError("contextual_tag_scan_request_required")
    original_text = enrichment_text_or_empty(request.strings_blob)
    if original_text == "":
        return []
    text = build_extraction_view(
        original_text,
        path=request.path,
        decoded_payloads=request.decoded_payloads,
    )
    blob = text.lower()
    tags = []

    def add(*xs: object) -> object:
        tags.extend(xs)

    add(*obfuscated_anchor_tags(blob, path=request.path))
    if is_renpy_official_updater_path(request.path, text):
        add(*profile_updater_behavior_abuse_tags(path=request.path, strings_blob=text))
    if is_renpy_tts_wscript_context(blob):
        add("renpy_tts_wscript", "assistive_tts_script_launch")
    elif context_regex(r"\b(?:wscript|cscript)(?:\.exe)?\b", blob) and context_regex(
        r"\.(?:vbs|vbe|js|jse|wsf)\b|//e:", blob
    ):
        add("wscript_exec", "script_execution")

    flags = command_context_flags(blob)
    add(*collect_command_execution_tags(blob, existing_tags=tags))
    add(*collect_persistence_and_credential_tags(blob))
    add(*collect_memory_and_evasion_tags(blob))
    add(
        *collect_lateral_collection_and_dotnet_tags(
            blob, has_powershell=flags["has_powershell"]
        )
    )
    add(*collect_central_heuristic_tags(text, path=request.path, source=request.source))
    add(*_collect_contextual_atomic_evidence_tags(blob))
    add(*detect_blockchain_abuse_tags(blob))
    add(*explicit_missed_family_tag_scan(blob, path=request.path, data=request.data))

    source_text = enrichment_text_or_empty(request.source)
    if source_text not in {
        "js_decoded_payload",
        "payload_decode_candidate",
        "pickle_decoded_payload",
    }:
        add(
            *js_execution_model.umige_js_execution_model_tags(
                text, path=request.path, finalize=request.finalize
            )
        )
        add(*umige_evidence_link_tags(text, path=request.path))

    if request.finalize:
        generation = finalize_tag_evidence_generation(
            tags,
            path=request.path,
            strings_blob=text,
            source=request.source,
        )
        return list(generation.evidence.tags)
    return list(tags)



def _collect_contextual_atomic_evidence_tags(blob: object) -> object:
    """Return bounded atomic observations from neighboring evidence domains."""
    tags = []
    if (context_regex('\\bos\\.system\\s*\\(', blob) or context_regex('\\bsubprocess\\.(?:popen|run|call)\\s*\\(', blob)) and context_any(blob, ['powershell', 'cmd.exe', 'curl', 'wget', 'http://', 'https://', 'discord', 'telegram', 'token', 'appdata', 'startup']):
        tags.extend(['process_exec', 'script_execution'])
    if context_any(blob, ['discord token', 'authorization', 'access_token', 'refresh_token', 'login data', 'cookies.sqlite', 'local state']) and context_any(blob, ['webhook', 'discord.com/api/webhooks', 'api.telegram.org', 'requests.post', 'fetch(', 'xmlhttprequest', 'socket.send']):
        tags.extend(['credential_access', 'token_secret_access', 'token_exfiltration', 'network_exfiltration', 'high_confidence_credential_theft'])
    if context_any(blob, ['dllimport', 'il2cpp', 'mono', 'assembly-csharp']) and context_any(blob, ['virtualalloc', 'virtualallocex']) and context_any(blob, ['createremotethread', 'ntcreatethreadex', 'queueuserapc']):
        tags.extend(['dll_load', 'memory_allocate', 'memory_write', 'thread_execution', 'process_injection', 'in_memory_execution', 'shellcode_exec'])
    if context_any(blob, ['process.start', 'createprocess', 'shellexecute', 'winexec']) and context_any(blob, ['unity', 'il2cpp', 'mono', 'assembly-csharp', 'system.diagnostics.process']):
        tags.extend(['process_exec', 'unity_process_exec'])
    return tags


__all__ = ("ContextualTagScanRequest", "contextual_tag_scan")
