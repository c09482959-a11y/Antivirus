"""Tag scoring audit class ownership."""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.contracts.detection_observation import DETECTION_OBSERVATION_UNAVAILABLE_TAG
from Virus_Scan.contracts.tag_taxonomy import (
    TAG_CLASS_ANALYTIC_CANDIDATE,
    TAG_CLASS_ATOMIC_OBSERVATION,
    TAG_CLASS_BEHAVIOR_DERIVATION,
    TAG_CLASS_CONTEXT,
    TAG_CLASS_REPORTING_ONLY,
    TAG_CLASS_UNAVAILABLE,
)
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.scoring.weighting.policy_constants import (
    HIGH_RISK_BUCKETS,
    SUPPORT_ONLY_SCORE_TAGS,
    TAG_AUDIT_VERSION,
    TAG_BEHAVIOR_SCOREABLE,
    TAG_STRUCTURAL_ONLY,
    TAG_WEAK_CONTEXT_ONLY,
    norm_lower_tag_set,
)
from Virus_Scan.detection.registries.chain_registry import CHAIN_CONCLUSION_TAGS
from Virus_Scan.detection.tags.heuristics.behavior_buckets import tag_behavior_bucket
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags


@dataclass(frozen=True, slots=True)
class _TagScoreContext:
    exec_context: bool
    network_context: bool
    decode_context: bool
    pickle_context: bool
    archive_context: bool
    api_context: bool


def _audit_tag_text(tag: object) -> object:
    text, reason = no_hook_text(
        tag,
        missing_reason="audit_tag_text_missing",
        unsupported_reason="audit_tag_text_rejected",
    )
    if reason:
        return 'tag_normalization_failure_evidence'
    return text.strip().lower()




def _tag_score_context(full: set[str], calls: set[str]) -> _TagScoreContext:
    return _TagScoreContext(
        exec_context=bool(full & {"process_exec", "script_execution", "powershell_exec", "cmd_exec", "wscript_exec", "mshta_exec", "dynamic_execution", "payload_execution", "in_memory_execution", "assembly_load"}),
        network_context=bool(full & {"network_download", "remote_payload_download", "lolbin_download", "network_c2", "remote_command_channel", "http_upload", "network_exfiltration", "token_exfiltration"}),
        decode_context=bool(full & {"payload_decode_confirmed", "decoded_pe_payload", "confirmed_embedded_pe_payload"}),
        pickle_context=bool(full & {"pickle_reduce_opcode", "pickle_dangerous_global", "pickle_callable_reference"}),
        archive_context=bool(full & {"archive_dropper", "dropper_behavior", "embedded_pe_payload", "confirmed_embedded_pe_payload"}),
        api_context=bool(calls & {"createprocessw", "shellexecutea", "shellexecutew", "winexec", "writeprocessmemory", "createremotethread", "virtualallocex", "minidumpwritedump"}),
    )



def _network_context_can_score(context: _TagScoreContext, full: set[str]) -> bool:
    return context.network_context and (
        context.exec_context or context.decode_context or context.pickle_context or "http_upload" in full
    )


def _compressed_context_can_score(context: _TagScoreContext) -> bool:
    return context.decode_context or context.exec_context or context.pickle_context or context.archive_context


def _decoded_context_can_score(context: _TagScoreContext) -> bool:
    return context.decode_context or context.exec_context or context.pickle_context


def _archive_context_can_score(context: _TagScoreContext) -> bool:
    return context.archive_context and (context.exec_context or context.decode_context or context.pickle_context)


def _default_context_can_score(context: _TagScoreContext) -> bool:
    return context.exec_context and (
        context.network_context or context.decode_context or context.archive_context or context.api_context
    )


def _weak_context_tag_can_score(tag: str, full: set[str], calls: set[str]) -> bool:
    context = _tag_score_context(full, calls)
    if tag in {"url_present", "network_url", "asset_resource_fetch", "browser_xhr_fetch", "network_activity"}:
        result = _network_context_can_score(context, full)
    elif tag in {"embedded_gzip_payload", "embedded_zlib_payload", "gzip_decode", "zlib_decompress", "gzip_decompress", "compressed_payload", "compressed_payload_candidate"}:
        result = _compressed_context_can_score(context)
    elif tag in {"decoded_base64_blob", "decoded_base64_data", "base64_blob_detected", "base64_detected", "encoded_data_context", "embedded_base64_payload"}:
        result = _decoded_context_can_score(context)
    elif tag in {"embedded_archive_signature", "embedded_zip_signature", "embedded_7z_signature", "embedded_rar_signature", "embedded_archive_payload"}:
        result = _archive_context_can_score(context)
    elif tag.startswith("pickle_"):
        result = context.pickle_context or context.exec_context
    else:
        result = _default_context_can_score(context)
    return result


def audit_tag_can_score(tag: object, full_tags: object = None, api_calls: object = None, ordered_events: object = None) -> object:
    """Return whether one tag has enough evidence to affect scoring."""
    del ordered_events
    tag_text = _audit_tag_text(tag)
    full = norm_lower_tag_set(normalize_tags(full_tags))
    calls = norm_lower_tag_set(api_calls)
    taxonomy_class = tag_class_for(tag_text)
    if taxonomy_class in {
        "", TAG_CLASS_ANALYTIC_CANDIDATE, TAG_CLASS_BEHAVIOR_DERIVATION,
        TAG_CLASS_REPORTING_ONLY, TAG_CLASS_UNAVAILABLE,
    }:
        return False
    tag_class = audit_tag_class(tag_text)
    if tag_class == "behavior":
        return taxonomy_class == TAG_CLASS_ATOMIC_OBSERVATION
    if tag_class == "chain_projection":
        return False
    if tag_class in {"weak_context", "structural"}:
        return (
            taxonomy_class in {TAG_CLASS_ATOMIC_OBSERVATION, TAG_CLASS_CONTEXT}
            and _weak_context_tag_can_score(tag_text, full, calls)
        )
    return False


def _audit_role_from_bucket(tag_text: str) -> str:
    bucket = tag_behavior_bucket(tag_text)
    if bucket in HIGH_RISK_BUCKETS and tag_text not in SUPPORT_ONLY_SCORE_TAGS:
        return "behavior"
    if bucket != "other_behavior":
        return "weak_context" if tag_text in SUPPORT_ONLY_SCORE_TAGS else "behavior"
    return "unknown"



def audit_tag_class(tag: object) -> object:
    """Return scoring class for one normalized tag."""
    tag_text = _audit_tag_text(tag)
    taxonomy_class = tag_class_for(tag_text)
    if taxonomy_class == TAG_CLASS_ANALYTIC_CANDIDATE or tag_text in CHAIN_CONCLUSION_TAGS:
        role = "chain_projection"
    elif taxonomy_class in {TAG_CLASS_BEHAVIOR_DERIVATION, TAG_CLASS_REPORTING_ONLY}:
        role = "weak_context"
    elif taxonomy_class == TAG_CLASS_UNAVAILABLE or taxonomy_class == "":
        role = "unknown"
    elif tag_text in TAG_STRUCTURAL_ONLY:
        role = "structural"
    elif tag_text in TAG_WEAK_CONTEXT_ONLY or tag_text in detection_registry_value("SUPPORT_ONLY_SCORE_TAGS", frozenset()):
        role = "weak_context"
    elif taxonomy_class == TAG_CLASS_ATOMIC_OBSERVATION and (
        tag_text in TAG_BEHAVIOR_SCOREABLE
        or tag_text in detection_registry_value("CONCRETE_SCORE_TAGS", frozenset())
    ):
        role = "behavior"
    else:
        role = _audit_role_from_bucket(tag_text)
        if taxonomy_class != TAG_CLASS_ATOMIC_OBSERVATION and role == "behavior":
            role = "weak_context"
    return role


def audit_tags_for_scoring(tags: object=None, api_calls: object=None, ordered_events: object=None) -> object:
    norm = norm_lower_tag_set(normalize_tags(tags))
    degraded = bool(norm & {'tag_normalization_failure_evidence', 'detection_stage_degraded', DETECTION_OBSERVATION_UNAVAILABLE_TAG})
    result = {
        'version': TAG_AUDIT_VERSION,
        'scoreable': sorted((t for t in norm if audit_tag_can_score(t, norm, api_calls=api_calls, ordered_events=ordered_events))),
        'weak_context': sorted((t for t in norm if audit_tag_class(t) == 'weak_context')),
        'structural': sorted((t for t in norm if audit_tag_class(t) == 'structural')),
        'behavior': sorted((t for t in norm if audit_tag_class(t) == 'behavior')),
        'chain_projection': sorted((t for t in norm if audit_tag_class(t) == 'chain_projection')),
    }
    if degraded:
        result['degraded'] = True
        result['failure_evidence'] = sorted(norm & {'tag_normalization_failure_evidence', 'detection_stage_degraded', DETECTION_OBSERVATION_UNAVAILABLE_TAG})
    return result


__all__ = ('audit_tag_can_score', 'audit_tag_class', 'audit_tags_for_scoring')
