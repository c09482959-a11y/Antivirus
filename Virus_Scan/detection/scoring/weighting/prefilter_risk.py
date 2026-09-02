"""Canonical score ownership for strict prefilter risk floors."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items, no_hook_sequence_items, no_hook_text
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence
from Virus_Scan.detection.profiles.profile_policy import profile_updater_has_hard_anchor
from Virus_Scan.detection.scoring.full_analysis.classification import classify_detection_score
from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.utils.text_validation import text_boundary_value


_TEXT_PREFILTER_SUFFIXES = frozenset({".rpy", ".py", ".rpym", ".txt"})
_PREFILTER_CATEGORY_SETS = tuple(
    frozenset(group)
    for group in (
        {"remote_payload_download", "network_download", "c2_beacon", "network_c2", "remote_command_channel"},
        {"powershell_exec", "cmd_exec", "process_exec", "script_host_exec", "lolbin_execution"},
        {"registry_persistence", "schtasks_create", "scheduled_task", "startup_persistence", "persistence"},
        {"process_injection", "memory_write", "thread_execution", "write_process_memory", "remote_thread_create"},
        {"unsafe_deserialization", "dynamic_code_exec", "pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode"},
        {"shadowcopy_delete", "defender_disable", "amsi_scanbuffer_patch", "etw_eventwrite_patch", "security_process_kill", "security_service_disable"},
        {"encoded_powershell", "payload_decode_confirmed"},
    )
)
_HIGH_RISK_INJECTION_TAGS = frozenset({"process_injection", "memory_write", "thread_execution"})
_REFERENCE_URL_HARD_ANCHORS = frozenset({
    "remote_payload_download",
    "network_download",
    "c2_beacon",
    "network_c2",
    "process_exec",
    "cmd_exec",
    "powershell_exec",
})


PrefilterValue = object
PrefilterMapping = dict[str, PrefilterValue]
PrefilterTags = set[str]
PrefilterHitTagResult = tuple[PrefilterValue, PrefilterValue]
PrefilterStringReadResult = tuple[str, BaseException | None]
PrefilterMergeResult = tuple[PrefilterValue, str]


def _record_prefilter_scoring_failure(
    result: PrefilterMapping, *, stage_name: str, error_source: str,
    error: BaseException | str,
) -> PrefilterMapping:
    failure = recoverable_failure_evidence(
        stage_name=stage_name,
        error_source=error_source,
        error=error,
        affected_context=_prefilter_result_text(_prefilter_path(result)),
    )
    payload = failure_evidence_payload((failure,))
    result.setdefault("detection_failures", [])
    result["detection_failures"].extend(payload["failures"])
    result["scanner_degraded"] = True
    result["confidence_degraded"] = True
    explanation = result.setdefault("explanation", {})
    if isinstance(explanation, dict):
        explanation.setdefault("detection_failures", []).extend(payload["failures"])
        explanation["scanner_degraded"] = True
        explanation["confidence_degraded"] = True
    return result


def _prefilter_hits_and_tags(prefilter_info: PrefilterMapping) -> PrefilterHitTagResult:
    hits = prefilter_info.get("hits") or []
    tags = prefilter_info.get("tags") or []
    return hits, tags


def _attach_prefilter_evidence(
    result: PrefilterMapping, prefilter_info: PrefilterMapping,
    hits: PrefilterValue, tags: PrefilterValue,
) -> None:
    result.setdefault("raw_prefilter_hits", hits)
    result.setdefault("raw_prefilter_tags", tags)


def _prefilter_path(result: PrefilterMapping) -> PrefilterValue | None:
    items = no_hook_mapping_items(result)
    if items is None:
        return None
    file_value = None
    node_value = None
    for key, value in items:
        if type(key) is str and str.__str__(key) == "file":
            file_value = value
        elif type(key) is str and str.__str__(key) == "node":
            node_value = value
    return file_value if file_value is not None else node_value


def _prefilter_result_text(value: PrefilterValue) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_prefilter_result_text",
        unsupported_reason="unsafe_prefilter_result_text_rejected",
    )
    return text if reason == "" else ""


def _read_prefilter_strings(path_for_floor: PrefilterValue | None) -> PrefilterStringReadResult:
    strings_for_floor = ""
    read_failure = None
    path_text = text_boundary_value(path_for_floor, unsupported="") or ""
    if path_text and Path(path_text).suffix.lower() in _TEXT_PREFILTER_SUFFIXES:
        try:
            strings_for_floor = Path(path_text).read_text(errors="ignore")[:262144]
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
            read_failure = error
    return strings_for_floor, read_failure


def _merge_prefilter_tags(
    result: PrefilterMapping, tags: PrefilterValue, path_for_floor: PrefilterValue | None,
    strings_for_floor: str,
) -> PrefilterValue:
    try:
        generation = finalize_tag_evidence_generation(
            list(result.get("tags") or []) + list(tags),
            path=path_for_floor,
            strings_blob=strings_for_floor,
            source="strict_prefilter",
        )
        return list(generation.evidence.tags)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return normalize_tags(list(result.get("tags") or []) + list(tags))


def _current_score_value(result: PrefilterMapping) -> float:
    current = result.get("score", 0.0)
    current_items = no_hook_mapping_items(current)
    if current_items is not None:
        for key, value in current_items:
            if type(key) is str and str.__str__(key) == "score":
                score, _score_reason = no_hook_finite_float(value, default=0.0)
                return score
        return 0.0
    score, _score_reason = no_hook_finite_float(current, default=0.0)
    return score


def _prefilter_category_count(tagset: set[str]) -> int:
    categories = 0
    for group in _PREFILTER_CATEGORY_SETS:
        if tagset & group:
            categories += 1
    return categories


def _risk_floor_for_tags(tagset: set[str]) -> float:
    floor = 0.0
    if _HIGH_RISK_INJECTION_TAGS & tagset:
        floor = max(floor, 62.0)
    categories = _prefilter_category_count(tagset)
    if categories >= 2:
        floor = max(floor, 60.0)
    elif categories == 1:
        floor = max(floor, 35.0)
    return floor


def _apply_prefilter_floor(
    result: PrefilterMapping, *, hits: PrefilterValue, floor: float, current_score: float,
) -> None:
    if floor and current_score < floor:
        result["score"] = floor
        result["classification"] = "suspicious"
        result["class"] = "suspicious"
        exp = result.setdefault("explanation", {})
        reasons = exp.setdefault("reasons", [])
        if "strict_prefilter_risk_floor" not in reasons:
            reasons.append("strict_prefilter_risk_floor")
        exp["raw_prefilter_hits"] = hits
        exp["raw_prefilter_floor"] = floor


def _apply_score_cap(
    result: PrefilterMapping, *, cap_name: str, capped_score: float, old_score: float,
) -> None:
    result["score"] = capped_score
    result["classification"] = classify_detection_score(capped_score)[0]
    result["class"] = classify_detection_score(capped_score)[0]
    result.setdefault("explanation", {}).setdefault("caps", []).append(
        {"name": cap_name, "old_score": old_score, "new_score": capped_score}
    )


def _apply_post_prefilter_caps(
    result: PrefilterMapping, *, tags_now: set[str], strings_for_floor: str,
) -> None:
    score_value = _current_score_value(result)
    if "renpy_official_updater" in tags_now and not profile_updater_has_hard_anchor(
        result.get("tags") or [],
        strings_for_floor,
    ):
        if score_value > 22.0:
            _apply_score_cap(
                result,
                cap_name="renpy_official_updater_prefilter_cap",
                capped_score=22.0,
                old_score=score_value,
            )
    elif "reference_url_behavior_suppressed" in tags_now and not (
        _REFERENCE_URL_HARD_ANCHORS & tags_now
    ):
        if score_value > 18.0:
            _apply_score_cap(
                result,
                cap_name="reference_url_prefilter_cap",
                capped_score=18.0,
                old_score=score_value,
            )


def _merge_tags_with_failure_evidence(
    result: PrefilterMapping, tags: PrefilterValue,
) -> PrefilterMergeResult:
    path_for_floor = _prefilter_path(result)
    strings_for_floor, read_failure = _read_prefilter_strings(path_for_floor)
    if read_failure is not None:
        result = _record_prefilter_scoring_failure(
            result,
            stage_name="strict_prefilter_string_read",
            error_source="apply_strict_prefilter_risk_floor",
            error=read_failure,
        )
    merged_tags = _merge_prefilter_tags(result, tags, path_for_floor, strings_for_floor)
    result["tags"] = merged_tags
    return merged_tags, strings_for_floor


def _apply_prefilter_scoring(
    result: PrefilterMapping, hits: PrefilterValue, tags: PrefilterValue,
) -> PrefilterMapping:
    merged_tags, strings_for_floor = _merge_tags_with_failure_evidence(result, tags)
    tagset = set(merged_tags)
    current_score = _current_score_value(result)
    floor = _risk_floor_for_tags(tagset)
    _apply_prefilter_floor(result, hits=hits, floor=floor, current_score=current_score)
    try:
        tags_now = {
            text.lower()
            for tag in normalize_tags(no_hook_sequence_items(result.get("tags")))
            for text, reason in (no_hook_text(tag, missing_reason="missing_prefilter_tag", unsupported_reason="unsafe_prefilter_tag_rejected"),)
            if reason == "" and text != ""
        }
        _apply_post_prefilter_caps(result, tags_now=tags_now, strings_for_floor=strings_for_floor)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        result = _record_prefilter_scoring_failure(
            result,
            stage_name="strict_prefilter_post_cap",
            error_source="apply_strict_prefilter_risk_floor",
            error=error,
        )
    return result


def apply_strict_prefilter_risk_floor(
    result: PrefilterMapping, prefilter_info: PrefilterMapping,
) -> PrefilterMapping:
    """
    Make raw prefilter evidence count after full scan. This prevents suspicious
    strings from merely disabling bypass but then being underweighted downstream.
    """
    try:
        hits, tags = _prefilter_hits_and_tags(prefilter_info)
        if not hits and not tags:
            return result
        _attach_prefilter_evidence(result, prefilter_info, hits, tags)
        return _apply_prefilter_scoring(result, hits, tags)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        return _record_prefilter_scoring_failure(
            result,
            stage_name="strict_prefilter_risk_floor",
            error_source="apply_strict_prefilter_risk_floor",
            error=error,
        )
