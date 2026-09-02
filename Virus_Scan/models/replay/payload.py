"""Parent-replay worker-result payload projection."""
from __future__ import annotations

import hashlib
import json

from Virus_Scan.contracts.result_record import normalize_result_record, result_is_incomplete_scan
from Virus_Scan.contracts.result_record import is_passive_fast_asset_result
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence, normalize_tag_evidence
from Virus_Scan.models.api.profile_learning_contracts import (
    canonical_behavior_flow_from_sources,
)
from Virus_Scan.utils.stages import effective_stage_for_path

from Virus_Scan.models.replay.detachment import (
    detach_replay_payload_list,
    detach_replay_payload_list_with_errors,
    detach_replay_payload_mapping_with_errors,
    finite_replay_score,
    safe_replay_text,
)
from Virus_Scan.models.replay.payload_boundaries import (
    first_safe_text,
    mapping_flag,
    replay_mapping_copy,
    replay_mapping_get,
    replay_mapping_has,
    replay_payload_unavailable,
)

from Virus_Scan.models.replay.payload_support import (
    _learning_behavior_sequences,
    _learning_integrity_and_tags,
    _learning_profile_context,
)


def safe_parent_replay_result_for_normalization(res: object) -> tuple[object, str]:
    out = replay_mapping_copy(res)
    if out is None:
        return res, ""
    degraded_input = False
    for key in ("file", "path", "node", "classification", "class", "verdict"):
        if replay_mapping_has(out, key):
            text = str.strip(safe_replay_text(replay_mapping_get(out, key)))
            if text != "":
                out[key] = text
            else:
                out.pop(key, None)
                degraded_input = True
    for key in ("tags", "suspicious_tags"):
        if replay_mapping_has(out, key):
            detached, field_errors = detach_replay_payload_list_with_errors(
                replay_mapping_get(out, key), key, required_sequence=True
            )
            if field_errors:
                degraded_input = True
            clean_tags: list[str] = []
            for item in detached:
                if type(item) is str:
                    clean_tags.append(item)
                else:
                    degraded_input = True
            out[key] = clean_tags
    for key in ("yara_hits", "ordered_events", "behavior_flow", "behavior_timeline"):
        if replay_mapping_has(out, key):
            detached, field_errors = detach_replay_payload_list_with_errors(
                replay_mapping_get(out, key), key, required_sequence=True
            )
            if field_errors:
                degraded_input = True
            out[key] = detached
    if replay_mapping_has(out, "scan_integrity"):
        scan_integrity, field_errors = detach_replay_payload_mapping_with_errors(
            replay_mapping_get(out, "scan_integrity"), "scan_integrity", required_mapping=True
        )
        if field_errors:
            degraded_input = True
        out["scan_integrity"] = scan_integrity
    if degraded_input:
        integrity = replay_mapping_copy(replay_mapping_get(out, "scan_integrity")) or {}
        integrity.update({
            "had_degraded_stage": True,
            "allow_learning": False,
            "file_failed": True,
            "parent_replay_input_unavailable": True,
        })
        out["scan_integrity"] = integrity
        out["tags"] = [
            item for item in detach_replay_payload_list(replay_mapping_get(out, "tags")) if type(item) is str
        ] + ["scanner_degraded", "scan_incomplete", "result_contract_violation"]
        out.setdefault("error", "parent replay input contained unavailable model tags")
    resolved = first_safe_text(out, "file", "path", "node")
    return out, resolved

def _normalized_learning_result(res: object) -> tuple[object | None, str]:
    if replay_mapping_copy(res) is None:
        return None, ""
    normalized_input, replay_file_path = safe_parent_replay_result_for_normalization(res)
    result = normalize_result_record(
        normalized_input,
        file_path=replay_file_path,
        source="parent_replay_payload",
    )
    return result, replay_file_path

def _parent_replay_observation_id(result: object, file_path: str) -> str:
    for key in ("observation_id", "job_id", "file_id", "scan_id"):
        value = first_safe_text(result, key)
        if value != "":
            return key + ":" + value
    stable = {
        "file_path": file_path,
        "classification": first_safe_text(result, "classification", "class", "verdict"),
        "effective_stage": first_safe_text(result, "effective_stage"),
        "previous_stage": first_safe_text(result, "previous_stage", "prev_stage"),
        "tags": tuple(item for item in detach_replay_payload_list(replay_mapping_get(result, "tags")) if type(item) is str),
        "score": replay_mapping_get(result, "score", replay_mapping_get(result, "score_100", 0.0)),
    }
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return "result:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def result_learning_payload(res: object) -> dict[str, object] | None:
    """Normalize one worker result into parent-side model replay inputs."""
    result, _replay_file_path = _normalized_learning_result(res)
    if result is None:
        return None
    if result_is_incomplete_scan(result):
        integrity = replay_mapping_copy(replay_mapping_get(result, "scan_integrity")) or {}
        if mapping_flag(integrity, "parent_replay_input_unavailable"):
            return replay_payload_unavailable()
        return None
    file_path = first_safe_text(result, "file", "node")
    if file_path == "":
        return None
    integrity, tags, unavailable = _learning_integrity_and_tags(result)
    if unavailable is not None or integrity is None or tags is None:
        return unavailable
    published_tags = tuple(item for item in tags if type(item) is str)
    has_published_tag_evidence = replay_mapping_has(result, "tag_evidence")
    if has_published_tag_evidence:
        tag_evidence = TagEvidence.from_record(
            replay_mapping_get(result, "tag_evidence"),
        )
        evidence_unavailable = tag_evidence.reasons.get("unavailable_reason")
        if evidence_unavailable or (published_tags and not tag_evidence.records):
            return replay_payload_unavailable([
                "tag_evidence:parent_replay_tag_evidence_unavailable",
            ])
    else:
        tag_evidence = normalize_tag_evidence(
            published_tags,
            source_detector="parent_replay",
            source_stage="raw_result_input",
        )
    if (
        has_published_tag_evidence
        and frozenset(published_tags) != frozenset(tag_evidence.tags)
    ):
        return replay_payload_unavailable([
            "tag_evidence:parent_replay_tag_projection_mismatch",
        ])
    verdict = replay_mapping_get(result, "classification", replay_mapping_get(result, "class"))
    yara_hits, api_calls, ordered_events, behavior_flow, unavailable = _learning_behavior_sequences(result)
    if unavailable is not None or yara_hits is None or api_calls is None or ordered_events is None or behavior_flow is None:
        return unavailable
    raw_score = replay_mapping_get(result, "score")
    raw_score = raw_score if raw_score is not None else replay_mapping_get(result, "score_100")
    score, score_degraded, score_unavailable_reason = finite_replay_score(raw_score)
    if is_passive_fast_asset_result(result):
        flow: list[str] = []
    else:
        flow = canonical_behavior_flow_from_sources(
            raw_tags=tag_evidence,
            ordered_events=ordered_events,
            behavior_flow=behavior_flow,
        )
    curr_stage_text = first_safe_text(result, "effective_stage")
    curr_stage = curr_stage_text if curr_stage_text != "" else effective_stage_for_path(tags, file_path)
    prev_stage_text = first_safe_text(result, "previous_stage", "prev_stage")
    prev_stage = prev_stage_text if prev_stage_text != "" else "unknown"
    engine_for_profile, engine_context, unavailable = _learning_profile_context(result)
    if unavailable is not None or engine_context is None:
        return unavailable
    payload: dict[str, object] = {
        "file_path": file_path,
        "engine": engine_for_profile,
        "engine_context": engine_context,
        "verdict": verdict,
        "tags": tags,
        "tag_evidence": tag_evidence.to_record(record_limit=64),
        "yara_hits": yara_hits,
        "score": score,
        "api_calls": api_calls,
        "ordered_events": ordered_events,
        "behavior_flow": behavior_flow,
        "flow": flow,
        "prev_stage": prev_stage,
        "curr_stage": curr_stage,
        "integrity": integrity,
        "observation_id": _parent_replay_observation_id(result, file_path),
        "passive_fast_asset": is_passive_fast_asset_result(result),
    }
    if score_degraded:
        payload["degraded"] = True
        payload["replay_score_unavailable_reason"] = score_unavailable_reason
    return payload

_safe_parent_replay_result_for_normalization = safe_parent_replay_result_for_normalization

__all__ = ("result_learning_payload", "safe_parent_replay_result_for_normalization")
