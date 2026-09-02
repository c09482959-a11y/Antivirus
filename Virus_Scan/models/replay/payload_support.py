"""Support helpers for parent replay learning-payload projection."""

from __future__ import annotations

from Virus_Scan.models.api.profile_learning_contracts import DEFAULT_ENGINES
from Virus_Scan.models.replay.detachment import (
    detach_replay_payload_list_with_errors,
    detach_replay_payload_mapping_with_errors,
)
from Virus_Scan.models.replay.payload_boundaries import (
    detached_mapping_field,
    mapping_flag,
    replay_mapping_get,
    replay_mapping_has,
    replay_payload_unavailable,
    safe_truthy_replay_flag,
)

def _learning_integrity_and_tags(result: object) -> tuple[dict[str, object] | None, list[object] | None, object | None]:
    integrity, integrity_errors = detach_replay_payload_mapping_with_errors(
        replay_mapping_get(result, "scan_integrity"),
        "scan_integrity",
        required_mapping=replay_mapping_has(result, "scan_integrity"),
    )
    if integrity_errors:
        return None, None, replay_payload_unavailable(integrity_errors)
    tags, tag_errors = detach_replay_payload_list_with_errors(
        replay_mapping_get(result, "tags"),
        "tags",
        required_sequence=replay_mapping_has(result, "tags"),
    )
    if tag_errors:
        return None, None, replay_payload_unavailable(tag_errors)
    tag_l = {str.__str__(t).lower() for t in tags if type(t) is str}
    if (
        mapping_flag(integrity, "file_failed")
        or mapping_flag(integrity, "queue_failure")
        or safe_truthy_replay_flag(replay_mapping_get(result, "queue_failure"))
        or (replay_mapping_get(integrity, "allow_learning") is False)
        or ("scan_incomplete" in tag_l)
        or ("scanner_failure" in tag_l)
        or ("result_contract_violation" in tag_l)
    ):
        return None, None, None
    return integrity, tags, None

def _learning_behavior_sequences(result: object) -> tuple[list[object] | None, list[object] | None, list[object] | None, list[object] | None, object | None]:
    yara_hits, yara_errors = detach_replay_payload_list_with_errors(
        replay_mapping_get(result, "yara_hits"),
        "yara_hits",
        required_sequence=replay_mapping_has(result, "yara_hits"),
    )
    if yara_errors:
        return None, None, None, None, replay_payload_unavailable(yara_errors)
    api_obj, api_obj_errors = detached_mapping_field(result, "api", required_mapping=False)
    if api_obj_errors:
        return None, None, None, None, replay_payload_unavailable(api_obj_errors)
    api_calls, api_errors = detach_replay_payload_list_with_errors(
        replay_mapping_get(api_obj, "api_calls"),
        "api_calls",
        required_sequence=replay_mapping_has(api_obj, "api_calls"),
    )
    if api_errors:
        return None, None, None, None, replay_payload_unavailable(api_errors)
    ordered_events, ordered_errors = detach_replay_payload_list_with_errors(
        replay_mapping_get(result, "ordered_events"),
        "ordered_events",
        required_sequence=replay_mapping_has(result, "ordered_events"),
    )
    if ordered_errors:
        return None, None, None, None, replay_payload_unavailable(ordered_errors)
    behavior_flow_value = replay_mapping_get(result, "behavior_flow") if replay_mapping_has(result, "behavior_flow") else ordered_events or replay_mapping_get(result, "behavior_timeline")
    behavior_flow, behavior_errors = detach_replay_payload_list_with_errors(
        behavior_flow_value,
        "behavior_flow",
        required_sequence=(replay_mapping_has(result, "behavior_flow") or replay_mapping_has(result, "behavior_timeline")),
    )
    if behavior_errors:
        return None, None, None, None, replay_payload_unavailable(behavior_errors)
    return yara_hits, api_calls, ordered_events, behavior_flow, None

def _learning_profile_context(result: object) -> tuple[object | None, dict[str, object] | None, object | None]:
    profile_selection, profile_selection_errors = detached_mapping_field(
        result, "profile_selection", required_mapping=False
    )
    if profile_selection_errors:
        return None, None, replay_payload_unavailable(profile_selection_errors)
    engine_for_profile = replay_mapping_get(profile_selection, "active_profile")
    engine_context, engine_context_errors = detach_replay_payload_mapping_with_errors(
        replay_mapping_get(result, "engine_context"),
        "engine_context",
        required_mapping=replay_mapping_has(result, "engine_context"),
    )
    if engine_context_errors:
        return None, None, replay_payload_unavailable(engine_context_errors)
    if engine_for_profile not in DEFAULT_ENGINES:
        engine_for_profile = None
    if engine_for_profile not in DEFAULT_ENGINES:
        engine_for_profile = "other"
    if len(engine_context) == 0:
        engine_context = {engine_for_profile: 1.0}
    return engine_for_profile, engine_context, None
