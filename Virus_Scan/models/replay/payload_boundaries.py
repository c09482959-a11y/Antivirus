"""Deterministic parent-replay learning payload boundary helpers."""
from __future__ import annotations


from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.models.replay.detachment import (
    detach_replay_payload_mapping_with_errors,
    safe_replay_text,
)


def replay_payload_unavailable(errors: list[str] | tuple[str, ...] | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "replay_payload_unavailable": True,
        "reason": "parent_replay_input_unavailable",
    }
    if errors is not None:
        error_items = tuple(errors)
        if len(error_items) > 0:
            payload["errors"] = list(error_items)
    return payload


def replay_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    return no_hook_mapping_items(value, allow_dict_subclass=True)


def replay_mapping_get(value: object, key: str, default: object = None) -> object:
    items = replay_mapping_items(value)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__eq__(item_key, key) is True:
            return item_value
    return default


def replay_mapping_has(value: object, key: str) -> bool:
    sentinel = object()
    return replay_mapping_get(value, key, sentinel) is not sentinel


def replay_mapping_copy(value: object) -> dict[str, object] | None:
    items = replay_mapping_items(value)
    if items is None:
        return None
    return {key: item for key, item in items if type(key) is str}


def first_safe_text(mapping: object, *keys: str) -> str:
    for key in keys:
        if not replay_mapping_has(mapping, key):
            continue
        text = safe_replay_text(replay_mapping_get(mapping, key))
        text = str.strip(text)
        if text != "":
            return text
    return ""


def safe_truthy_replay_flag(value: object) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    if type(value) in (int, float):
        return value != 0
    text = safe_replay_text(value)
    return str.strip(text).lower() in {"1", "true", "yes", "y", "on", "failed", "error"}


def mapping_flag(mapping: object, key: str) -> bool:
    return safe_truthy_replay_flag(replay_mapping_get(mapping, key))


def detached_mapping_field(
    result: object,
    field: str,
    *,
    required_mapping: bool = False,
) -> tuple[dict[str, object], list[str]]:
    return detach_replay_payload_mapping_with_errors(
        replay_mapping_get(result, field),
        field,
        required_mapping=required_mapping or replay_mapping_has(result, field),
    )


__all__ = (
    "detached_mapping_field",
    "first_safe_text",
    "mapping_flag",
    "replay_mapping_copy",
    "replay_mapping_get",
    "replay_mapping_has",
    "replay_mapping_items",
    "replay_payload_unavailable",
    "safe_truthy_replay_flag",
)
