"""Deterministic parent replay-learning boundary helpers."""
from __future__ import annotations


from Virus_Scan.models.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_mapping_items
from Virus_Scan.models.replay.payload_boundaries import safe_truthy_replay_flag
from Virus_Scan.models.replay.detachment import safe_replay_text


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


def replay_mapping_values(value: object) -> tuple[object, ...] | None:
    items = replay_mapping_items(value)
    return None if items is None else tuple(item_value for _key, item_value in items)


def result_parent_replayed(result: object) -> bool:
    return replay_mapping_get(result, "_umige_parent_model_replayed") is True


def has_non_empty_text_field(mapping: object, key: str) -> bool:
    value = replay_mapping_get(mapping, key)
    if value is None:
        return False
    text = safe_replay_text(value)
    return text != "" and str.strip(text) != ""


def learning_result_promoted(learning_result: object) -> bool:
    return safe_truthy_replay_flag(replay_mapping_get(learning_result, "promoted"))


def safe_summary_count(value: object) -> int:
    if value is None:
        return 0
    if type(value) is bool:
        return 1 if value else 0
    count, _reason = no_hook_exact_nonnegative_int(value, default=0)
    return count


__all__ = (
    "has_non_empty_text_field",
    "learning_result_promoted",
    "replay_mapping_get",
    "replay_mapping_items",
    "replay_mapping_values",
    "result_parent_replayed",
    "safe_summary_count",
)
