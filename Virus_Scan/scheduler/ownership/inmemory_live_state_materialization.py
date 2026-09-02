"""Canonical no-hook materialization for in-memory scheduler live state inputs."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_value, unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_text
from Virus_Scan.scheduler.ownership.inmemory_live_state_contract import (
    LiveEwmaSnapshot,
    LiveMappingSnapshot,
    LiveProcessSnapshot,
    LiveScalarOutcome,
    LiveSetSnapshot,
    LiveStateFieldOutcome,
    LiveStateRejection,
)


def live_state_rejection(field_name: str, value: object, reason: str) -> LiveStateRejection:
    return {
        "inmemory_live_state_input_rejected": True,
        "field": field_name,
        "reason": reason,
        "evidence": unsupported_scheduler_value_evidence(value, field_name=field_name),
    }


def live_scalar(value: object) -> LiveScalarOutcome:
    if value is None or type(value) in {str, bool, int}:
        return LiveScalarOutcome(value, accepted=True, reason="")
    if type(value) is float:
        return LiveScalarOutcome(value, accepted=True, reason="")
    return LiveScalarOutcome((), accepted=False, reason="inmemory_live_scalar_rejected")


def _outcome(field_name: str, status: str, reason: str, rejections: tuple[LiveStateRejection, ...]) -> LiveStateFieldOutcome:
    if status == "defaulted":
        return LiveStateFieldOutcome(field_name, "defaulted", reason, len(rejections))
    if status == "rejected":
        return LiveStateFieldOutcome(field_name, "rejected", reason, len(rejections))
    return LiveStateFieldOutcome(field_name, "materialized", reason, len(rejections))


def live_mapping_snapshot(value: object, *, field_name: str) -> LiveMappingSnapshot:
    if value is None:
        return LiveMappingSnapshot({}, _outcome(field_name, "defaulted", "inmemory_live_mapping_missing", ()), ())
    items = no_hook_mapping_items(value)
    if items is None:
        rejection = live_state_rejection(field_name, value, "inmemory_live_mapping_rejected")
        rejections: tuple[LiveStateRejection, ...] = (rejection,)
        return LiveMappingSnapshot({}, _outcome(field_name, "rejected", "inmemory_live_mapping_rejected", rejections), rejections)
    out: dict[object, object] = {}
    rejections_list: list[LiveStateRejection] = []
    for index, (key, item) in enumerate(items):
        safe_key = live_scalar(key)
        if not safe_key.accepted:
            rejections_list.append(live_state_rejection(str.__str__(field_name) + "_key_" + int.__str__(index), key, "inmemory_live_mapping_key_rejected"))
            continue
        out[safe_key.value] = immutable_value(item)
    rejections = tuple(rejections_list)
    return LiveMappingSnapshot(out, _outcome(field_name, "materialized", "", rejections), rejections)


def live_set_snapshot(value: object, *, field_name: str) -> LiveSetSnapshot:
    if value is None:
        return LiveSetSnapshot(set(), _outcome(field_name, "defaulted", "inmemory_live_set_missing", ()), ())
    items = no_hook_sequence_items(value)
    if not items and type(value) not in {list, tuple, set, frozenset}:
        rejection = live_state_rejection(field_name, value, "inmemory_live_set_rejected")
        rejections: tuple[LiveStateRejection, ...] = (rejection,)
        return LiveSetSnapshot(set(), _outcome(field_name, "rejected", "inmemory_live_set_rejected", rejections), rejections)
    out: set[object] = set()
    rejections_list: list[LiveStateRejection] = []
    for index, item in enumerate(items):
        safe_item = live_scalar(item)
        if not safe_item.accepted:
            rejections_list.append(live_state_rejection(str.__str__(field_name) + "_" + int.__str__(index), item, "inmemory_live_set_item_rejected"))
            continue
        out.add(safe_item.value)
    rejections = tuple(rejections_list)
    return LiveSetSnapshot(out, _outcome(field_name, "materialized", "", rejections), rejections)


def live_process_snapshot(value: object, *, field_name: str) -> LiveProcessSnapshot:
    if value is None:
        return LiveProcessSnapshot([], _outcome(field_name, "defaulted", "inmemory_live_processes_missing", ()), ())
    if type(value) is list:
        return LiveProcessSnapshot(list(value), _outcome(field_name, "materialized", "", ()), ())
    if type(value) is tuple:
        return LiveProcessSnapshot(list(value), _outcome(field_name, "materialized", "", ()), ())
    rejection = live_state_rejection(field_name, value, "inmemory_live_processes_rejected")
    rejections = (rejection,)
    return LiveProcessSnapshot([], _outcome(field_name, "rejected", "inmemory_live_processes_rejected", rejections), rejections)


def live_ewma_snapshot(value: object) -> LiveEwmaSnapshot:
    field_name = "ewma_state"
    if value is None:
        return LiveEwmaSnapshot({}, _outcome(field_name, "defaulted", "inmemory_live_ewma_missing", ()), ())
    items = no_hook_mapping_items(value)
    if items is None:
        rejection = live_state_rejection(field_name, value, "inmemory_live_ewma_mapping_rejected")
        rejections: tuple[LiveStateRejection, ...] = (rejection,)
        return LiveEwmaSnapshot({}, _outcome(field_name, "rejected", "inmemory_live_ewma_mapping_rejected", rejections), rejections)
    out: dict[str, float] = {}
    rejections_list: list[LiveStateRejection] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = scheduler_text(key, unsupported_reason="inmemory_live_ewma_key_rejected")
        if key_reason or key_text == "":
            rejections_list.append(live_state_rejection("ewma_state_key_" + int.__str__(index), key, key_reason or "inmemory_live_ewma_key_blank"))
            continue
        number, value_reason = scheduler_float(item, reason="inmemory_live_ewma_value_rejected")
        if value_reason:
            rejections_list.append(live_state_rejection("ewma_state_value_" + str.__str__(key_text), item, value_reason))
            continue
        out[key_text] = number
    rejections = tuple(rejections_list)
    return LiveEwmaSnapshot(out, _outcome(field_name, "materialized", "", rejections), rejections)
