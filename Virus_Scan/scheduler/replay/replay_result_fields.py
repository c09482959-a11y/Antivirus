"""Exact replay result field extraction without caller-owned hooks."""
from __future__ import annotations

import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision


@dataclass(frozen=True)
class ReplayMappingItemsDecision:
    status: str
    reason: str
    items: tuple[tuple[object, object], ...] | None


@dataclass(frozen=True)
class ReplayTextDecision:
    status: str
    reason: str
    text: str | None


@dataclass(frozen=True)
class ReplayCountDecision:
    status: str
    reason: str
    count: int


def replay_mapping_items_decision(result: Mapping[str, object] | None) -> ReplayMappingItemsDecision:
    if type(result) is dict or type(result) is MappingProxyType:
        items = no_hook_mapping_items(result)
        if items is not None:
            return ReplayMappingItemsDecision(status="accepted", reason="", items=items)
        return ReplayMappingItemsDecision(status="unsupported_mapping", reason="unsupported_replay_mapping", items=None)
    frozen_decision = frozen_scheduler_items_decision(result)
    if frozen_decision.accepted:
        return ReplayMappingItemsDecision(status="accepted_frozen", reason="", items=frozen_decision.items)
    return ReplayMappingItemsDecision(status="unsupported", reason="unsupported_replay_result", items=None)


def replay_mapping_items(result: Mapping[str, object] | None) -> object:
    return replay_mapping_items_decision(result).items


def is_replay_mapping(result: object) -> bool:
    return replay_mapping_items(result) is not None


def replay_mapping_value(result: Mapping[str, object] | None, *keys: str, default: object = None) -> object:
    items = replay_mapping_items(result)
    if items is None:
        exception_message = "malformed scheduler replay result record"
        raise RuntimeError(exception_message)
    wanted = frozenset(keys)
    values: dict[str, object] = {}
    for key, value in items:
        if type(key) is str and key in wanted and key not in values:
            values[key] = value
    for key in keys:
        if key in values:
            return values[key]
    return default


def exact_replay_text_decision(value: object) -> ReplayTextDecision:
    if value is None:
        return ReplayTextDecision(status="missing", reason="missing_replay_text", text="")
    if type(value) is str:
        return ReplayTextDecision(status="accepted", reason="", text=value.strip())
    if type(value) is int:
        return ReplayTextDecision(status="accepted_int", reason="", text=int.__str__(value).strip())
    if type(value) is float and math.isfinite(value):
        return ReplayTextDecision(status="accepted_float", reason="", text=float.__str__(value).strip())
    return ReplayTextDecision(status="unsupported", reason="unsupported_replay_text", text=None)


def exact_replay_text(value: object) -> str | None:
    return exact_replay_text_decision(value).text


def first_replay_text(result: Mapping[str, object] | None, *keys: str, default: str = "") -> str | None:
    for key in keys:
        text = exact_replay_text(replay_mapping_value(result, key, default=None))
        if text:
            return text
    return default


def replay_count_value_decision(result: Mapping[str, object] | None, *keys: str) -> ReplayCountDecision:
    for key in keys:
        value = replay_mapping_value(result, key, default=None)
        if value is None:
            continue
        if type(value) is bool:
            exception_message = "scheduler replay count field is malformed"
            raise RuntimeError(exception_message)
        if type(value) is int:
            if value < 0:
                exception_message = "scheduler replay count field is malformed"
                raise RuntimeError(exception_message)
            return ReplayCountDecision(status="accepted_int", reason="", count=value)
        if type(value) is float and math.isfinite(value):
            if value < 0 or not value.is_integer():
                exception_message = "scheduler replay count field is malformed"
                raise RuntimeError(exception_message)
            return ReplayCountDecision(status="accepted_float", reason="", count=int(value))
        text_decision = exact_replay_text_decision(value)
        if text_decision.text:
            try:
                numeric = int(text_decision.text)
            except ValueError as exc:
                exception_message = "scheduler replay count field is malformed"
                raise RuntimeError(exception_message) from exc
            if numeric < 0:
                exception_message = "scheduler replay count field is malformed"
                raise RuntimeError(exception_message)
            return ReplayCountDecision(status="accepted_text", reason="", count=numeric)
        exception_message = "scheduler replay count field is malformed"
        raise RuntimeError(exception_message)
    return ReplayCountDecision(status="missing", reason="missing_replay_count", count=0)


def replay_count_value(result: Mapping[str, object] | None, *keys: str) -> int:
    return replay_count_value_decision(result, *keys).count


__all__ = (
    "ReplayCountDecision",
    "ReplayMappingItemsDecision",
    "ReplayTextDecision",
    "exact_replay_text",
    "exact_replay_text_decision",
    "first_replay_text",
    "is_replay_mapping",
    "replay_count_value",
    "replay_count_value_decision",
    "replay_mapping_items",
    "replay_mapping_items_decision",
    "replay_mapping_value",
)
