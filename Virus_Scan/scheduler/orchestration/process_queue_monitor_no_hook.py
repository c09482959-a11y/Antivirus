"""No-hook helpers for process-queue monitor orchestration contracts."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value, scheduler_mapping_items_tuple, scheduler_str_key_mapping_from_items
from dataclasses import dataclass
from typing import Mapping, TypeAlias

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.immutable_output_support import (
    frozen_scheduler_items_decision,
    unsupported_scheduler_value_evidence,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int, scheduler_text
from Virus_Scan.scheduler.orchestration.progress_state_freezing import freeze_scheduler_progress_state

MonitorValue: TypeAlias = object
MonitorItems: TypeAlias = tuple[tuple[object, object], ...]
MonitorFrozenValues: TypeAlias = tuple[object, ...]
MonitorFeedCountsResult: TypeAlias = tuple[int, int, int, int, int, object]

@dataclass(frozen=True)
class MonitorMappingDecision:
    accepted: bool
    items: MonitorItems
    reason: str


@dataclass(frozen=True)
class MonitorPressureDecision:
    available: bool
    pressure: bool
    reason: str

def monitor_int(value: MonitorValue, *, default: int = 0, minimum: int | None = None, reason: str) -> int:
    parsed, _issue = scheduler_int(value, default=default, minimum=minimum, reason=reason)
    return parsed


def monitor_float(value: MonitorValue, *, default: float = 0.0, minimum: float | None = None, reason: str) -> float:
    parsed, _issue = scheduler_float(value, default=default, minimum=minimum, reason=reason)
    return parsed


def monitor_optional_float(value: MonitorValue, *, default: float | None = None,
                           minimum: float | None = None, reason: str) -> float | None:
    if value is None:
        return default
    parsed, _issue = scheduler_float(value, default=0.0 if default is None else default, minimum=minimum, reason=reason)
    return parsed


def monitor_bool(value: MonitorValue, *, default: bool = False, reason: str) -> bool:
    parsed, _issue = scheduler_bool(value, default=default, reason=reason)
    return parsed


def monitor_queue_identities(values: MonitorValue) -> frozenset[str]:
    frozen: set[str] = set()
    for index, item in enumerate(no_hook_sequence_items(values)):
        text, issue = scheduler_text(item, unsupported_reason="process_queue_monitor_identity_rejected")
        if issue == "" and text:
            frozen.add(text)
            continue
        frozen.add("unsupported_queue_identity_" + int.__str__(index))
    return frozenset(frozen)


def monitor_recoverable_exceptions(values: MonitorValue) -> tuple[type[BaseException], ...]:
    return tuple(
        item
        for item in no_hook_sequence_items(values)
        if type(item) is type and issubclass(item, BaseException)
    )


def _monitor_mapping_decision(value: MonitorValue) -> MonitorMappingDecision:
    items = scheduler_mapping_items_tuple(value)
    if items is not None:
        return MonitorMappingDecision(True, items, "mapping_items")
    frozen_decision = frozen_scheduler_items_decision(value)
    if frozen_decision.accepted:
        return MonitorMappingDecision(True, tuple(frozen_decision.items), "frozen_scheduler_items")
    return MonitorMappingDecision(False, (), "process_queue_monitor_mapping_rejected")


def monitor_elastic_io_sample(value: MonitorValue) -> Mapping[str, object]:
    if value is None:
        return immutable_mapping()
    decision = _monitor_mapping_decision(value)
    if not decision.accepted:
        return immutable_mapping((
            ("pressure", False),
            ("scheduler_monitor_elastic_io_sample_unavailable", True),
            ("reason", "process_queue_monitor_elastic_io_sample_rejected"),
            ("evidence", unsupported_scheduler_value_evidence(value, field_name="elastic_io_sample")),
        ))
    return immutable_mapping(scheduler_str_key_mapping_from_items(decision.items))


def monitor_elastic_io_pressure(value: MonitorValue) -> bool:
    decision = _monitor_mapping_decision(value)
    if not decision.accepted:
        return False
    pressure = scheduler_mapping_item_value(decision.items, "pressure")
    if pressure is None:
        return False
    parsed, issue = scheduler_bool(
        pressure,
        default=False,
        reason="process_queue_monitor_io_pressure_rejected",
    )
    return parsed if issue == "" else False


monitor_immutable_value = freeze_scheduler_progress_state


def monitor_feed_counts(feed_counts: MonitorValue, *, file_done_count: int,
                        file_failed_count: int, file_active_count: int,
                        file_pending_count: int, raw_live: int,
                        default_counts: MonitorValue) -> MonitorFeedCountsResult:
    if feed_counts is None:
        return file_done_count, file_failed_count, file_active_count, file_pending_count, raw_live, default_counts
    decision = _monitor_mapping_decision(feed_counts)
    if not decision.accepted:
        return (
            file_done_count,
            file_failed_count,
            file_active_count,
            file_pending_count,
            raw_live,
            immutable_mapping((
                ("scheduler_monitor_feed_counts_unavailable", True),
                ("reason", "process_queue_monitor_feed_counts_rejected"),
                ("default_counts", immutable_value(default_counts)),
                ("evidence", unsupported_scheduler_value_evidence(feed_counts, field_name="process_queue_feed_counts")),
            )),
        )
    mapping = scheduler_str_key_mapping_from_items(decision.items)
    default_decision = _monitor_mapping_decision(default_counts)
    default_mapping = (
        scheduler_str_key_mapping_from_items(default_decision.items)
        if default_decision.accepted else {}
    )
    defaults = {
        "file_done": file_done_count,
        "file_failed": file_failed_count,
        "file_active": file_active_count,
        "file_pending": file_pending_count,
        "raw_pending": dict.get(default_mapping, "raw_pending", 0),
        "raw_active": dict.get(default_mapping, "raw_active", 0),
        "raw_done": dict.get(default_mapping, "raw_done", 0),
        "raw_failed": dict.get(default_mapping, "raw_failed", 0),
    }
    reasons = {
        key: "process_queue_monitor_" + key + "_rejected"
        for key in defaults
    }
    normalized: dict[str, int] = {}
    published: dict[str, object] = {}
    for key, default in defaults.items():
        value = dict.get(mapping, key)
        parsed, issue = scheduler_int(value, default=default, minimum=0, reason=reasons[key])
        normalized[key] = parsed
        published[key] = parsed if issue == "" else immutable_mapping((
            ("unsupported_scheduler_value", True), ("reason", issue),
            ("evidence", unsupported_scheduler_value_evidence(value, field_name=key)),
        ))
    return (normalized["file_done"], normalized["file_failed"],
            normalized["file_active"], normalized["file_pending"],
            normalized["raw_pending"] + normalized["raw_active"], immutable_mapping(published))


__all__ = (
    "MonitorMappingDecision",
    "MonitorPressureDecision",
    "monitor_bool",
    "monitor_elastic_io_pressure",
    "monitor_elastic_io_sample",
    "monitor_feed_counts",
    "monitor_float",
    "monitor_immutable_value",
    "monitor_int",
    "monitor_optional_float",
    "monitor_queue_identities",
    "monitor_recoverable_exceptions",
)
