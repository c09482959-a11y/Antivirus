"""Replayable decisions for hybrid queue replay snapshots."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, TYPE_CHECKING, NoReturn

from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.scheduler.api.contracts import HybridQueueStateError
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision

if TYPE_CHECKING:
    from pathlib import Path

_EMPTY_HYBRID_COUNT_ITEMS: tuple[tuple[object, object], ...] = ()
_NO_HYBRID_SNAPSHOT: Mapping[str, object] | None = None
_INVALID_HYBRID_QUEUE_COUNT_VALUE = "invalid hybrid queue count value"


def _raise_invalid_hybrid_queue_count_value() -> NoReturn:
    raise HybridQueueStateError(_INVALID_HYBRID_QUEUE_COUNT_VALUE)


@dataclass(frozen=True)
class HybridCountValueDecision:
    """Replayable decision for one hybrid queue count value."""

    value: int
    reason: str
    accepted: bool
    missing: bool = False


@dataclass(frozen=True)
class HybridCountsItemsDecision:
    """Replayable decision for hybrid queue count item materialization."""

    items: tuple[tuple[object, object], ...]
    reason: str
    accepted: bool
    missing: bool = False


@dataclass(frozen=True)
class HybridSnapshotReadDecision:
    """Replayable decision for hybrid queue snapshot availability."""

    snapshot: Mapping[str, object] | None
    reason: str
    available: bool
    path: Path


def hybrid_count_value_decision(value: object) -> HybridCountValueDecision:
    if value is None:
        return HybridCountValueDecision(
            value=0,
            reason="hybrid_queue_count_value_missing",
            accepted=False,
            missing=True,
        )
    if type(value) is bool:
        _raise_invalid_hybrid_queue_count_value()
    if type(value) is int:
        if value < 0:
            _raise_invalid_hybrid_queue_count_value()
        return HybridCountValueDecision(
            value=value,
            reason="hybrid_queue_count_value_integer",
            accepted=True,
        )
    if type(value) is float:
        metric = exact_finite_float_or_none(value)
        if metric is not None and metric >= 0 and metric.is_integer():
            return HybridCountValueDecision(
                value=int(metric),
                reason="hybrid_queue_count_value_float_integer",
                accepted=True,
            )
        exception_message = "invalid hybrid queue count value"
        raise HybridQueueStateError(exception_message)
    text, reason = no_hook_text(
        value,
        missing_reason="missing_hybrid_queue_count_value",
        unsupported_reason="invalid_hybrid_queue_count_value",
    )
    if reason == "" and text:
        try:
            numeric = int(text)
        except ValueError as exc:
            exception_message = "invalid hybrid queue count value"
            raise HybridQueueStateError(exception_message) from exc
        if numeric < 0:
            exception_message = "invalid hybrid queue count value"
            raise HybridQueueStateError(exception_message)
        return HybridCountValueDecision(
            value=numeric,
            reason="hybrid_queue_count_value_text_integer",
            accepted=True,
        )
    exception_message = "invalid hybrid queue count value"
    raise HybridQueueStateError(exception_message)


def hybrid_counts_items_decision(counts: Mapping[str, object] | None) -> HybridCountsItemsDecision:
    if counts is None:
        return HybridCountsItemsDecision(
            items=_EMPTY_HYBRID_COUNT_ITEMS,
            reason="hybrid_queue_count_mapping_missing",
            accepted=False,
            missing=True,
        )
    frozen_decision = frozen_scheduler_items_decision(counts)
    if frozen_decision.accepted:
        return HybridCountsItemsDecision(
            items=frozen_decision.items,
            reason="hybrid_queue_count_mapping_frozen",
            accepted=True,
        )
    items = no_hook_mapping_items(counts)
    if items is None:
        exception_message = "invalid hybrid queue count mapping"
        raise HybridQueueStateError(exception_message)
    return HybridCountsItemsDecision(
        items=items,
        reason="hybrid_queue_count_mapping_materialized",
        accepted=True,
    )


def hybrid_snapshot_read_missing_decision(path: Path) -> HybridSnapshotReadDecision:
    return HybridSnapshotReadDecision(
        snapshot=_NO_HYBRID_SNAPSHOT,
        reason="hybrid_queue_state_file_missing",
        available=False,
        path=path,
    )


__all__ = (
    "HybridCountValueDecision",
    "HybridCountsItemsDecision",
    "HybridSnapshotReadDecision",
    "hybrid_count_value_decision",
    "hybrid_counts_items_decision",
    "hybrid_snapshot_read_missing_decision",
)
