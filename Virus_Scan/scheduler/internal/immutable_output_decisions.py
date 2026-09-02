"""Typed decisions for scheduler immutable-output boundary projections."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrozenSchedulerItemsDecision:
    """Replayable decision for exact FrozenSchedulerMapping item access."""

    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[str, object], ...] = ()


@dataclass(frozen=True)
class FrozenSchedulerEqualityDecision:
    """Replayable decision for FrozenSchedulerMapping equality projection."""

    equal: bool
    reason: str
    compared_type: str


@dataclass(frozen=True)
class TuplePairItemsDecision:
    """Replayable decision for tuple-backed pair materialization."""

    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[object, object], ...] = ()
    failed_index: int = -1


@dataclass(frozen=True)
class ImmutableTupleDecision:
    """Replayable decision for scheduler tuple immutability projection."""

    accepted: bool
    reason: str
    value_type: str
    items: tuple[object, ...] = ()
    evidence: object = None


@dataclass(frozen=True)
class SchedulerMappingMaterializationDecision:
    """Replayable decision for scheduler mapping materialization."""

    accepted: bool
    reason: str
    value_type: str
    value: object = None
    evidence: object = None


def frozen_items_available(items: tuple[tuple[str, object], ...]) -> FrozenSchedulerItemsDecision:
    return FrozenSchedulerItemsDecision(
        accepted=True,
        reason="frozen_scheduler_items_available",
        value_type="FrozenSchedulerMapping",
        items=items,
    )


def frozen_items_rejected(reason: str, value_type: str) -> FrozenSchedulerItemsDecision:
    return FrozenSchedulerItemsDecision(accepted=False, reason=reason, value_type=value_type)


def frozen_mapping_equality(*, equal: bool, reason: str, compared_type: str) -> FrozenSchedulerEqualityDecision:
    return FrozenSchedulerEqualityDecision(equal=equal, reason=reason, compared_type=compared_type)

def tuple_pair_items_available(
    items: tuple[tuple[object, object], ...],
    value_type: str,
) -> TuplePairItemsDecision:
    return TuplePairItemsDecision(
        accepted=True,
        reason="tuple_pair_items_available",
        value_type=value_type,
        items=items,
    )


def tuple_pair_items_rejected(
    reason: str,
    value_type: str,
    *,
    failed_index: int,
) -> TuplePairItemsDecision:
    return TuplePairItemsDecision(
        accepted=False,
        reason=reason,
        value_type=value_type,
        failed_index=failed_index,
    )


def immutable_tuple_available(
    items: tuple[object, ...],
    value_type: str,
    *,
    reason: str = "immutable_tuple_available",
    evidence: object = None,
) -> ImmutableTupleDecision:
    return ImmutableTupleDecision(
        accepted=True,
        reason=reason,
        value_type=value_type,
        items=items,
        evidence=evidence,
    )


def immutable_tuple_rejected(
    reason: str,
    value_type: str,
    *,
    evidence: object,
) -> ImmutableTupleDecision:
    return ImmutableTupleDecision(
        accepted=False,
        reason=reason,
        value_type=value_type,
        evidence=evidence,
    )


def scheduler_mapping_materialized(
    value: object,
    value_type: str,
    *,
    reason: str = "scheduler_mapping_materialized",
    evidence: object = None,
) -> SchedulerMappingMaterializationDecision:
    return SchedulerMappingMaterializationDecision(
        accepted=True,
        reason=reason,
        value_type=value_type,
        value=value,
        evidence=evidence,
    )


def scheduler_mapping_materialization_rejected(
    reason: str,
    value_type: str,
    *,
    value: object,
    evidence: object,
) -> SchedulerMappingMaterializationDecision:
    return SchedulerMappingMaterializationDecision(
        accepted=False,
        reason=reason,
        value_type=value_type,
        value=value,
        evidence=evidence,
    )

