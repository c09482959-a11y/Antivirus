"""Typed support contracts for raw work execution boundaries."""
from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence

RawCallable: TypeAlias = Callable[..., object]
RawMappingItem: TypeAlias = tuple[object, object]
RawMappingItems: TypeAlias = tuple[RawMappingItem, ...]
RawEnvelopeResult: TypeAlias = dict[str, object]
RawBoundaryIssues: TypeAlias = dict[str, object]
RawCollectorResult: TypeAlias = dict[str, object]



def raw_envelope_failure_result(
    value: object, *, field_name: str, reason: str
) -> RawEnvelopeResult:
    """Build replayable raw-work boundary failure evidence."""
    evidence = unsupported_scheduler_value_evidence(value, field_name=field_name)
    evidence["raw_execution_failure_reason"] = reason
    return evidence


__all__ = (
    "RawBoundaryIssues",
    "RawCallable",
    "RawCollectorResult",
    "RawEnvelopeResult",
    "RawMappingItem",
    "RawMappingItems",
    "raw_envelope_failure_result",
)
