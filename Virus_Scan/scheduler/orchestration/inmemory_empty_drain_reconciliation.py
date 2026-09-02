"""Replayable empty-drain reconciliation gate decisions."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple


@dataclass(frozen=True, slots=True)
class EmptyDrainReconciliationDecision:
    """Typed decision for the empty-drain reconciliation gate."""

    should_reconcile: bool
    unsupported_fields: tuple[str, ...] = ()
    evidence: tuple[Mapping[str, object], ...] = ()
    replayable: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "unsupported_fields", immutable_tuple(self.unsupported_fields))
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))


def unsupported_empty_drain_reconciliation(fields: tuple[str, ...]) -> EmptyDrainReconciliationDecision:
    unsupported = tuple(field for field in fields if type(field) is str and field)
    evidence: tuple[Mapping[str, object], ...] = ()
    if unsupported:
        evidence = (
            MappingProxyType(
                {
                    "stage": "inmemory_empty_drain_reconciliation_gate",
                    "reason": "unsupported_empty_drain_state",
                    "unsupported_fields": unsupported,
                    "should_reconcile": False,
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_reproduce": True,
                }
            ),
        )
    return EmptyDrainReconciliationDecision(should_reconcile=False, unsupported_fields=unsupported, evidence=evidence)

