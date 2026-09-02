"""Replayable typed decisions for in-memory file-scan worker support."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text


@dataclass(frozen=True)
class InMemoryWorkerConfigDecision:
    snapshot: dict[object, object] | None
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class InMemoryWorkerTextDecision:
    text: str
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


def inmemory_worker_config_decision(cfg: object) -> InMemoryWorkerConfigDecision:
    if cfg is None:
        return InMemoryWorkerConfigDecision(
            snapshot={},
            accepted=True,
            reason="missing_config_empty_snapshot",
            evidence=scheduler_evidence_pairs(
                ("decision", "inmemory_worker_config"),
                ("accepted", True),
                ("reason", "missing_config_empty_snapshot"),
                ("value_type", "NoneType"),
                ("item_count", 0),
            ),
        )
    items = no_hook_mapping_items(cfg)
    if items is None:
        frozen_decision = frozen_scheduler_items_decision(cfg)
        if frozen_decision.accepted:
            items = frozen_decision.items
    if items is None:
        reason = "inmemory_worker_config_rejected"
        return InMemoryWorkerConfigDecision(
            snapshot=None,
            accepted=False,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "inmemory_worker_config"),
                ("accepted", False),
                ("reason", reason),
                ("value_type", no_hook_type_name(cfg)),
            ),
        )
    snapshot = scheduler_str_key_mapping_from_items(items)
    return InMemoryWorkerConfigDecision(
        snapshot=snapshot,
        accepted=True,
        reason="accepted_inmemory_worker_config",
        evidence=scheduler_evidence_pairs(
            ("decision", "inmemory_worker_config"),
            ("accepted", True),
            ("reason", "accepted_inmemory_worker_config"),
            ("value_type", no_hook_type_name(cfg)),
            ("item_count", len(snapshot)),
        ),
    )


def inmemory_worker_text_decision(value: object) -> InMemoryWorkerTextDecision:
    text, reason = scheduler_text(value, replacement_text="")
    accepted = reason == "" and text != ""
    decision_reason = "accepted_inmemory_worker_text" if accepted else reason or "empty_inmemory_worker_text"
    return InMemoryWorkerTextDecision(
        text=text if accepted else str.__str__(""),
        accepted=accepted,
        reason=decision_reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "inmemory_worker_text"),
            ("accepted", accepted),
            ("reason", decision_reason),
            ("value_type", no_hook_type_name(value)),
        ),
    )


__all__ = (
    "InMemoryWorkerConfigDecision",
    "InMemoryWorkerTextDecision",
    "inmemory_worker_config_decision",
    "inmemory_worker_text_decision",
)
