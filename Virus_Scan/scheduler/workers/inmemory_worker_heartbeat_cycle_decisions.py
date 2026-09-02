"""Replayable no-hook decisions for in-memory worker heartbeat projections."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_value_snapshot


@dataclass(frozen=True, slots=True)
class WorkerHeartbeatMappingDecision:
    """Replayable no-hook decision for heartbeat mapping projections."""

    accepted: bool
    reason: str
    items: tuple[tuple[object, object], ...] = ()
    config: Mapping[str, object] = field(default_factory=dict)
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        object.__setattr__(self, "config", immutable_mapping(self.config))
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))


def heartbeat_active_items_decision(active: object) -> WorkerHeartbeatMappingDecision:
    items = no_hook_mapping_items(active)
    if items is None:
        reason = "worker_heartbeat_active_not_mapping"
        return WorkerHeartbeatMappingDecision(False, reason, evidence=(immutable_mapping({
            "worker_heartbeat_mapping_failure": reason,
            "field": "active_workers",
            "value": scheduler_value_snapshot(active, field_name="active_workers"),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }),))
    return WorkerHeartbeatMappingDecision(True, "", items=items)


def heartbeat_cfg_decision(cfg: object) -> WorkerHeartbeatMappingDecision:
    items = no_hook_mapping_items(cfg)
    if items is None:
        reason = "worker_heartbeat_config_not_mapping"
        return WorkerHeartbeatMappingDecision(False, reason, evidence=(immutable_mapping({
            "worker_heartbeat_mapping_failure": reason,
            "field": "heartbeat_config",
            "value": scheduler_value_snapshot(cfg, field_name="heartbeat_config"),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }),))
    return WorkerHeartbeatMappingDecision(True, "", config=scheduler_str_key_mapping_from_items(items))


__all__ = ("WorkerHeartbeatMappingDecision", "heartbeat_active_items_decision", "heartbeat_cfg_decision")
