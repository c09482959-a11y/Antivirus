"""Replayable timeout sweep record value decisions."""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr


@dataclass(frozen=True, slots=True)
class TimeoutRecordValueDecision:
    value: object
    reason: str
    field: str
    found: bool
    source_is_mapping: bool

    def as_value(self) -> object:
        return self.value


@dataclass(frozen=True, slots=True)
class TimeoutSharedHeartbeatValueDecision:
    value: object
    reason: str
    field: str
    found: bool
    source_supported: bool

    def as_value(self) -> object:
        return self.value


def timeout_record_value_decision(record: object, field: str) -> TimeoutRecordValueDecision:
    if type(record) is not dict:
        return TimeoutRecordValueDecision(None, "unsupported_timeout_record_mapping", field, found=False, source_is_mapping=False)
    if dict.__contains__(record, field):
        return TimeoutRecordValueDecision(dict.__getitem__(record, field), "timeout_record_field_present", field, found=True, source_is_mapping=True)
    return TimeoutRecordValueDecision(None, "timeout_record_field_absent", field, found=False, source_is_mapping=True)



def _shared_mapping_decision(source: object, field: str, reason: str) -> TimeoutSharedHeartbeatValueDecision:
    decision = timeout_record_value_decision(source, field)
    if decision.source_is_mapping:
        return TimeoutSharedHeartbeatValueDecision(decision.value, reason if not decision.found else "shared_heartbeat_field_present", field, decision.found, source_supported=True)
    return TimeoutSharedHeartbeatValueDecision(None, reason, field, found=False, source_supported=False)


def timeout_shared_heartbeat_value_decision(shared_heartbeat_result: object, field: str) -> TimeoutSharedHeartbeatValueDecision:
    if type(shared_heartbeat_result) is SimpleNamespace:
        namespace_state = scheduler_exact_attr(shared_heartbeat_result, "__dict__", owner_type=SimpleNamespace, default={})
        return _shared_mapping_decision(namespace_state, field, "shared_heartbeat_field_absent")
    state = no_hook_plain_instance_dict(shared_heartbeat_result)
    if state is not None:
        return _shared_mapping_decision(state, field, "shared_heartbeat_field_absent")
    if type(shared_heartbeat_result) is dict:
        return _shared_mapping_decision(shared_heartbeat_result, field, "shared_heartbeat_field_absent")
    return TimeoutSharedHeartbeatValueDecision(None, "unsupported_shared_heartbeat_result", field, found=False, source_supported=False)


__all__ = (
    "TimeoutRecordValueDecision",
    "TimeoutSharedHeartbeatValueDecision",
    "timeout_record_value_decision",
    "timeout_shared_heartbeat_value_decision",
)
