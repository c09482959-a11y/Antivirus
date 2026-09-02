"""No-hook timeout-configuration evidence attachment for in-memory jobs."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_output_support import (
    FrozenSchedulerMapping,
    unsupported_scheduler_value_evidence,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping



def _evidence_records(evidence_records: object) -> tuple[FrozenSchedulerMapping, ...]:
    if evidence_records is None:
        return timeout_config_evidence_records_decision(evidence_records).as_tuple()
    if type(evidence_records) not in {tuple, list}:
        return (immutable_mapping(unsupported_scheduler_value_evidence(evidence_records, field_name="timeout_config_evidence_records")),)
    snapshots: list[FrozenSchedulerMapping] = []
    for index, record in enumerate(evidence_records):
        snapshot = immutable_mapping(record)
        if type(snapshot) is FrozenSchedulerMapping:
            snapshots.append(snapshot)
        else:
            snapshots.append(
                immutable_mapping(
                    unsupported_scheduler_value_evidence(
                        record,
                        field_name=str.__add__("timeout_config_evidence_", int.__str__(index)),
                    )
                )
            )
    return tuple(snapshots)


def _existing_tuple(value: object, *, field_name: str) -> tuple[object, ...]:
    if value is None:
        return existing_timeout_config_tuple_decision(value, field_name=field_name).as_tuple()
    if type(value) is tuple:
        return value
    if type(value) is list:
        return tuple(value)
    return (immutable_mapping(unsupported_scheduler_value_evidence(value, field_name=field_name)),)


def _evidence_reason(evidence: FrozenSchedulerMapping) -> str:
    try:
        setting = evidence["setting"]
    except KeyError:
        return "inmemory_timeout_config"
    if type(setting) is str and setting:
        return str.__str__(setting)
    return "inmemory_timeout_config"


def _history_entries(immutable_evidence: tuple[FrozenSchedulerMapping, ...]) -> tuple[FrozenSchedulerMapping, ...]:
    entries: list[FrozenSchedulerMapping] = []
    for evidence in immutable_evidence:
        entry = immutable_mapping(
            {
                "reason": _evidence_reason(evidence),
                "action": "timeout_config_evidence",
                "timeout_config_evidence": evidence,
            }
        )
        if type(entry) is FrozenSchedulerMapping:
            entries.append(entry)
    return tuple(entries)


def attach_timeout_config_evidence_to_job_records(job_records: object, evidence_records: object) -> None:
    """Attach immutable timeout evidence to exact in-memory job records.

    The job registry is scheduler-owned and currently represented as an exact
    ``dict`` of exact mutable job-record dictionaries.  Unknown mapping-like or
    iterable objects are rejected before their ``items``, ``__iter__``, boolean,
    string, numeric, or representation hooks can execute.
    """


    immutable_evidence = _evidence_records(evidence_records)
    if len(immutable_evidence) == 0:
        return
    if type(job_records) is not dict:
        return
    history_entries = _history_entries(immutable_evidence)
    for _job_id, record in dict.items(job_records):
        if type(record) is not dict:
            continue
        existing_evidence = _existing_tuple(
            dict.get(record, "timeout_config_evidence"),
            field_name="existing_timeout_config_evidence",
        )
        record["timeout_config_evidence"] = existing_evidence + immutable_evidence
        record["timeout_config_evidence_recorded"] = True
        existing_history = _existing_tuple(dict.get(record, "history"), field_name="existing_job_history")
        record["history"] = existing_history + history_entries


__all__ = (
    "ExistingTimeoutConfigTupleDecision",
    "TimeoutConfigEvidenceRecordsDecision",
    "attach_timeout_config_evidence_to_job_records",
    "existing_timeout_config_tuple_decision",
    "timeout_config_evidence_records_decision",
)


class TimeoutConfigEvidenceRecordsDecision:
    """Replayable decision for timeout-config evidence-record projections."""

    __slots__ = ("accepted", "reason", "records", "value_type")

    def __init__(self, *, accepted: bool, reason: str, value_type: str, records: tuple[FrozenSchedulerMapping, ...] = ()) -> None:
        self.accepted = bool(accepted)
        self.reason = str.__str__(reason) if type(reason) is str else "timeout_config_evidence_records_decision"
        self.value_type = str.__str__(value_type) if type(value_type) is str else "unknown"
        self.records = tuple(records)

    def as_tuple(self) -> tuple[FrozenSchedulerMapping, ...]:
        """Return the tuple projection used by callers."""
        return self.records


class ExistingTimeoutConfigTupleDecision:
    """Replayable decision for existing timeout-config tuple projections."""

    __slots__ = ("accepted", "field_name", "items", "reason", "value_type")

    def __init__(self, *, accepted: bool, reason: str, field_name: str, value_type: str, items: tuple[object, ...] = ()) -> None:
        self.accepted = bool(accepted)
        self.reason = str.__str__(reason) if type(reason) is str else "existing_timeout_config_tuple_decision"
        self.field_name = str.__str__(field_name) if type(field_name) is str else "timeout_config_existing_tuple"
        self.value_type = str.__str__(value_type) if type(value_type) is str else "unknown"
        self.items = tuple(items)

    def as_tuple(self) -> tuple[object, ...]:
        """Return the tuple projection used by callers."""
        return self.items


def timeout_config_evidence_records_decision(evidence_records: object) -> TimeoutConfigEvidenceRecordsDecision:
    """Return a replayable decision for timeout-config evidence records."""
    if evidence_records is None:
        return TimeoutConfigEvidenceRecordsDecision(
            accepted=True,
            reason="timeout_config_evidence_records_missing",
            value_type="NoneType",
        )
    snapshot = _evidence_records(evidence_records)
    return TimeoutConfigEvidenceRecordsDecision(
        accepted=True,
        reason="timeout_config_evidence_records_materialized",
        value_type=type(evidence_records).__name__,
        records=snapshot,
    )


def existing_timeout_config_tuple_decision(value: object, *, field_name: str) -> ExistingTimeoutConfigTupleDecision:
    """Return a replayable decision for existing tuple/list timeout evidence fields."""
    if value is None:
        return ExistingTimeoutConfigTupleDecision(
            accepted=True,
            reason="existing_timeout_config_tuple_missing",
            field_name=field_name,
            value_type="NoneType",
        )
    if type(value) is tuple:
        return ExistingTimeoutConfigTupleDecision(
            accepted=True,
            reason="existing_timeout_config_tuple_materialized",
            field_name=field_name,
            value_type="tuple",
            items=value,
        )
    if type(value) is list:
        return ExistingTimeoutConfigTupleDecision(
            accepted=True,
            reason="existing_timeout_config_list_materialized",
            field_name=field_name,
            value_type="list",
            items=tuple(value),
        )
    return ExistingTimeoutConfigTupleDecision(
        accepted=False,
        reason="existing_timeout_config_tuple_rejected",
        field_name=field_name,
        value_type=type(value).__name__,
        items=(immutable_mapping(unsupported_scheduler_value_evidence(value, field_name=field_name)),),
    )
