"""Immutable runtime events used to coordinate adaptive subsystems.

Stage 28 constrains mutation by making cross-domain communication append-only and
immutable.  Mutable queues/caches still exist inside their owners, but external
coordination should flow through these events rather than arbitrary shared-state
writes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping
import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.runtime.governance_inputs import (
    runtime_float,
    runtime_int,
    runtime_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value


class RuntimeEventSeverity(str, Enum):
    DEBUG = "debug"
    OPERATIONAL = "operational"
    ANOMALY = "anomaly"
    SECURITY = "security"
    CRITICAL = "critical"


class RuntimeEventType(str, Enum):
    STATE_MUTATION = "state_mutation"
    CONFIG_SNAPSHOT = "config_snapshot"
    SCHEDULER_PRESSURE = "scheduler_pressure"
    QUEUE_DEBT = "queue_debt"
    TELEMETRY_BUDGET = "telemetry_budget"
    REPLAY_BUDGET = "replay_budget"
    GOVERNANCE_ABORT = "governance_abort"
    FAILURE_DOMAIN = "failure_domain"


@dataclass(frozen=True)
class RuntimeEvent:
    event_type: RuntimeEventType | str
    domain: str
    message: str
    severity: RuntimeEventSeverity | str = RuntimeEventSeverity.OPERATIONAL
    timestamp: float = field(default_factory=time.time)
    generation: int = 0
    fields: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not RuntimeEvent:
            exception_message = "runtime event owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[Mapping[str, object], ...] = ()
        event_type_value = (
            self.event_type.value
            if type(self.event_type) is RuntimeEventType
            else self.event_type
        )
        event_type, issues = runtime_text(
            event_type_value,
            field_name="runtime_event_type",
            default="input_rejected",
        )
        evidence += issues
        domain, issues = runtime_text(
            self.domain, field_name="runtime_event_domain", default="runtime"
        )
        evidence += issues
        message, issues = runtime_text(
            self.message,
            field_name="runtime_event_message",
            default="runtime_input_rejected",
        )
        evidence += issues
        severity_value = (
            self.severity.value
            if type(self.severity) is RuntimeEventSeverity
            else self.severity
        )
        severity, issues = runtime_text(
            severity_value,
            field_name="runtime_event_severity",
            default=RuntimeEventSeverity.ANOMALY.value,
        )
        evidence += issues
        timestamp, issues = runtime_float(
            self.timestamp,
            field_name="runtime_event_timestamp",
            minimum=0.0,
        )
        evidence += issues
        generation, issues = runtime_int(
            self.generation,
            field_name="runtime_event_generation",
            default=0,
        )
        evidence += issues
        frozen_fields = freeze_runtime_value(
            {} if self.fields is None else self.fields
        )
        if evidence:
            items = no_hook_mapping_items(frozen_fields)
            fields = dict(items) if items is not None else {"fields": frozen_fields}
            fields["input_evidence"] = evidence
            frozen_fields = freeze_runtime_value(fields)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "fields", frozen_fields)

    def as_dict(self) -> dict[str, object]:
        return {
            "event_type": self.event_type,
            "domain": self.domain,
            "message": self.message,
            "severity": self.severity,
            "timestamp": round(self.timestamp, 6),
            "generation": self.generation,
            "fields": materialize_runtime_value(self.fields),
        }


__all__ = ("RuntimeEvent", "RuntimeEventSeverity", "RuntimeEventType")
