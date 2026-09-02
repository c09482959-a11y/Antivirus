"""Adaptive telemetry governance with bounded no-hook evidence."""
from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Mapping
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_json_key
from Virus_Scan.runtime.governance_inputs import (
    runtime_float,
    runtime_int,
    runtime_mapping,
    runtime_text,
)
from Virus_Scan.runtime.immutable_core import (
    freeze_runtime_value,
    materialize_runtime_value,
)


SEVERITY_RANK = MappingProxyType(
    {
        "debug": 0,
        "info": 1,
        "operational": 2,
        "anomaly": 3,
        "security": 4,
        "critical": 5,
    }
)


def _telemetry_indexed(prefix: str, index: int) -> str:
    if type(index) is int and type(index) is not bool:
        return prefix + "_" + int.__str__(index)
    return prefix + "_index"


def _append_telemetry_evidence(
    evidence: tuple[Mapping[str, object], ...],
    issues: tuple[Mapping[str, object], ...],
) -> tuple[Mapping[str, object], ...]:
    if issues == ():
        return evidence
    return evidence + issues


@dataclass
class TelemetryBudget:
    max_events_per_key: int = 8
    max_events_total: int = 512
    burst_window_sec: float = 10.0
    counters: dict[str, dict[str, object]] = field(default_factory=dict)
    total: int = 0
    suppressed_total: int = 0
    input_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) not in (TelemetryBudget, WorkloadTelemetryBudget):
            exception_message = "telemetry budget owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[Mapping[str, object], ...] = ()
        self.max_events_per_key, issues = runtime_int(
            self.max_events_per_key,
            field_name="telemetry_max_events_per_key",
            default=8,
        )
        evidence = _append_telemetry_evidence(evidence, issues)
        self.max_events_total, issues = runtime_int(
            self.max_events_total,
            field_name="telemetry_max_events_total",
            default=512,
        )
        evidence = _append_telemetry_evidence(evidence, issues)
        self.burst_window_sec, issues = runtime_float(
            self.burst_window_sec,
            field_name="telemetry_burst_window_sec",
            default=10.0,
            minimum=0.0,
        )
        evidence = _append_telemetry_evidence(evidence, issues)
        self.max_events_per_key = max(1, self.max_events_per_key)
        self.max_events_total = max(1, self.max_events_total)
        if type(self.counters) is not dict:
            evidence += (
                {
                    "runtime_input_rejected": True,
                    "field_name": "telemetry_counters",
                    "reason": "telemetry_counter_owner_rejected",
                },
            )
            self.counters = {}
        self.input_evidence = evidence

    def _rejection(
        self, key: str, severity: str, evidence: tuple[Mapping[str, object], ...]
    ) -> dict[str, object]:
        self.input_evidence = _append_telemetry_evidence(self.input_evidence, evidence)
        return {
            "key": key,
            "severity": severity,
            "count": 0,
            "suppressed": 0,
            "runtime_input_rejected": True,
            "input_evidence": materialize_runtime_value(
                freeze_runtime_value(evidence)
            ),
        }

    def record(
        self,
        key: str,
        *,
        severity: str = "operational",
        payload: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        key_text, key_issues = runtime_text(
            key, field_name="telemetry_key", default="input_rejected"
        )
        severity_text, severity_issues = runtime_text(
            severity,
            field_name="telemetry_severity",
            default="anomaly",
        )
        severity_text = severity_text.lower()
        input_evidence = key_issues + severity_issues
        payload_state, payload_issues = runtime_mapping(
            payload, field_name="telemetry_payload"
        )
        input_evidence += payload_issues
        if input_evidence:
            return self._rejection(
                key_text, severity_text, input_evidence
            )

        now = time.time()
        rec = self.counters.setdefault(
            key_text,
            {
                "count": 0,
                "first": now,
                "last": 0.0,
                "suppressed": 0,
                "severity": severity_text,
            },
        )
        if now - rec["first"] > self.burst_window_sec:
            rec.update(
                {
                    "count": 0,
                    "first": now,
                    "suppressed": 0,
                    "severity": severity_text,
                }
            )
        rec["count"] += 1
        rec["last"] = now
        previous_severity = rec["severity"]
        rec["severity"] = (
            severity_text
            if SEVERITY_RANK.get(severity_text, 2)
            >= SEVERITY_RANK.get(previous_severity, 2)
            else previous_severity
        )
        self.total += 1
        critical = (
            SEVERITY_RANK.get(severity_text, 2)
            >= SEVERITY_RANK["critical"]
        )
        if (
            rec["count"] > self.max_events_per_key
            or self.total > self.max_events_total
        ) and not critical:
            rec["suppressed"] += 1
            self.suppressed_total += 1
            return None
        out: dict[str, object] = {
            "key": key_text,
            "severity": severity_text,
            "count": rec["count"],
            "suppressed": rec["suppressed"],
        }
        if payload_state and critical:
            out["payload"] = materialize_runtime_value(
                freeze_runtime_value(payload_state)
            )
        elif payload_state:
            payload_keys: list[str] = []
            for index, payload_key in enumerate(dict.keys(payload_state)):
                text, reason = no_hook_json_key(
                    payload_key, index, prefix="telemetry_payload_key"
                )
                payload_keys.append(text if not reason else _telemetry_indexed("rejected", index))
            out["payload_keys"] = sorted(payload_keys)[:16]
        return out

    def summary(self) -> dict[str, object]:
        top = [
            {
                "key": key,
                "count": row["count"],
                "suppressed": row["suppressed"],
                "severity": row["severity"],
            }
            for key, row in dict.items(self.counters)
        ]
        top.sort(
            key=lambda row: (
                -row["suppressed"],
                -row["count"],
                row["key"],
            )
        )
        out = {
            "total": self.total,
            "suppressed_total": self.suppressed_total,
            "unique_keys": len(self.counters),
            "top": top[:16],
        }
        if self.input_evidence:
            out["input_evidence"] = materialize_runtime_value(
                freeze_runtime_value(self.input_evidence)
            )
        return out


@dataclass
class WorkloadTelemetryBudget(TelemetryBudget):
    workload_id: str = "global"
    max_replay_traces: int = 64
    max_governance_emissions: int = 128
    replay_traces: int = 0
    governance_emissions: int = 0

    def __post_init__(self) -> None:
        if type(self) is not WorkloadTelemetryBudget:
            exception_message = "workload telemetry budget owner rejected"
            raise TypeError(exception_message)
        super().__post_init__()
        self.workload_id, issues = runtime_text(
            self.workload_id,
            field_name="telemetry_workload_id",
            default="input_rejected",
        )
        self.input_evidence = _append_telemetry_evidence(self.input_evidence, issues)
        self.max_replay_traces, issues = runtime_int(
            self.max_replay_traces,
            field_name="telemetry_max_replay_traces",
            default=64,
        )
        self.input_evidence = _append_telemetry_evidence(self.input_evidence, issues)
        self.max_governance_emissions, issues = runtime_int(
            self.max_governance_emissions,
            field_name="telemetry_max_governance_emissions",
            default=128,
        )
        self.input_evidence = _append_telemetry_evidence(self.input_evidence, issues)
        self.max_replay_traces = max(1, self.max_replay_traces)
        self.max_governance_emissions = max(
            1, self.max_governance_emissions
        )

    def record_replay_trace(
        self, key: str, payload: dict[str, object] | None = None
    ) -> dict[str, object] | None:
        self.replay_traces += 1
        if self.replay_traces > self.max_replay_traces:
            self.suppressed_total += 1
            return None
        key_text, issues = runtime_text(
            key, field_name="telemetry_replay_key", default="input_rejected"
        )
        if issues:
            return self._rejection(key_text, "operational", issues)
        return self.record(
            "replay:" + key_text, severity="operational", payload=payload
        )

    def record_governance(
        self,
        key: str,
        *,
        severity: str = "operational",
        payload: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        key_text, key_issues = runtime_text(
            key,
            field_name="telemetry_governance_key",
            default="input_rejected",
        )
        severity_text, severity_issues = runtime_text(
            severity,
            field_name="telemetry_governance_severity",
            default="anomaly",
        )
        issues = key_issues + severity_issues
        if issues:
            return self._rejection(key_text, severity_text, issues)
        self.governance_emissions += 1
        if (
            self.governance_emissions > self.max_governance_emissions
            and SEVERITY_RANK.get(severity_text, 2)
            < SEVERITY_RANK["critical"]
        ):
            self.suppressed_total += 1
            return None
        return self.record(
            "governance:" + key_text,
            severity=severity_text,
            payload=payload,
        )


__all__ = ("SEVERITY_RANK", "TelemetryBudget", "WorkloadTelemetryBudget")
