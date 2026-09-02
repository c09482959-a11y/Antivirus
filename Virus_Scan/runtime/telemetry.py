"""Economically bounded runtime telemetry owned by RuntimeContext.

Stage 21 adds pressure-aware backpressure: telemetry samples adapt downward under
high event pressure, redundant noncritical events are coalesced, and all storage
is bounded so observability cannot destabilize scanning.
"""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from dataclasses import dataclass, field
from typing import NoReturn
from Virus_Scan.runtime.runtime_economics_ledger import get_runtime_economics_ledger
from Virus_Scan.contracts.env_config import float_env, int_env
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.runtime.immutable_core import materialize_runtime_value, freeze_runtime_value
import time


_RUNTIME_TELEMETRY_OWNER_REQUIRED = "runtime telemetry owner must be RuntimeTelemetry"


def _raise_runtime_telemetry_owner_required() -> NoReturn:
    raise TypeError(_RUNTIME_TELEMETRY_OWNER_REQUIRED)


def _telemetry_items(mapping: dict[str, object]) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(mapping)
    return items if items is not None else ()


@dataclass
class RuntimeTelemetry:
    counters: dict[str, int] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)
    events: list[dict[str, object]] = field(default_factory=list)
    max_events: int = field(default_factory=lambda: int_env("UMIGE_TELEMETRY_MAX_EVENTS", 250, 0))
    sample_every: int = field(default_factory=lambda: int_env("UMIGE_TELEMETRY_SAMPLE_EVERY", 5, 1))
    pressure_threshold: float = field(default_factory=lambda: float_env("UMIGE_TELEMETRY_PRESSURE_THRESHOLD", 0.80, 0.05, 1.0))
    critical_event_reserve: int = field(default_factory=lambda: int_env("UMIGE_TELEMETRY_CRITICAL_RESERVE", 25, 0))
    _event_seen: dict[str, int] = field(default_factory=dict)
    _coalesced: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not RuntimeTelemetry:
            _raise_runtime_telemetry_owner_required()
        for field_name, expected_type in (
            ("counters", dict),
            ("gauges", dict),
            ("events", list),
            ("_event_seen", dict),
            ("_coalesced", dict),
        ):
            if type(no_hook_exact_owner_field(self, RuntimeTelemetry, field_name)) is not expected_type:
                raise TypeError("runtime telemetry " + field_name + " owner rejected")
        max_events, max_events_reason = no_hook_exact_nonnegative_int(
            self.max_events,
            default=250,
            reason="runtime_telemetry_max_events_rejected",
            allow_exact_text=False,
        )
        sample_every, sample_reason = no_hook_exact_nonnegative_int(
            self.sample_every,
            default=5,
            reason="runtime_telemetry_sample_every_rejected",
            allow_exact_text=False,
        )
        reserve, reserve_reason = no_hook_exact_nonnegative_int(
            self.critical_event_reserve,
            default=25,
            reason="runtime_telemetry_critical_reserve_rejected",
            allow_exact_text=False,
        )
        threshold, threshold_reason = no_hook_finite_float(
            self.pressure_threshold,
            default=0.80,
            minimum=0.05,
            maximum=1.0,
            reason="runtime_telemetry_pressure_threshold_rejected",
            non_finite_reason="runtime_telemetry_pressure_threshold_rejected",
            allow_exact_text=False,
        )
        if (
            max_events_reason
            or sample_reason
            or reserve_reason
            or threshold_reason
            or sample_every < 1
        ):
            exception_message = "runtime telemetry configuration rejected"
            raise ValueError(exception_message)
        self.max_events = max_events
        self.sample_every = sample_every
        self.critical_event_reserve = reserve
        self.pressure_threshold = threshold
        for key, value in _telemetry_items(self.counters):
            count, count_reason = no_hook_exact_nonnegative_int(
                value,
                default=0,
                reason="runtime_telemetry_counter_value_rejected",
                allow_exact_text=False,
            )
            if type(key) is not str or key == "" or count_reason:
                exception_message = "runtime telemetry initial counter rejected"
                raise ValueError(exception_message)
            self.counters[key] = count
        for key, value in _telemetry_items(self.gauges):
            metric, metric_reason = no_hook_finite_float(
                value,
                default=0.0,
                reason="runtime_telemetry_gauge_value_rejected",
                non_finite_reason="runtime_telemetry_gauge_non_finite",
                allow_exact_text=False,
            )
            if type(key) is not str or key == "" or metric_reason:
                exception_message = "runtime telemetry initial gauge rejected"
                raise ValueError(exception_message)
            self.gauges[key] = metric
        detached_events = []
        for event in self.events:
            if type(event) is not dict:
                exception_message = "runtime telemetry initial event rejected"
                raise TypeError(exception_message)
            detached = materialize_runtime_value(freeze_runtime_value(event))
            if type(detached) is not dict:
                exception_message = "runtime telemetry initial event rejected"
                raise TypeError(exception_message)
            detached_events.append(detached)
        self.events = detached_events
        for counter in (self._event_seen, self._coalesced):
            for key, value in _telemetry_items(counter):
                if type(key) is not str or type(value) is not int or value < 0:
                    exception_message = "runtime telemetry internal counter rejected"
                    raise ValueError(exception_message)

    @property
    def pressure(self) -> float:
        if self.max_events <= 0:
            return 1.0
        return min(1.0, len(self.events) / float(max(1, self.max_events)))

    def incr(self, name: str, value: int = 1) -> None:
        key, key_reason = no_hook_text(
            name,
            missing_reason="runtime_telemetry_counter_name_missing",
            unsupported_reason="runtime_telemetry_counter_name_rejected",
        )
        increment, value_reason = no_hook_exact_nonnegative_int(
            value, default=0, reason="runtime_telemetry_counter_value_rejected"
        )
        if key_reason or key == "" or value_reason:
            record_suppressed_failure(
                "runtime_telemetry_counter_rejected",
                ValueError(key_reason or value_reason or "runtime_telemetry_counter_name_blank"),
                domain="telemetry",
            )
            return
        self.counters[key] = dict.get(self.counters, key, 0) + increment

    def gauge(self, name: str, value: float) -> None:
        key, key_reason = no_hook_text(
            name,
            missing_reason="runtime_telemetry_gauge_name_missing",
            unsupported_reason="runtime_telemetry_gauge_name_rejected",
        )
        metric, value_reason = no_hook_finite_float(
            value,
            default=0.0,
            reason="runtime_telemetry_gauge_value_rejected",
            non_finite_reason="runtime_telemetry_gauge_non_finite",
        )
        if key_reason or key == "" or value_reason:
            record_suppressed_failure(
                "runtime_telemetry_gauge_rejected",
                ValueError(key_reason or value_reason or "runtime_telemetry_gauge_name_blank"),
                domain="telemetry",
            )
            return
        self.gauges[key] = metric

    def _effective_sample_every(self, important: bool) -> int:
        if important:
            return max(1, self.sample_every // 2)
        if self.pressure >= self.pressure_threshold:
            return max(self.sample_every * 4, 20)
        if self.pressure >= self.pressure_threshold * 0.75:
            return max(self.sample_every * 2, 10)
        return max(1, self.sample_every)

    def event(self, domain: str, message: str, **fields: object) -> None:
        try:
            get_runtime_economics_ledger().observe('telemetry_cost', 1.0)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_suppressed_failure('telemetry_cost_observe_failed', exc, domain='telemetry')
        domain_text, domain_reason = no_hook_text(
            domain,
            missing_reason="runtime_telemetry_domain_missing",
            unsupported_reason="runtime_telemetry_domain_rejected",
        )
        message_text, message_reason = no_hook_text(
            message,
            missing_reason="runtime_telemetry_message_missing",
            unsupported_reason="runtime_telemetry_message_rejected",
        )
        input_evidence = {}
        if domain_reason or domain_text == "":
            input_evidence["domain_rejection"] = domain_reason or "runtime_telemetry_domain_blank"
            input_evidence["domain_type"] = no_hook_type_name(domain)
            domain_text = "runtime_input_rejected"
        if message_reason or message_text == "":
            input_evidence["message_rejection"] = message_reason or "runtime_telemetry_message_blank"
            input_evidence["message_type"] = no_hook_type_name(message)
            message_text = "telemetry_input_rejected"
        key = domain_text + ":" + message_text
        seen = dict.get(self._event_seen, key, 0) + 1
        self._event_seen[key] = seen
        self.incr("events." + domain_text + "." + message_text, 1)
        if self.max_events <= 0:
            self._coalesced[key] = dict.get(self._coalesced, key, 0) + 1
            return
        important_value = dict.pop(fields, "important", False)
        important = important_value if type(important_value) is bool else False
        if type(important_value) is not bool:
            input_evidence["important_rejection"] = "runtime_telemetry_important_rejected"
        sample_every = self._effective_sample_every(important)
        if not important and seen % sample_every != 1:
            self._coalesced[key] = dict.get(self._coalesced, key, 0) + 1
            return
        item = {
            "time": round(time.time(), 3),
            "domain": domain_text,
            "message": message_text,
            "count": seen,
        }
        if input_evidence:
            item["input_evidence"] = input_evidence
        dropped = self._coalesced.pop(key, 0)
        if dropped:
            item["coalesced"] = dropped
        materialized_fields = materialize_runtime_value(freeze_runtime_value(fields))
        if type(materialized_fields) is dict:
            item.update(materialized_fields)
        self.events.append(item)
        overflow = len(self.events) - self.max_events
        if overflow > 0:
            # Preserve a small reserve of recent important events by dropping
            # oldest non-important events first, then falling back to FIFO.
            kept: list[dict[str, object]] = []
            dropped_count = 0
            for ev in self.events:
                if dropped_count < overflow and not ev.get("important"):
                    dropped_count += 1
                    continue
                kept.append(ev)
            self.events = kept[-self.max_events:]
            self.incr("telemetry.backpressure_dropped", max(overflow, dropped_count))

    def queue_metric(self, queue: str, latency: float | None = None, debt: float | None = None, saturation: float | None = None) -> None:
        queue_text, reason = no_hook_text(
            queue,
            missing_reason="runtime_telemetry_queue_missing",
            unsupported_reason="runtime_telemetry_queue_rejected",
        )
        if reason or queue_text == "":
            record_suppressed_failure(
                "runtime_telemetry_queue_rejected",
                ValueError(reason or "runtime_telemetry_queue_blank"),
                domain="telemetry",
            )
            return
        prefix = "queue." + queue_text
        if latency is not None:
            self.gauge(prefix + ".latency", latency)
        if debt is not None:
            self.gauge(prefix + ".debt", debt)
        if saturation is not None:
            self.gauge(prefix + ".saturation", saturation)

    def quota_activation(self, name: str, *, important: bool = True) -> None:
        name_text, reason = no_hook_text(
            name,
            missing_reason="runtime_telemetry_quota_missing",
            unsupported_reason="runtime_telemetry_quota_rejected",
        )
        if reason or name_text == "":
            record_suppressed_failure(
                "runtime_telemetry_quota_rejected",
                ValueError(reason or "runtime_telemetry_quota_blank"),
                domain="telemetry",
            )
            return
        self.incr("quota." + name_text, 1)
        self.event("quota", name_text, important=important)

    def failure_domain(self, domain: str, where: str = "") -> None:
        domain_text, reason = no_hook_text(
            domain,
            missing_reason="runtime_telemetry_failure_domain_missing",
            unsupported_reason="runtime_telemetry_failure_domain_rejected",
        )
        if reason or domain_text == "":
            domain_text = "runtime_input_rejected"
        self.incr("failure_domain." + domain_text, 1)
        self.event("failure_domain", domain_text, where=where, important=True)

    def snapshot(self) -> dict[str, object]:
        return materialize_runtime_value(freeze_runtime_value({
            "counters": dict(_telemetry_items(self.counters)),
            "gauges": dict(_telemetry_items(self.gauges)),
            "events": list(self.events),
            "pressure": self.pressure,
            "coalesced": dict(_telemetry_items(self._coalesced)),
        }))


__all__ = ("RuntimeTelemetry",)
