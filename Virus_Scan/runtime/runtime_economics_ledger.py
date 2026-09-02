"""Central typed runtime economics ledger."""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.runtime.governance_inputs import runtime_float, runtime_text


def _default_channels() -> dict[str, float]:
    return {
        "admission_cost": 0.0,
        "execution_cost": 0.0,
        "replay_cost": 0.0,
        "telemetry_cost": 0.0,
        "event_publish_cost": 0.0,
        "scoring_inertia": 0.0,
        "recovery_cost": 0.0,
    }


def _channel_items(channels: dict[str, float]) -> tuple[tuple[str, float], ...]:
    return tuple(sorted(dict.items(channels)))


@dataclass
class RuntimeEconomicsLedger:
    channels: dict[str, float] = field(default_factory=_default_channels)
    input_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) is not RuntimeEconomicsLedger:
            exception_message = "runtime economics ledger owner rejected"
            raise TypeError(exception_message)
        if type(self.channels) is not dict:
            object.__setattr__(self, "channels", _default_channels())
            self.input_evidence += ({"field": "channels", "reason": "runtime_economics_channels_rejected"},)

    def observe(self, channel: str, amount: float) -> float:
        key, key_issues = runtime_text(
            channel,
            field_name="runtime_economics_channel",
            default="input_rejected",
        )
        metric, amount_issues = runtime_float(
            amount,
            field_name="runtime_economics_amount",
            default=0.0,
            minimum=0.0,
        )
        issues = key_issues + amount_issues
        if issues:
            self.input_evidence += issues
            return self.channels.get(key, 0.0)
        if key not in self.channels:
            self.channels[key] = 0.0
        self.channels[key] += metric
        return self.channels[key]

    def snapshot(self) -> Mapping[str, object]:
        out: dict[str, object] = dict(_channel_items(self.channels))
        if self.input_evidence:
            out["__input_evidence__"] = self.input_evidence
        return MappingProxyType(out)


_GLOBAL_RUNTIME_ECONOMICS_LEDGER = RuntimeEconomicsLedger()


def get_runtime_economics_ledger() -> RuntimeEconomicsLedger:
    return _GLOBAL_RUNTIME_ECONOMICS_LEDGER


def observe_runtime_economics(channel: str, amount: float = 0.0) -> float:
    """Record accounting cost; callers retain admission/denial ownership."""
    return get_runtime_economics_ledger().observe(channel, amount)


__all__ = (
    "RuntimeEconomicsLedger",
    "get_runtime_economics_ledger",
    "observe_runtime_economics",
)
