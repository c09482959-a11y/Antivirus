"""Separated governance planes with hysteresis and circuit breakers."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field
from dataclasses import dataclass, field
from time import monotonic
from typing import Mapping, MutableMapping

from Virus_Scan.runtime.governance_inputs import runtime_float, runtime_text


def _governance_child_field(parent: str, child: str) -> str:
    if type(parent) is str and type(child) is str:
        return str.__str__(parent) + "_" + str.__str__(child)
    return "governance_field"

DEFAULT_GOVERNANCE_PLANES = ("replay", "telemetry", "scheduler", "saturation", "semantic")


@dataclass
class GovernancePlane:
    name: str
    trip_threshold: float = 25.0
    release_threshold: float = 12.0
    cooldown_sec: float = 0.25
    pressure: float = 0.0
    state: str = "normal"
    transitions: int = 0
    last_transition: float = field(default_factory=monotonic)
    input_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) is not GovernancePlane:
            exception_message = "governance plane owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[Mapping[str, object], ...] = ()
        self.name, issues = runtime_text(
            self.name, field_name="governance_plane_name", default="saturation"
        )
        evidence += issues
        for field_name, default, minimum in (
            ("trip_threshold", 25.0, 0.0),
            ("release_threshold", 12.0, 0.0),
            ("cooldown_sec", 0.25, 0.0),
            ("pressure", 0.0, 0.0),
            ("last_transition", 0.0, 0.0),
        ):
            value, issues = runtime_float(
                no_hook_exact_owner_field(self, GovernancePlane, field_name),
                field_name=_governance_child_field("governance_plane", field_name),
                default=default,
                minimum=minimum,
            )
            evidence += issues
            object.__setattr__(self, field_name, value)
        self.state, issues = runtime_text(
            self.state,
            field_name="governance_plane_state",
            default="tripped",
        )
        evidence += issues
        self.input_evidence = evidence

    def observe(self, amount: float) -> dict[str, object]:
        amount_value, issues = runtime_float(
            amount,
            field_name="governance_plane_amount",
            default=0.0,
            minimum=0.0,
        )
        if issues:
            self.input_evidence += issues
            return {
                "plane": self.name,
                "state": "tripped",
                "pressure": round(self.pressure, 4),
                "transitioned": False,
                "transitions": self.transitions,
                "runtime_input_rejected": True,
                "input_evidence": issues,
            }
        now = monotonic()
        if amount_value <= 0.0:
            self.pressure = max(0.0, self.pressure * 0.85)
        else:
            self.pressure = min(100.0, self.pressure + amount_value * (0.5 if self.state != "normal" else 1.0))
        old = self.state
        if self.state == "normal" and self.pressure >= self.trip_threshold and now - self.last_transition >= self.cooldown_sec:
            self.state = "tripped"
        elif self.state == "tripped" and self.pressure <= self.release_threshold and now - self.last_transition >= self.cooldown_sec:
            self.state = "normal"
        if self.state != old:
            self.transitions += 1
            self.last_transition = now
        return {"plane": self.name, "state": self.state, "pressure": round(self.pressure, 4), "transitioned": self.state != old, "transitions": self.transitions}

    def decay(self) -> dict[str, object]:
        return self.observe(0.0)


def make_governance_planes() -> dict[str, GovernancePlane]:
    return {name: GovernancePlane(name) for name in DEFAULT_GOVERNANCE_PLANES}


def observe_governance_plane(planes: MutableMapping[str, GovernancePlane], plane: str, amount: float) -> dict[str, object]:
    key, issues = runtime_text(
        plane, field_name="governance_plane_key", default="saturation"
    )
    if type(planes) is not dict:
        return {
            "plane": key,
            "state": "tripped",
            "pressure": 0.0,
            "transitioned": False,
            "transitions": 0,
            "runtime_input_rejected": True,
            "input_evidence": (*issues, {'runtime_input_rejected': True, 'field_name': 'governance_planes', 'reason': 'governance_planes_owner_rejected'}),
        }
    if issues:
        return {
            "plane": key,
            "state": "tripped",
            "pressure": 0.0,
            "transitioned": False,
            "transitions": 0,
            "runtime_input_rejected": True,
            "input_evidence": issues,
        }
    if key not in planes:
        planes[key] = GovernancePlane(key)
    return planes[key].observe(amount)


def governance_planes_snapshot(planes: MutableMapping[str, GovernancePlane]) -> dict[str, object]:
    if type(planes) is not dict:
        return {
            "governance_planes_unavailable": True,
            "runtime_input_rejected": True,
        }
    out: dict[str, object] = {}
    rows = tuple(
        (name, plane)
        for name, plane in dict.items(planes)
        if type(name) is str and type(plane) is GovernancePlane
    )
    for name, plane in sorted(rows, key=lambda item: str.__str__(item[0])):
        row: dict[str, object] = {
            "state": plane.state,
            "pressure": round(plane.pressure, 4),
            "transitions": plane.transitions,
        }
        if plane.input_evidence:
            row["input_evidence"] = plane.input_evidence
        out[name] = row
    return out


__all__ = ("GovernancePlane", "governance_planes_snapshot", "make_governance_planes", "observe_governance_plane")
