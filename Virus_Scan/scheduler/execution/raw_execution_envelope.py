"""Raw scheduler execution envelopes.

Envelope ownership separates queue execution mechanics from detection/model/report
semantics.  Queue boundaries pass this typed envelope and convert to the persisted raw-result record only at the accumulator write boundary.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping

@dataclass(frozen=True, slots=True)
class RawExecutionEnvelope:
    file: str
    collector: str
    ok: bool
    result: Mapping[str, object] = field(default_factory=immutable_mapping)
    error: str = ""
    attempt: int = 0
    seq: int | None = None

    def __post_init__(self) -> object:
        object.__setattr__(self, "result", immutable_mapping(self.result))

    def to_accumulator_record(self) -> Mapping[str, object]:
        """Materialize only at the durable accumulator serialization edge."""
        source = materialize_scheduler_mapping(self.result or immutable_mapping())
        if type(source) is not dict:
            source = {}
        out = {
            **source,
            "collector": dict.get(source, "collector", self.collector),
            "attempt": dict.get(source, "attempt", self.attempt),
        }
        if self.seq is not None and "seq" not in out:
            out["seq"] = self.seq
        if not self.ok and self.error:
            if "error" not in out:
                out["error"] = self.error
            if "errors" not in out:
                out["errors"] = [self.error]
        return out
