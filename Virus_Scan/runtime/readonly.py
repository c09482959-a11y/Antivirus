"""Read-only runtime views for subsystems."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value


def _freeze_readonly_config(config: object) -> object:
    """Freeze JSON-style config payloads while preserving typed config objects."""
    if type(config) in (dict, list, tuple, set, frozenset):
        return freeze_runtime_value(config)
    return config

@dataclass(frozen=True)
class ReadonlyRuntimeView:
    state: Mapping[str, object]
    config: object = None
    generation: int = 0

    def __post_init__(self) -> None:
        if type(self) is not ReadonlyRuntimeView:
            exception_message = "readonly runtime view owner rejected"
            raise TypeError(exception_message)
        state = {} if self.state is None else self.state
        object.__setattr__(self, "state", freeze_runtime_value(state))
        object.__setattr__(self, "config", _freeze_readonly_config(self.config))
        generation, _reason = no_hook_exact_nonnegative_int(
            self.generation,
            default=0,
            reason="readonly_runtime_generation_rejected",
            allow_exact_text=True,
        )
        object.__setattr__(self, "generation", generation)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object], *, config: object = None, generation: int = 0) -> "ReadonlyRuntimeView":
        return cls(mapping, config=config, generation=generation)

    def get(self, name: str, default: object = None) -> object:
        return self.state.get(name, default)

    def as_dict(self) -> dict[str, object]:
        return materialize_runtime_value(self.state)


__all__ = ("ReadonlyRuntimeView",)
