"""Context-owned immutable scheduler dependency snapshots."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.context_no_hook import context_text_tuple, merge_context_evidence
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value


@dataclass(frozen=True, slots=True)
class SchedulerDependencySnapshot:
    """Immutable declaration of scheduler dependency bindings.

    Callable objects remain references by design; the mutable metadata around them
    is frozen so dependency ownership cannot be changed by caller-owned mappings.
    """

    bindings: Mapping[str, object] = field(default_factory=immutable_mapping)
    binding_names: tuple[str, ...] = ()
    public_contracts: tuple[str, ...] = ()
    missing_dependencies: tuple[str, ...] = ()
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        frozen_bindings = immutable_mapping(self.bindings)
        frozen_binding_decision = frozen_scheduler_items_decision(frozen_bindings)
        frozen_binding_items = frozen_binding_decision.items if frozen_binding_decision.accepted else ()
        frozen_binding_keys = tuple(key for key, _value in frozen_binding_items)
        explicit_names, binding_evidence = context_text_tuple(self.binding_names, field_name="binding_names")
        key_names, key_evidence = context_text_tuple(frozen_binding_keys, field_name="binding_keys")
        binding_names = tuple(sorted(set(explicit_names + key_names)))
        public_contracts, public_contracts_evidence = context_text_tuple(self.public_contracts, field_name="public_contracts")
        missing_dependencies, missing_evidence = context_text_tuple(self.missing_dependencies, field_name="missing_dependencies")
        object.__setattr__(self, "bindings", frozen_bindings)
        object.__setattr__(self, "binding_names", binding_names)
        object.__setattr__(self, "public_contracts", public_contracts)
        object.__setattr__(self, "missing_dependencies", missing_dependencies)
        object.__setattr__(self, "evidence", merge_context_evidence(self.evidence, binding_evidence, key_evidence, public_contracts_evidence, missing_evidence))

    def as_dict(self) -> dict[str, object]:
        return {
            "binding_names": list(self.binding_names),
            "public_contracts": list(self.public_contracts),
            "missing_dependencies": list(self.missing_dependencies),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }


    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerDependencySnapshot":
        return cls(
            bindings=scheduler_mapping_value(value, "bindings", {}),
            binding_names=scheduler_mapping_value(value, "binding_names", ()),
            public_contracts=scheduler_mapping_value(value, "public_contracts", ()),
            missing_dependencies=scheduler_mapping_value(value, "missing_dependencies", ()),
            evidence=scheduler_mapping_value(value, "evidence", ()),
        )


__all__ = ("SchedulerDependencySnapshot",)
