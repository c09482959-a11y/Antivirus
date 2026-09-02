"""Loaded-class ownership checks for scheduler frozen dataclass materialization."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from types import ModuleType


from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr


@dataclass(frozen=True, slots=True)
class SchedulerDataclassOwnershipDecision:
    """Replayable dataclass ownership decision without empty-string sentinels."""

    accepted: bool
    reason: str




def scheduler_type_attr(value: object, name: str, default: str = "") -> str:
    """Read exact type metadata without invoking caller-owned metaclass hooks."""
    try:
        attr = type.__getattribute__(type(value), name)
    except (AttributeError, TypeError):
        return default
    if type(attr) is str:
        return str.__str__(attr)
    return default


def _loaded_scheduler_dataclass_type_decision(value: object) -> SchedulerDataclassOwnershipDecision:
    value_type = type(value)
    module_name = scheduler_type_attr(value, "__module__")
    type_name = scheduler_type_attr(value, "__name__")
    if not module_name.startswith("Virus_Scan.scheduler.") or type_name == "":
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_type_not_scheduler_owned"
        )
    module = sys.modules.get(module_name)
    if type(module) is not ModuleType:
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_module_not_loaded"
        )
    module_dict = scheduler_exact_attr(module, "__dict__", owner_type=ModuleType)
    if module_dict is None:
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_module_dict_rejected"
        )
    if type(module_dict) is not dict:
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_module_dict_not_exact"
        )
    if dict.get(module_dict, type_name) is not value_type:
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_type_not_loaded_owner"
        )
    return SchedulerDataclassOwnershipDecision(accepted=True, reason="scheduler_dataclass_type_loaded_owner")



def _internal_frozen_dataclass_decision(value: object) -> SchedulerDataclassOwnershipDecision:
    if type(value) is type:
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_value_is_type"
        )
    loaded_decision = _loaded_scheduler_dataclass_type_decision(value)
    if not loaded_decision.accepted:
        return loaded_decision
    try:
        params = type.__getattribute__(type(value), "__dataclass_params__")
    except (AttributeError, TypeError):
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_params_missing"
        )
    params_module = scheduler_type_attr(params, "__module__")
    params_name = scheduler_type_attr(params, "__name__")
    if params_module != "dataclasses" or params_name != "_DataclassParams":
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_params_not_owned"
        )
    frozen = scheduler_exact_attr(params, "frozen", owner_type=type(params))
    if frozen is None:
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_frozen_flag_rejected"
        )
    if frozen is not True:
        return SchedulerDataclassOwnershipDecision(
            accepted=False, reason="scheduler_dataclass_not_frozen"
        )
    return SchedulerDataclassOwnershipDecision(accepted=True, reason="scheduler_frozen_dataclass_accepted")


__all__ = ("_internal_frozen_dataclass_decision", "scheduler_type_attr")
