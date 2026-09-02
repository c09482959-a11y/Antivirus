"""Canonical no-hook attribute reads for exact scheduler-owned records."""
from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace


_MISSING = object()


def scheduler_exact_attr(
    owner: object,
    name: str,
    *,
    owner_type: type[object] | None = None,
    module_name: str = "",
    type_name: str = "",
    default: object = None,
) -> object:
    """Read a field from a scheduler-owned exact object without caller hooks.

    The helper is the single scheduler-local boundary that may use
    ``object.__getattribute__`` for record fields.  Callers must either provide
    the exact runtime type or the exact loaded module/name identity.  Unknown
    subclasses and classes with caller-owned ``__getattribute__`` are rejected
    before the field read.
    """
    if type(name) is not str or not name:
        return default
    owner_runtime_type = type(owner)
    if owner_type is not None:
        if owner_runtime_type is not owner_type:
            return default
    elif module_name or type_name:
        try:
            owner_module_value = type.__getattribute__(owner_runtime_type, "__module__")
        except (AttributeError, TypeError, RuntimeError):
            owner_module_value = ""
        owner_module = str.__str__(owner_module_value) if type(owner_module_value) is str else ""
        if owner_module != module_name:
            return default
        try:
            owner_name_value = type.__getattribute__(owner_runtime_type, "__name__")
        except (AttributeError, TypeError, RuntimeError):
            owner_name_value = ""
        owner_name = str.__str__(owner_name_value) if type(owner_name_value) is str else ""
        if owner_name != type_name:
            return default
        module = dict.get(sys.modules, module_name) if module_name else None
        if type(module) is not ModuleType:
            return default
        module_dict = scheduler_exact_attr(module, "__dict__", owner_type=ModuleType, default=None)
        if type(module_dict) is not dict or dict.get(module_dict, type_name) is not owner_runtime_type:
            return default
    else:
        return default
    try:
        getattribute = type.__getattribute__(owner_runtime_type, "__getattribute__")
        if owner_runtime_type is ModuleType:
            expected_getattribute = type.__getattribute__(ModuleType, "__getattribute__")
        elif owner_runtime_type is SimpleNamespace:
            expected_getattribute = type.__getattribute__(SimpleNamespace, "__getattribute__")
        else:
            expected_getattribute = object.__getattribute__
        if getattribute is not expected_getattribute:
            return default
        return object.__getattribute__(owner, name)
    except (AttributeError, TypeError, RuntimeError):
        return default


__all__ = ("scheduler_exact_attr",)
