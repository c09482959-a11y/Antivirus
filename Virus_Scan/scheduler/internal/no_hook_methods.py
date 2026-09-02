"""No-hook scheduler method lookup for owned lifecycle boundary objects."""
from __future__ import annotations

from types import BuiltinFunctionType, MethodDescriptorType, WrapperDescriptorType


from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict

_SAFE_METHOD_DESCRIPTOR_TYPES = (RUNTIME_NATIVE_FUNCTION_TYPE, MethodDescriptorType, WrapperDescriptorType, BuiltinFunctionType)



def safe_scheduler_bound_method(
    owner: object,
    name: str,
    *,
    reason_prefix: str = "unsafe_scheduler_method",
    allowed_names: frozenset[str] | None = None,
) -> tuple[object, str]:
    """Return a bound method without invoking caller-owned attribute hooks.

    The scheduler receives process, queue, thread, dependency, and recovery
    objects across lifecycle boundaries.  Probing them with ``hasattr`` or
    ``getattr`` can execute caller-owned ``__getattribute__`` or descriptor
    code.  This helper accepts only exact normal attribute lookup plus a plain
    method descriptor found on the class MRO, then binds that descriptor through
    the builtin descriptor implementation.
    """
    reason_prefix_text = str.__str__(reason_prefix) if type(reason_prefix) is str and reason_prefix else "unsafe_scheduler_method"
    if type(name) is not str or not name:
        return None, str.__add__(reason_prefix_text, "_name_rejected")
    if allowed_names is not None and name not in allowed_names:
        return None, str.__add__(reason_prefix_text, "_name_rejected")
    if owner is None:
        return None, ""
    owner_type = type(owner)
    try:
        if type.__getattribute__(owner_type, "__getattribute__") is not object.__getattribute__:
            return None, str.__add__(reason_prefix_text, "_getattribute_rejected")
        mro = type.__getattribute__(owner_type, "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return None, str.__add__(reason_prefix_text, "_type_rejected")
    descriptor = None
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError, RuntimeError):
            return None, str.__add__(reason_prefix_text, "_type_rejected")
        candidate = class_dict.get(name)
        if candidate is None:
            continue
        descriptor = candidate
        break
    if descriptor is None:
        return None, ""
    if type(descriptor) not in _SAFE_METHOD_DESCRIPTOR_TYPES:
        return None, str.__add__(reason_prefix_text, "_descriptor_rejected")
    try:
        return descriptor.__get__(owner, owner_type), ""
    except RECOVERABLE_RUNTIME_ERRORS:
        return None, str.__add__(reason_prefix_text, "_method_bind_failed")


def safe_scheduler_instance_callable(
    owner: object,
    name: str,
    *,
    reason_prefix: str = "unsafe_scheduler_callable",
) -> tuple[object, str]:
    """Return an owned callable instance field without invoking descriptors."""
    reason_prefix_text = str.__str__(reason_prefix) if type(reason_prefix) is str and reason_prefix else "unsafe_scheduler_callable"
    if type(name) is not str or not name:
        return None, str.__add__(reason_prefix_text, "_name_rejected")
    if owner is None:
        return None, str.__add__(reason_prefix_text, "_missing")
    data = no_hook_plain_instance_dict(owner)
    if data is None:
        return None, str.__add__(reason_prefix_text, "_instance_dict_rejected")
    candidate = dict.get(data, name)
    if candidate is None:
        return None, str.__add__(reason_prefix_text, "_missing")
    if not callable(candidate):
        return None, str.__add__(reason_prefix_text, "_callable_rejected")
    return candidate, ""


__all__ = ("safe_scheduler_bound_method", "safe_scheduler_instance_callable")
