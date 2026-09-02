"""Canonical no-hook materialization for model evidence boundaries.

This module accepts only owned primitive values, exact builtin containers, and
internal frozen dataclasses. Unsupported caller-owned objects become explicit
failure evidence without invoking caller-owned text, numeric, truthiness,
iteration, mapping, formatting, or property hooks.
"""
from __future__ import annotations

from dataclasses import fields, is_dataclass
import ast
from types import GetSetDescriptorType, MappingProxyType, ModuleType, SimpleNamespace
import base64
import gc
import json
import math
import sys

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS

_JSON_FAILURE_KEYS = frozenset(("value", "unavailable_reason", "value_type"))
_INTERNAL_MODULE_PREFIX = "Virus_Scan."
_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))
_DEFAULT_MAX_ITEMS = 512


def _reason_prefix_text(value: object, *, default: str = "json") -> str:
    if type(value) is str and value:
        return str.__str__(value)
    return default


def _reason_suffix(prefix: object, suffix: str, *, default: str = "json") -> str:
    return _reason_prefix_text(prefix, default=default) + suffix


def _reason_wrapped(prefix: object, leading: str, trailing: str, *, default: str = "json") -> str:
    return leading + _reason_prefix_text(prefix, default=default) + trailing


def _index_text(index: object) -> str:
    if type(index) is int and type(index) is not bool:
        return int.__str__(index)
    return "0"


def no_hook_duplicate_key(key_text: object, index: object, *, rejection: str = "duplicate_key_rejected") -> str:
    """Return a deterministic duplicate-key suffix without caller hooks."""
    if type(key_text) is not str or type(index) is not int or type(index) is bool:
        return str.__str__(rejection) if type(rejection) is str else "duplicate_key_rejected"
    return str.__str__(key_text) + "#" + int.__str__(index)


def _safe_type_attr(value: object, name: str, default: str = "unknown") -> str:
    """Read a type attribute without invoking instance or metaclass hooks."""
    try:
        attr = type.__getattribute__(type(value), name)
    except (AttributeError, TypeError):
        return default
    if type(attr) is str:
        return str.__str__(attr)
    return default


def no_hook_type_name(value: object) -> str:
    return _safe_type_attr(value, "__name__")


def no_hook_failure(reason: str, value: object) -> dict[str, object]:
    return {"value": None, "unavailable_reason": reason, "value_type": no_hook_type_name(value)}


def unsupported_value_evidence(value: object, *, context: str = "json", reason: str = "unsupported_value") -> dict[str, object]:
    evidence = no_hook_failure(reason, value)
    if type(context) is str and context:
        evidence["context"] = str.__str__(context)
    return evidence


def invalid_key_evidence(value: object, *, context: str = "json", index: int = 0) -> dict[str, object]:
    evidence = no_hook_failure("invalid_json_mapping_key", value)
    if type(context) is str and context:
        evidence["context"] = str.__str__(context)
    if type(index) is int and not isinstance(index, bool):
        evidence["index"] = index
    return evidence


def is_exact_text(value: object) -> bool:
    return type(value) is str


def exact_text_or_none(value: object) -> str | None:
    if type(value) is str:
        return str.__str__(value)
    return None


def _is_str_subclass_no_hook_status(value: object) -> tuple[bool, str]:
    value_type = type(value)
    if value_type is str:
        return True, ""
    try:
        mro = type.__getattribute__(value_type, "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return False, "str_mro_unavailable"
    if type(mro) is not tuple:
        return False, "str_mro_not_tuple"
    for cls in mro:
        if cls is str:
            return True, ""
    return False, "not_str_subclass"


def _is_str_subclass_no_hook(value: object) -> bool:
    accepted, _reason = _is_str_subclass_no_hook_status(value)
    return accepted


def exact_bool_or_none(value: object) -> bool | None:
    if type(value) is bool:
        return value
    return None


def exact_int_or_none(value: object) -> int | None:
    if type(value) is int and type(value) is not bool:
        return value
    return None


def exact_finite_float_or_none(value: object) -> float | None:
    if type(value) is float:
        if math.isfinite(value):
            return value
        return None
    if type(value) is int and type(value) is not bool:
        metric = value + 0.0
        if math.isfinite(metric):
            return metric
    return None


def _default_finite_float(default: object) -> float:
    metric = exact_finite_float_or_none(default)
    if metric is not None:
        return metric
    return 0.0


def no_hook_plain_instance_dict_status(value: object) -> tuple[dict[object, object] | None, str]:
    """Return an exact instance ``__dict__`` without executing caller hooks.

    ``object.__getattribute__(value, "__dict__")`` is not safe by itself: a
    caller-owned class can install a property or descriptor named ``__dict__``
    and that descriptor executes even when the call is wrapped in ``try``.  This
    helper first proves that the class exposes Python's built-in instance-dict
    descriptor and that normal attribute lookup has not been overridden.
    """
    value_type = type(value)
    try:
        owner_getattribute = type.__getattribute__(value_type, "__getattribute__")
        simple_namespace_getattribute = type.__getattribute__(SimpleNamespace, "__getattribute__")
        if value_type is SimpleNamespace:
            if owner_getattribute is not simple_namespace_getattribute:
                return None, "custom_getattribute"
        elif owner_getattribute is not object.__getattribute__:
            return None, "custom_getattribute"
        mro = type.__getattribute__(value_type, "__mro__")
    except (AttributeError, TypeError):
        return None, "type_layout_unavailable"
    if type(mro) is not tuple:
        return None, "type_mro_not_tuple"
    has_builtin_instance_dict = False
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError):
            return None, "class_dict_unavailable"
        descriptor = class_dict.get("__dict__")
        if descriptor is None:
            continue
        if type(descriptor) is GetSetDescriptorType or value_type is SimpleNamespace:
            has_builtin_instance_dict = True
            break
        return None, "non_builtin_instance_dict_descriptor"
    if not has_builtin_instance_dict:
        return None, "missing_builtin_instance_dict"
    try:
        data = object.__getattribute__(value, "__dict__")
    except (*RECOVERABLE_RUNTIME_ERRORS, AttributeError, TypeError):
        return None, "instance_dict_unavailable"
    if type(data) is dict:
        return data, ""
    return None, "instance_dict_not_exact_dict"


def no_hook_plain_instance_dict(value: object) -> dict[object, object] | None:
    data, _reason = no_hook_plain_instance_dict_status(value)
    return data




def no_hook_ast_field_status(value: object, allowed_types: tuple[type[ast.AST], ...], field_name: str) -> tuple[object | None, str]:
    """Read an exact CPython ``ast`` node field through the no-hook owner.

    Scanner CI audits need source location/name fields from parser-owned AST
    nodes, but local modules must not carry direct ``object.__getattribute__``
    bypasses.  This helper accepts only exact builtin AST node classes whose
    attribute access slot is the ``ast.AST`` slot wrapper, rejecting subclasses
    or hostile objects before any instance attribute read.
    """
    if type(allowed_types) is not tuple or not allowed_types:
        return None, "ast_owner_types_rejected"
    if type(field_name) is not str or field_name == "":
        return None, "ast_field_name_rejected"
    value_type = type(value)
    if value_type not in allowed_types:
        return None, "ast_owner_type_mismatch"
    try:
        ast_getattribute = type.__getattribute__(ast.AST, "__getattribute__")
        owner_getattribute = type.__getattribute__(value_type, "__getattribute__")
    except (AttributeError, TypeError):
        return None, "ast_owner_layout_unavailable"
    if owner_getattribute is not ast_getattribute:
        return None, "ast_owner_custom_getattribute"
    try:
        return object.__getattribute__(value, field_name), ""
    except (*RECOVERABLE_RUNTIME_ERRORS, AttributeError, TypeError):
        return None, "ast_field_unavailable"

def no_hook_exact_owner_field_status(value: object, owner_type: type[object], field_name: str) -> tuple[object | None, str]:
    """Read an owned exact-type field through the canonical no-hook boundary.

    Callers must pass the exact internal owner type they already validated.  The
    helper rejects subclasses, hostile field-name objects, and owner types with
    custom ``__getattribute__`` so local modules do not carry direct
    ``object.__getattribute__`` bypasses.
    """
    if type(owner_type) is not type:
        return None, "owner_type_rejected"
    if type(field_name) is not str or field_name == "":
        return None, "field_name_rejected"
    if type(value) is not owner_type:
        return None, "owner_type_mismatch"
    try:
        owner_getattribute = type.__getattribute__(owner_type, "__getattribute__")
        simple_namespace_getattribute = type.__getattribute__(SimpleNamespace, "__getattribute__")
        if owner_type is SimpleNamespace:
            if owner_getattribute is not simple_namespace_getattribute:
                return None, "custom_getattribute"
        elif owner_getattribute is not object.__getattribute__:
            return None, "custom_getattribute"
        return object.__getattribute__(value, field_name), ""
    except (*RECOVERABLE_RUNTIME_ERRORS, AttributeError, TypeError):
        return None, "owned_field_unavailable"


def no_hook_exact_owner_field(value: object, owner_type: type[object], field_name: str) -> object | None:
    field_value, _reason = no_hook_exact_owner_field_status(value, owner_type, field_name)
    return field_value

def no_hook_module_dict_status(value: object) -> tuple[dict[str, object] | None, str]:
    """Return an exact module ``__dict__`` without caller-owned hooks."""
    if type(value) is not ModuleType:
        return None, "module_not_exact_module"
    try:
        module_dict = object.__getattribute__(value, "__dict__")
    except (*RECOVERABLE_RUNTIME_ERRORS, AttributeError, TypeError):
        return None, "module_dict_unavailable"
    if type(module_dict) is dict:
        return module_dict, ""
    return None, "module_dict_not_exact_dict"


def no_hook_internal_frozen_dataclass_status(value: object) -> tuple[bool, str]:
    """Return internal frozen dataclass status through the canonical no-hook owner."""
    return _is_internal_frozen_dataclass_status(value)


def _plain_instance_text_field(value: object) -> str | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return None
    for field_name in ("text", "_text", "value", "_value"):
        text_value = dict.get(data, field_name)
        if type(text_value) is str:
            return str.__str__(text_value)
    return None


def no_hook_text(value: object, *, missing_reason: str = "missing_text", unsupported_reason: str = "unsafe_text_value_rejected") -> tuple[str, str]:
    if value is None:
        return "", missing_reason
    if type(value) is str:
        return str.__str__(value), ""
    if _is_str_subclass_no_hook(value):
        return str.__str__(value), ""
    if type(value) is bytes:
        try:
            return bytes(value).decode("utf-8", "replace"), ""
        except RECOVERABLE_RUNTIME_ERRORS:
            return "", "bytes_text_decode_failed"
    if type(value) is bytearray:
        try:
            return bytes(value).decode("utf-8", "replace"), ""
        except RECOVERABLE_RUNTIME_ERRORS:
            return "", "bytes_text_decode_failed"
    if type(value) is bool:
        return ("true" if value else "false"), ""
    if type(value) is int:
        return int.__str__(value), ""
    if type(value) is float:
        if math.isfinite(value):
            return float.__str__(value), ""
        return "", "non_finite_text_number"
    text_field = _plain_instance_text_field(value)
    if text_field is not None:
        return text_field, ""
    return "", unsupported_reason


def no_hook_finite_float(
    value: object,
    *,
    default: float = 0.0,
    minimum: float | None = None,
    maximum: float | None = None,
    reason: str = "unsafe_numeric_value_rejected",
    non_finite_reason: str = "non_finite_number",
    allow_exact_text: bool = True,
) -> tuple[float, str]:
    default_metric = _default_finite_float(default)
    candidate = default if value is None else value
    if type(candidate) is bool:
        return default_metric, reason
    if type(candidate) is int:
        metric = candidate + 0.0
    elif type(candidate) is float:
        metric = candidate
    elif allow_exact_text and _is_str_subclass_no_hook(candidate):
        text, text_reason = no_hook_text(
            candidate,
            missing_reason="missing_numeric_text",
            unsupported_reason="unsafe_numeric_text_rejected",
        )
        if text_reason:
            return default_metric, reason
        try:
            metric = float(str.strip(text))
        except RECOVERABLE_RUNTIME_ERRORS:
            return default_metric, reason
    elif allow_exact_text and type(candidate) is bytes:
        try:
            metric = float(bytes(candidate).decode("utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return default_metric, reason
    elif allow_exact_text and type(candidate) is bytearray:
        try:
            metric = float(bytes(candidate).decode("utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return default_metric, reason
    else:
        return default_metric, reason
    if not math.isfinite(metric):
        return default_metric, non_finite_reason
    if minimum is not None:
        lower = exact_finite_float_or_none(minimum)
        if lower is not None and metric < lower:
            metric = lower
    if maximum is not None:
        upper = exact_finite_float_or_none(maximum)
        if upper is not None and metric > upper:
            metric = upper
    return metric, ""



def no_hook_exact_nonnegative_int(
    value: object,
    *,
    default: int = 0,
    reason: str = "unsafe_integer_value_rejected",
    non_finite_reason: str = "non_finite_integer_value",
    allow_exact_text: bool = True,
) -> tuple[int, str]:
    """Return an exact non-negative integer without caller-owned hooks.

    The function accepts exact builtin integers, integral finite floats, and
    exact primitive text/bytes integer spellings when explicitly allowed.
    Non-integral finite floats such as ``2.9`` are rejected instead of being
    silently truncated by ``int(...)``.
    """
    default_value = default if type(default) is int and type(default) is not bool and default >= 0 else 0
    candidate = default if value is None else value
    if type(candidate) is bool:
        return default_value, reason
    if type(candidate) is int:
        if candidate < 0:
            return default_value, reason
        return candidate, ""
    if type(candidate) is float:
        if not math.isfinite(candidate):
            return default_value, non_finite_reason
        if not candidate.is_integer() or candidate < 0:
            return default_value, reason
        return int(candidate), ""
    if allow_exact_text and _is_str_subclass_no_hook(candidate):
        text, text_reason = no_hook_text(
            candidate,
            missing_reason="missing_integer_text",
            unsupported_reason="unsafe_integer_text_rejected",
        )
        if text_reason:
            return default_value, reason
        text = str.strip(text)
    elif allow_exact_text and type(candidate) is bytes:
        try:
            text = bytes(candidate).decode("utf-8", "replace").strip()
        except RECOVERABLE_RUNTIME_ERRORS:
            return default_value, reason
    elif allow_exact_text and type(candidate) is bytearray:
        try:
            text = bytes(candidate).decode("utf-8", "replace").strip()
        except RECOVERABLE_RUNTIME_ERRORS:
            return default_value, reason
    else:
        return default_value, reason
    if not text:
        return default_value, reason
    sign = 1
    digits = text
    if digits[0] in "+-":
        sign = -1 if digits[0] == "-" else 1
        digits = digits[1:]
    if not digits or not digits.isdecimal():
        return default_value, reason
    parsed = sign * int(digits, 10)
    if parsed < 0:
        return default_value, reason
    return parsed, ""

def no_hook_json_key(key: object, index: int, *, prefix: str = "non_materializable_key") -> tuple[str, str]:
    safe_prefix = _reason_prefix_text(prefix, default="non_materializable_key")
    safe_index = _index_text(index)
    text, reason = no_hook_text(
        key,
        missing_reason="missing_json_mapping_key",
        unsupported_reason="invalid_key_type",
    )
    if reason == "" and text != "":
        return text, ""
    if reason == "" and text == "":
        return "empty_" + safe_prefix + "_" + safe_index, "blank_json_mapping_key"
    return safe_prefix + "_" + safe_index, reason


def _mapping_proxy_backing_dict_status(value: object) -> tuple[dict[object, object] | None, str]:
    if type(value) is not _MAPPING_PROXY_TYPE:
        return None, "not_mapping_proxy"
    try:
        referents = gc.get_referents(value)
    except RECOVERABLE_RUNTIME_ERRORS:
        return None, "mapping_proxy_referents_unavailable"
    if len(referents) != 1:
        return None, "mapping_proxy_referent_count_mismatch"
    backing = referents[0]
    if type(backing) is dict:
        return backing, ""
    return None, "mapping_proxy_backing_not_exact_dict"


def _mapping_proxy_backing_dict(value: object) -> dict[object, object] | None:
    backing, _reason = _mapping_proxy_backing_dict_status(value)
    return backing


def _is_owned_dict_instance_status(value: object, *, allow_dict_subclass: bool = False) -> tuple[bool, str]:
    if type(value) is dict:
        return True, ""
    if not allow_dict_subclass or not isinstance(value, dict):
        return False, "not_owned_dict"
    value_type = type(value)
    try:
        owned = (
            type.__getattribute__(value_type, "__iter__") is dict.__iter__
            and type.__getattribute__(value_type, "keys") is dict.keys
            and type.__getattribute__(value_type, "items") is dict.items
            and type.__getattribute__(value_type, "values") is dict.values
            and type.__getattribute__(value_type, "get") is dict.get
        )
    except (AttributeError, TypeError):
        return False, "dict_descriptor_unavailable"
    if owned:
        return True, ""
    return False, "dict_subclass_overrides_boundary_methods"


def _is_owned_dict_instance(value: object, *, allow_dict_subclass: bool = False) -> bool:
    owned, _reason = _is_owned_dict_instance_status(value, allow_dict_subclass=allow_dict_subclass)
    return owned


def no_hook_is_owned_mapping(value: object, *, allow_dict_subclass: bool = False) -> bool:
    """Return whether mapping entries can be read without caller-owned hooks."""
    return _is_owned_dict_instance(value, allow_dict_subclass=allow_dict_subclass) or _mapping_proxy_backing_dict(value) is not None


def no_hook_mapping_items_status(value: object, *, allow_dict_subclass: bool = False) -> tuple[tuple[tuple[object, object], ...] | None, str]:
    """Return mapping items using only built-in dict descriptors."""
    owned, owned_reason = _is_owned_dict_instance_status(value, allow_dict_subclass=allow_dict_subclass)
    if owned:
        try:
            items = tuple(dict.items(value))
        except RECOVERABLE_RUNTIME_ERRORS:
            return None, "mapping_items_unavailable"
        return items, ""
    backing, proxy_reason = _mapping_proxy_backing_dict_status(value)
    if backing is not None:
        try:
            items = tuple(dict.items(backing))
        except RECOVERABLE_RUNTIME_ERRORS:
            return None, "mapping_proxy_items_unavailable"
        return items, ""
    if proxy_reason != "not_mapping_proxy":
        return None, proxy_reason
    return None, owned_reason


def no_hook_mapping_items(value: object, *, allow_dict_subclass: bool = False) -> tuple[tuple[object, object], ...] | None:
    """Return mapping items using only built-in dict descriptors."""
    items, _reason = no_hook_mapping_items_status(value, allow_dict_subclass=allow_dict_subclass)
    return items


def no_hook_sequence_items(value: object) -> tuple[object, ...]:
    """Return boundary sequence items without invoking caller-owned iteration."""
    if value is None:
        return ()
    if type(value) in (str, bytes, bytearray, int, float, bool):
        return (value,)
    if no_hook_mapping_items(value) is not None:
        return (value,)
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value)
    return ()


def no_hook_optional_sequence_items(
    value: object,
    *,
    unsupported: tuple[object, ...] = (),
) -> tuple[object, ...]:
    """Return optional sequence values, including owned ``values`` wrappers.

    This is the canonical contract for boundaries that treat scalar text as one
    item, preserve exact built-in containers, and accept a plain instance whose
    exact ``__dict__`` stores an exact list or tuple under ``values``. Unknown
    objects are never iterated and resolve to the caller-supplied immutable
    unsupported evidence tuple.
    """
    if value is None:
        result: tuple[object, ...] = ()
    elif isinstance(value, (str, bytes)) or type(value) is bytearray:
        result = (value,)
    elif type(value) is tuple:
        result = value
    elif type(value) in (list, set, frozenset):
        result = tuple(value)
    else:
        data = no_hook_plain_instance_dict(value)
        values = dict.get(data, "values") if data is not None else None
        if type(values) is tuple:
            result = values
        elif type(values) is list:
            result = tuple(values)
        else:
            result = unsupported
    return result


def _is_owned_mapping(value: object) -> bool:
    return no_hook_is_owned_mapping(value)


def _is_loaded_internal_dataclass_type_status(value: object) -> tuple[bool, str]:
    value_type = type(value)
    module_name = _safe_type_attr(value, "__module__", default="")
    type_name = _safe_type_attr(value, "__name__", default="")
    if not module_name.startswith(_INTERNAL_MODULE_PREFIX) or type_name == "":
        return False, "not_internal_module_type"
    module = sys.modules.get(module_name)
    module_dict, module_reason = no_hook_module_dict_status(module)
    if module_dict is None:
        return False, "internal_" + module_reason
    if dict.get(module_dict, type_name) is value_type:
        return True, ""
    return False, "module_type_identity_mismatch"


def _is_loaded_internal_dataclass_type(value: object) -> bool:
    loaded, _reason = _is_loaded_internal_dataclass_type_status(value)
    return loaded


def _is_internal_frozen_dataclass_status(value: object) -> tuple[bool, str]:
    if isinstance(value, type):
        return False, "dataclass_type_not_instance"
    if not _is_loaded_internal_dataclass_type(value):
        return False, "not_loaded_internal_dataclass_type"
    if not is_dataclass(value):
        return False, "not_dataclass"
    try:
        params = type.__getattribute__(type(value), "__dataclass_params__")
        frozen = object.__getattribute__(params, "frozen")
    except (AttributeError, TypeError):
        return False, "dataclass_params_unavailable"
    if frozen is True:
        return True, ""
    return False, "dataclass_not_frozen"


def _is_internal_frozen_dataclass(value: object) -> bool:
    accepted, _reason = _is_internal_frozen_dataclass_status(value)
    return accepted


def _limit_exceeded(items: tuple[tuple[object, object], ...] | list[object] | tuple[object, ...] | frozenset[object] | set[object], max_items: int) -> bool:
    return len(items) > max_items


def no_hook_materialize(value: object, *, depth: int = 0, max_depth: int = 12, reason_prefix: str = "json", max_items: int = _DEFAULT_MAX_ITEMS) -> object:
    safe_reason_prefix = _reason_prefix_text(reason_prefix)
    if depth > max_depth:
        return no_hook_failure(_reason_suffix(safe_reason_prefix, "_depth_limit_exceeded"), value)
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is str:
        return str.__str__(value)
    if _is_str_subclass_no_hook(value):
        return str.__str__(value)
    if type(value) is float:
        if math.isfinite(value):
            return value
        return no_hook_failure(_reason_wrapped(safe_reason_prefix, "non_finite_", "_number"), value)
    if type(value) is bytes:
        try:
            return {"bytes_b64": base64.b64encode(bytes(value[:4096])).decode("ascii")}
        except RECOVERABLE_RUNTIME_ERRORS:
            return no_hook_failure(_reason_suffix(safe_reason_prefix, "_bytes_encode_failed"), value)
    if type(value) is bytearray:
        try:
            return {"bytes_b64": base64.b64encode(bytes(value[:4096])).decode("ascii")}
        except RECOVERABLE_RUNTIME_ERRORS:
            return no_hook_failure(_reason_suffix(safe_reason_prefix, "_bytes_encode_failed"), value)
    if _is_owned_mapping(value):
        items = no_hook_mapping_items(value)
        if items is None:
            return no_hook_failure(_reason_suffix(safe_reason_prefix, "_mapping_materialization_failed"), value)
        if len(items) > max_items:
            return no_hook_failure(_reason_suffix(safe_reason_prefix, "_mapping_size_limit_exceeded"), value)
        mapping_out: dict[str, object] = {}
        keyed: list[tuple[str, int, object, str]] = []
        for index, (key, item) in enumerate(items):
            key_text, key_reason = no_hook_json_key(key, index, prefix=_reason_suffix(safe_reason_prefix, "_key"))
            keyed.append((key_text, index, item, key_reason))
        for raw_key_text, index, item, key_reason in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in mapping_out:
                key_text = no_hook_duplicate_key(key_text, index)
            if key_reason:
                mapping_out[key_text] = no_hook_failure(key_reason, item)
            else:
                mapping_out[key_text] = no_hook_materialize(item, depth=depth + 1, max_depth=max_depth, reason_prefix=safe_reason_prefix, max_items=max_items)
        return mapping_out
    if type(value) in (tuple, list):
        if len(value) > max_items:
            return no_hook_failure(_reason_suffix(safe_reason_prefix, "_sequence_size_limit_exceeded"), value)
        return [no_hook_materialize(item, depth=depth + 1, max_depth=max_depth, reason_prefix=safe_reason_prefix, max_items=max_items) for item in value]
    if type(value) in (set, frozenset):
        if len(value) > max_items:
            return no_hook_failure(_reason_suffix(safe_reason_prefix, "_set_size_limit_exceeded"), value)
        materialized = [no_hook_materialize(item, depth=depth + 1, max_depth=max_depth, reason_prefix=safe_reason_prefix, max_items=max_items) for item in value]
        return sorted(materialized, key=no_hook_json_sort_key)
    if _is_internal_frozen_dataclass(value):
        dataclass_out: dict[str, object] = {}
        for field in fields(value):
            try:
                item = object.__getattribute__(value, field.name)
            except RECOVERABLE_RUNTIME_ERRORS:
                dataclass_out[field.name] = no_hook_failure(_reason_suffix(safe_reason_prefix, "_dataclass_field_unavailable"), value)
                continue
            dataclass_out[field.name] = no_hook_materialize(item, depth=depth + 1, max_depth=max_depth, reason_prefix=safe_reason_prefix, max_items=max_items)
        return dataclass_out
    return no_hook_failure(_reason_wrapped(safe_reason_prefix, "non_materializable_", "_value"), value)


def materialize_json_no_hook(value: object, *, context: str = "json", max_depth: int = 12, max_items: int = _DEFAULT_MAX_ITEMS) -> object:
    reason_prefix = _reason_prefix_text(context)
    return no_hook_materialize(value, max_depth=max_depth, reason_prefix=reason_prefix, max_items=max_items)


def materialize_mapping_no_hook(value: object, *, context: str = "json", max_depth: int = 12, max_items: int = _DEFAULT_MAX_ITEMS) -> object:
    reason_prefix = _reason_prefix_text(context)
    if not _is_owned_mapping(value):
        return no_hook_failure(_reason_wrapped(reason_prefix, "non_materializable_", "_mapping"), value)
    return no_hook_materialize(value, max_depth=max_depth, reason_prefix=reason_prefix, max_items=max_items)


def no_hook_json_sort_key(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except RECOVERABLE_RUNTIME_ERRORS:
        return no_hook_type_name(value) + ":json_sort_unavailable"


__all__ = (
    "exact_bool_or_none",
    "exact_finite_float_or_none",
    "exact_int_or_none",
    "exact_text_or_none",
    "invalid_key_evidence",
    "is_exact_text",
    "materialize_json_no_hook",
    "materialize_mapping_no_hook",
    "no_hook_duplicate_key",
    "no_hook_exact_nonnegative_int",
    "no_hook_exact_owner_field",
    "no_hook_exact_owner_field_status",
    "no_hook_failure",
    "no_hook_finite_float",
    "no_hook_internal_frozen_dataclass_status",
    "no_hook_is_owned_mapping",
    "no_hook_json_key",
    "no_hook_json_sort_key",
    "no_hook_mapping_items",
    "no_hook_mapping_items_status",
    "no_hook_materialize",
    "no_hook_module_dict_status",
    "no_hook_optional_sequence_items",
    "no_hook_plain_instance_dict",
    "no_hook_plain_instance_dict_status",
    "no_hook_sequence_items",
    "no_hook_text",
    "no_hook_type_name",
    "unsupported_value_evidence",
)
