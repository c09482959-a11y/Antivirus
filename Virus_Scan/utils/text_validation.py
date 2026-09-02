"""Direct-import-safe text normalization helpers."""
from __future__ import annotations
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath


from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict

_TEXT_SCALAR_TYPES = (int, float, bool)
_SAFE_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)


def _is_str_subclass_no_hook(value: object) -> bool:
    value_type = type(value)
    if value_type is str:
        return True
    try:
        mro = type.__getattribute__(value_type, "__mro__")
    except (*IO_CONFIGURATION_ERRORS, AttributeError, TypeError):
        return False
    return type(mro) is tuple and str in mro


def _stdlib_path_text(value: PurePath) -> str:
    """Return deterministic path evidence without caller-owned path hooks."""
    return PurePath.__str__(value).replace("\\", "/")


def _declares_rejected_materialization_hook(value: object) -> bool:
    rejected = False
    try:
        mro = type.__getattribute__(type(value), "__mro__")
    except (*IO_CONFIGURATION_ERRORS, AttributeError, TypeError):
        mro = ()
        rejected = True
    for cls in mro:
        if cls is object:
            continue
        try:
            namespace = type.__getattribute__(cls, "__dict__")
        except (*IO_CONFIGURATION_ERRORS, AttributeError, TypeError):
            rejected = True
            break
        if "__fspath__" in namespace or "__iter__" in namespace or "__float__" in namespace or "__int__" in namespace:
            return True
    return rejected


def _exact_text_boundary_value(value: object) -> tuple[bool, str]:
    handled = True
    if _is_str_subclass_no_hook(value):
        text = str.__str__(value)
    elif type(value) is bytes:
        text = bytes.decode(value, "latin1", errors="ignore")
    elif type(value) is bytearray:
        text = bytes(value).decode("latin1", errors="ignore")
    elif type(value) is memoryview:
        text = bytes(value).decode("latin1", errors="ignore")
    elif type(value) in _SAFE_PATH_TYPES:
        text = _stdlib_path_text(value)
    elif type(value) in _TEXT_SCALAR_TYPES:
        text = repr(value)
    else:
        handled, text = False, ""
    return handled, text


def _plain_instance_text_boundary_value(value: object) -> tuple[bool, str]:
    fields = no_hook_plain_instance_dict(value)
    handled, text = False, ""
    if type(fields) is dict:
        for field_name in ("text", "_text", "value"):
            if field_name not in fields:
                continue
            field_value = dict.__getitem__(fields, field_name)
            handled, text = _exact_text_boundary_value(field_value)
            if handled:
                break
    return handled, text


def text_boundary_value(value: object, *, unsupported: str | None = "") -> str | None:
    """Project caller text without invoking caller-owned conversion hooks.

    Only exact primitive/path owner types are materialized.  Custom path-like,
    numeric-like, iterable-like, or descriptor-backed objects are rejected before
    ``__fspath__``, ``__str__``, ``__repr__``, ``__format__``, ``__iter__``, or
    truthiness hooks can run.
    """
    if value is None:
        return ""
    handled, text = _exact_text_boundary_value(value)
    if handled:
        return text
    if _declares_rejected_materialization_hook(value):
        return unsupported
    handled, text = _plain_instance_text_boundary_value(value)
    if handled:
        return text
    return unsupported


def _text_boundary_value(value: object) -> str:
    text = text_boundary_value(value, unsupported="")
    return text if text is not None else ""


def tag_validation_text(strings_blob: object = "") -> str:
    return _text_boundary_value(strings_blob).lower()


__all__ = ("tag_validation_text", "text_boundary_value")
