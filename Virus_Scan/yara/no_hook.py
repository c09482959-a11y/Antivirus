"""No-hook materialization helpers for YARA boundaries."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
)
from Virus_Scan.runtime.structured_failures import safe_exception_message
from Virus_Scan.utils.text_validation import text_boundary_value


def yara_text(value: object, *, default: str = "") -> str:
    text = text_boundary_value(value, unsupported=None)
    if type(text) is str:
        return str.__str__(text)
    return default


def yara_lower_text(value: object, *, default: str = "") -> str:
    return yara_text(value, default=default).lower()


def yara_exception_text(exc: BaseException | str) -> str:
    text = safe_exception_message(exc)
    return str.__str__(text) if type(text) is str else ""


def yara_message(*parts: object) -> str:
    out: list[str] = []
    for part in parts:
        if isinstance(part, BaseException):
            out.append(yara_exception_text(part))
        else:
            out.append(yara_text(part))
    return "".join(out)


def yara_nonnegative_int(value: object, *, default: int = 0) -> int:
    number, reason = no_hook_exact_nonnegative_int(value, default=default, reason="invalid_yara_integer")
    return default if reason else number


def yara_positive_int(value: object, *, default: int = 1) -> int:
    number = yara_nonnegative_int(value, default=default)
    return max(1, number)


def yara_float(value: object, *, default: float = 0.0) -> float:
    metric, reason = no_hook_finite_float(value, default=default, reason="invalid_yara_float")
    return default if reason else metric


def yara_mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    return no_hook_mapping_items(value) or ()


def yara_mapping_get(value: object, key: str, default: object = None) -> object:
    for candidate, item in yara_mapping_items(value):
        if type(candidate) is str and candidate == key:
            return item
    return default


def yara_plain_attr(value: object, name: str, default: object = None) -> object:
    data = no_hook_plain_instance_dict(value)
    if data is not None and name in data:
        return dict.__getitem__(data, name)
    class_dict = None
    try:
        class_dict = type.__getattribute__(type(value), "__dict__")
    except (AttributeError, TypeError):
        class_dict = None
    if type(class_dict) is not dict:
        return default
    raw = dict.get(class_dict, name)
    if type(raw) in (str, bytes, bytearray, memoryview, int, float, bool):
        return raw
    return default


def yara_bytes(value: object) -> bytes:
    if type(value) is bytes:
        return bytes(value)
    if type(value) is bytearray:
        return bytes(value)
    return b""


def yara_temp_path(base: object, *parts: object, suffix: str = "tmp") -> str:
    cleaned = [yara_text(base), *(yara_text(part) for part in parts), suffix]
    return ".".join(item for item in cleaned if item != "")


__all__ = (
    "yara_bytes",
    "yara_exception_text",
    "yara_float",
    "yara_lower_text",
    "yara_mapping_get",
    "yara_mapping_items",
    "yara_message",
    "yara_nonnegative_int",
    "yara_plain_attr",
    "yara_positive_int",
    "yara_temp_path",
    "yara_text",
)
