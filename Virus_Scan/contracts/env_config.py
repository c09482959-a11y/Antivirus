"""Import-light environment parsing contract.

Owns primitive env parsing so replay, telemetry, resource economics, and config do
not duplicate economic-control helpers. Environment values are materialized with
owned primitive conversions only; caller-provided test readers cannot force
``__str__``, ``__int__``, ``__float__``, truthiness, or mapping hooks.
"""
from __future__ import annotations
import os

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text

_PROCESS_ENVIRON_TYPE = type(os.environ)


def _primitive_int(value: object, default: int) -> tuple[int, str]:
    if type(value) is bool:
        return int(default), "unsafe_numeric_value_rejected"
    if type(value) is int:
        return value, ""
    text, reason = no_hook_text(value, unsupported_reason="unsafe_env_value_rejected")
    if reason:
        return int(default), reason
    try:
        return int(str.__str__(text).strip()), ""
    except (TypeError, ValueError, OverflowError):
        return int(default), "parse_error"


def _primitive_float(value: object, default: float) -> tuple[float, str]:
    metric, reason = no_hook_finite_float(
        value,
        default=float(default),
        reason="unsafe_env_value_rejected",
        non_finite_reason="non_finite_env_value",
        allow_exact_text=True,
    )
    return metric, reason


def _clamp_int(value: int, minimum: int = 0, maximum: int | None = None) -> int:
    value = max(int(minimum), value)
    if maximum is not None:
        value = min(int(maximum), value)
    return value


def int_env(name: str, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        raw = os.environ.get(name, default)
    except (TypeError, ValueError, OSError):
        raw = default
    value, _reason = _primitive_int(raw if raw not in (None, "") else default, int(default))
    return _clamp_int(value, minimum, maximum)


def int_env_status(name: str, default: int, minimum: int = 0, maximum: int | None = None, *, env_reader: object = None) -> tuple[str, int]:
    reader = env_reader if env_reader is not None else os.environ.get
    try:
        raw = reader(name, default)
    except (TypeError, ValueError, OSError):
        raw = default
        status = "parse_error"
    else:
        status = "valid"
    value, reason = _primitive_int(raw if raw not in (None, "") else default, int(default))
    if reason:
        status = "parse_error" if reason in {"parse_error", "unsafe_env_value_rejected"} else reason
    return status, _clamp_int(value, minimum, maximum)


def _process_environment_items(environment: object = None) -> tuple[tuple[tuple[object, object], ...], str]:
    if environment is None:
        environment = os.environ
    if type(environment) is not _PROCESS_ENVIRON_TYPE:
        return ((), "unsupported_process_environment_mapping")
    try:
        return (tuple(_PROCESS_ENVIRON_TYPE.items(environment)), "")
    except (TypeError, ValueError, OSError):
        return ((), "process_environment_items_unavailable")


def env_contains_text_status(*needles: str, environment: object = None) -> tuple[bool, str]:
    cleaned_items: list[str] = []
    for needle in needles:
        text, reason = no_hook_text(needle, unsupported_reason="unsafe_env_needle_rejected")
        if reason:
            continue
        cleaned = str.__str__(text).strip().lower()
        if cleaned:
            cleaned_items.append(cleaned)
    cleaned_needles = tuple(cleaned_items)
    if not cleaned_needles:
        return (False, "no_env_needles")
    env_items, env_reason = _process_environment_items(environment)
    if env_reason:
        return (False, env_reason)
    texts = []
    for key, value in env_items:
        key_text, key_reason = no_hook_text(key, unsupported_reason="unsafe_env_key_rejected")
        value_text, value_reason = no_hook_text(value, unsupported_reason="unsafe_env_value_rejected")
        if not key_reason:
            texts.append(str.__str__(key_text).lower())
        if not value_reason:
            texts.append(str.__str__(value_text).lower())
    joined = " ".join(texts)
    return (any(needle in joined for needle in cleaned_needles), "matched_env_text")


def env_contains_text(*needles: str) -> bool:
    matched, _reason = env_contains_text_status(*needles)
    return matched is True


def float_env(name: str, default: float, minimum: float = 0.0, maximum: float | None = None) -> float:
    try:
        raw = os.environ.get(name, default)
    except (TypeError, ValueError, OSError):
        raw = default
    value, _reason = _primitive_float(raw if raw not in (None, "") else default, float(default))
    if maximum is not None:
        value = min(float(maximum), value)
    return max(float(minimum), value)


def bool_env(name: str, default: bool = False) -> bool:
    default_text = "1" if default else "0"
    try:
        raw = os.environ.get(name, default_text)
    except (TypeError, ValueError, OSError):
        return bool(default)
    text, reason = no_hook_text(raw if raw not in (None, "") else default_text, unsupported_reason="unsafe_env_value_rejected")
    if reason:
        return bool(default)
    return str.__str__(text).strip().lower() not in {"0", "false", "no", "off"}


def str_env(name: str, default: str = "") -> str:
    try:
        raw = os.environ.get(name, default)
    except (TypeError, ValueError, OSError):
        raw = default
    text, reason = no_hook_text(raw if raw not in (None, "") else default, unsupported_reason="unsafe_env_value_rejected")
    if reason:
        default_text, default_reason = no_hook_text(default, unsupported_reason="unsafe_env_default_rejected")
        return "" if default_reason else default_text
    return text


__all__ = ("bool_env", "env_contains_text", "env_contains_text_status", "float_env", "int_env", "int_env_status", "str_env")
