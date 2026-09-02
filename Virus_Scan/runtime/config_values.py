"""Read-only runtime configuration value access.

Configuration is resolved from environment overrides first and then from
canonical init-state publication snapshots.  Callers cannot mutate shared
runtime state or synchronize module namespaces through this API.
"""
from __future__ import annotations

import os

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_text,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.structured_failures import record_suppressed_failure

_ENV_PREFIX = "UMIGE_"


def runtime_value(name: str, default: object = None) -> object:
    key, reason = no_hook_text(
        name,
        missing_reason="runtime_config_name_missing",
        unsupported_reason="runtime_config_name_rejected",
    )
    if reason or key == "":
        record_suppressed_failure(
            "runtime_config_name_rejected",
            ValueError(reason or "runtime_config_name_blank"),
            domain="runtime_config",
        )
        return default
    env_key = _ENV_PREFIX + key
    if env_key in os.environ:
        return os.environ.get(env_key)
    try:
        return get_init_value(key, default)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure(
            "runtime_config_value_read_failed", exc, domain="runtime_config"
        )
        return default


def runtime_bool(name: str, *, default: bool = False) -> bool:
    value = runtime_value(name, default)
    if type(value) is bool:
        return value
    if type(value) is int and type(value) is not bool:
        return value != 0
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off", ""}:
            return False
    record_suppressed_failure(
        "runtime_config_bool_rejected",
        ValueError("runtime_config_bool_rejected"),
        domain="runtime_config",
    )
    return default if type(default) is bool else False


def runtime_int(name: str, default: int = 0) -> int:
    base_value = default if type(default) is int and type(default) is not bool else 0
    value, reason = no_hook_exact_nonnegative_int(
        runtime_value(name, base_value),
        default=max(0, base_value),
        reason="runtime_config_int_rejected",
        allow_exact_text=True,
    )
    if reason:
        record_suppressed_failure(
            "runtime_config_int_rejected", ValueError(reason), domain="runtime_config"
        )
    return value


def runtime_mapping(name: str, default: object = None) -> object:
    value = runtime_value(name, default)
    return value if value is not None else default


__all__ = ("runtime_bool", "runtime_int", "runtime_mapping", "runtime_value")
