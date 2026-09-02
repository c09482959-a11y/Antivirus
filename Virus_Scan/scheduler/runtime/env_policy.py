"""Scheduler-owned runtime environment value parsing helpers."""
from __future__ import annotations

import os
from typing import Mapping, MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.contracts.evidence_record_support import (
    scheduler_mapping_items,
    scheduler_mapping_value,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_value_snapshot,
)


def _record_env_rejection(
    *,
    parser: str,
    name: object,
    value: object,
    safe_default: object,
    reason: str,
) -> None:
    setting = name if type(name) is str and name else "unknown_scheduler_setting"
    record_suppressed_failure(
        "scheduler_env_" + parser + "_rejected",
        ValueError(reason),
        domain="scheduler",
        context={
            "scheduler_environment_value_rejected": True,
            "setting": setting,
            "reason": reason,
            "value_type": no_hook_type_name(value),
            "value": scheduler_value_snapshot(value, field_name=setting),
            "default_value": scheduler_value_snapshot(safe_default, field_name=setting + "_default"),
        },
    )


def _snapshot_env_value(env: Mapping[str, str], name: object, default: object) -> tuple[object, str]:
    if type(name) is not str or name == "":
        return default, "scheduler_env_name_rejected"
    snapshot = scheduler_environment_snapshot(env)
    items = scheduler_mapping_items(snapshot)
    if items is None:
        return default, "scheduler_environment_snapshot_rejected"
    if scheduler_mapping_value(snapshot, "scheduler_mapping_unavailable") is True:
        return default, "scheduler_environment_mapping_rejected"
    return scheduler_mapping_value(snapshot, name, default=default), ""


def float_env(
    env: Mapping[str, str],
    name: str,
    default: float,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> float:
    del recoverable_exceptions
    safe_default, default_reason = scheduler_float(
        default,
        default=0.0,
        reason="scheduler_env_float_default_rejected",
    )
    if default_reason:
        _record_env_rejection(
            parser="float_default",
            name=name,
            value=default,
            safe_default=0.0,
            reason=default_reason,
        )
    value, snapshot_reason = _snapshot_env_value(env, name, safe_default)
    metric, reason = scheduler_float(
        value,
        default=safe_default,
        reason="scheduler_env_float_value_rejected",
    )
    rejection = snapshot_reason or reason
    if rejection:
        _record_env_rejection(
            parser="float",
            name=name,
            value=value,
            safe_default=safe_default,
            reason=rejection,
        )
        return safe_default
    return metric


def int_env(
    env: Mapping[str, str],
    name: str,
    default: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> int:
    del recoverable_exceptions
    safe_default, default_reason = scheduler_int(
        default,
        default=0,
        reason="scheduler_env_integer_default_rejected",
    )
    if default_reason:
        _record_env_rejection(
            parser="integer_default",
            name=name,
            value=default,
            safe_default=0,
            reason=default_reason,
        )
    value, snapshot_reason = _snapshot_env_value(env, name, safe_default)
    parsed, reason = scheduler_int(
        value,
        default=safe_default,
        reason="scheduler_env_integer_value_rejected",
    )
    rejection = snapshot_reason or reason
    if rejection:
        _record_env_rejection(
            parser="integer",
            name=name,
            value=value,
            safe_default=safe_default,
            reason=rejection,
        )
        return safe_default
    return parsed


def bool_env(
    env: Mapping[str, str],
    name: str,
    default: bool,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    del recoverable_exceptions
    safe_default = default if type(default) is bool else False
    if type(default) is not bool:
        _record_env_rejection(
            parser="bool_default",
            name=name,
            value=default,
            safe_default=False,
            reason="scheduler_env_bool_default_rejected",
        )
    value, snapshot_reason = _snapshot_env_value(env, name, safe_default)
    parsed, reason = scheduler_bool(
        value,
        default=safe_default,
        reason="scheduler_env_bool_value_rejected",
    )
    rejection = snapshot_reason or reason
    if rejection:
        _record_env_rejection(
            parser="bool",
            name=name,
            value=value,
            safe_default=safe_default,
            reason=rejection,
        )
        return safe_default
    return parsed


def scheduler_environment_snapshot(env: Mapping[str, str] | None = None) -> Mapping[str, str]:
    """Return the scheduler-owned immutable process-environment snapshot."""

    if env is None:
        return immutable_mapping(dict(os.environ))
    return immutable_mapping(env)


def scheduler_environment_writer(
    env: MutableMapping[str, str] | None = None,
) -> MutableMapping[str, str]:
    """Return the scheduler-owned environment publication target."""

    return os.environ if env is None else env


__all__ = (
    "bool_env",
    "float_env",
    "int_env",
    "scheduler_environment_snapshot",
    "scheduler_environment_writer",
)
