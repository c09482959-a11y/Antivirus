"""No-hook environment readers for in-memory scheduler runtime config."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int, scheduler_text


@dataclass(frozen=True, slots=True)
class InMemoryRuntimeEnvValueDecision:
    value: object
    reason: str
    found: bool
    source_is_mapping: bool

    def as_value(self) -> object:
        return self.value


def env_value_decision(environ: Mapping[str, str], name: str) -> InMemoryRuntimeEnvValueDecision:
    items = no_hook_mapping_items(environ)
    if items is None:
        return InMemoryRuntimeEnvValueDecision(
            value=None,
            reason="inmemory_runtime_env_source_rejected",
            found=False,
            source_is_mapping=False,
        )
    missing = object()
    value = scheduler_mapping_item_value(items, name, missing)
    if value is missing:
        return InMemoryRuntimeEnvValueDecision(
            value=None,
            reason="inmemory_runtime_env_value_missing",
            found=False,
            source_is_mapping=True,
        )
    return InMemoryRuntimeEnvValueDecision(
        value=value,
        reason="",
        found=True,
        source_is_mapping=True,
    )


def env_value(environ: Mapping[str, str], name: str) -> object:
    return env_value_decision(environ, name).as_value()


def env_int(environ: Mapping[str, str], name: str, default: int) -> int:
    parsed, reason = scheduler_int(
        env_value(environ, name),
        default=default,
        reason="inmemory_runtime_env_int_rejected",
    )
    return default if reason != "" else parsed


def env_int_required(environ: Mapping[str, str], name: str, default: int) -> int:
    raw_value = env_value(environ, name)
    if raw_value is None:
        return default
    parsed, reason = scheduler_int(
        raw_value,
        default=default,
        reason="inmemory_runtime_env_int_rejected",
    )
    if reason != "":
        raise ValueError(reason)
    return parsed


def env_float(environ: Mapping[str, str], name: str, default: float) -> float:
    parsed, reason = scheduler_float(
        env_value(environ, name),
        default=default,
        reason="inmemory_runtime_env_float_rejected",
    )
    return default if reason != "" else parsed


def env_text(environ: Mapping[str, str], name: str, default: str) -> str:
    text, reason = scheduler_text(env_value(environ, name), replacement_text=default)
    if reason != "" or text == "":
        return default
    return text


__all__ = ("InMemoryRuntimeEnvValueDecision", "env_float", "env_int", "env_int_required", "env_text", "env_value", "env_value_decision")
