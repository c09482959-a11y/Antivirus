"""Runtime-owned raw collector worker capacity calculations."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_text_mapping_from_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text, scheduler_value_snapshot
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot

SCHEDULER_STAGE_PARALLEL_DEFAULT_WORKERS = 6


def _int_result(value: object, *, policy_default: int, minimum: int = 1, maximum: int | None = None, setting: str) -> tuple[int, str]:
    parsed, reason = scheduler_int(value, default=policy_default, minimum=minimum, maximum=maximum, reason="scheduler_raw_capacity_integer_rejected")
    if reason:
        record_suppressed_failure(
            "scheduler_raw_capacity_integer_rejected",
            ValueError(reason),
            domain="scheduler",
            context={
                "setting": setting,
                "reason": reason,
                "value_type": no_hook_type_name(value),
                "value": scheduler_value_snapshot(value, field_name=setting),
                "policy_default": scheduler_value_snapshot(policy_default, field_name=setting + "_policy_default"),
            },
        )
    return parsed, reason


def _raw_capacity_env(env: object) -> Mapping[str, str] | None:
    if env is None:
        return None
    snapshot = scheduler_str_text_mapping_from_items(no_hook_mapping_items(env))
    if not snapshot and not isinstance(env, Mapping):
        return None
    return snapshot


def stage_parallel_workers(default: object=SCHEDULER_STAGE_PARALLEL_DEFAULT_WORKERS, *, env: object=None) -> int:
    source = scheduler_environment_snapshot(_raw_capacity_env(env))
    policy_default, _policy_default_reason = _int_result(
        default,
        policy_default=SCHEDULER_STAGE_PARALLEL_DEFAULT_WORKERS,
        minimum=1,
        maximum=64,
        setting="stage_parallel_workers_default",
    )
    workers, _workers_reason = _int_result(
        source.get("UMIGE_STAGE_PARALLEL_WORKERS", policy_default),
        policy_default=policy_default,
        minimum=1,
        maximum=64,
        setting="UMIGE_STAGE_PARALLEL_WORKERS",
    )
    return workers


def raw_worker_pool_cap(queue_dir: object = None, *, env: object = None) -> int:
    # queue_dir is retained for the scheduler worker-capacity callback contract;
    # the current cap is derived from explicit environment policy.
    _ = queue_dir
    source = scheduler_environment_snapshot(_raw_capacity_env(env))
    try:
        configured = source.get("UMIGE_RAW_WORKER_POOL_CAP")
        if configured is not None and not (type(configured) is str and configured == ""):
            configured_cap, configured_reason = _int_result(configured, policy_default=4, minimum=1, maximum=64, setting="UMIGE_RAW_WORKER_POOL_CAP")
            if configured_reason == "":
                return configured_cap
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        try:
            record_suppressed_failure("suppressed_exception", exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc
    max_children, _max_children_reason = _int_result(
        source.get("UMIGE_PROCESS_QUEUE_MAX_CHILDREN", "100"),
        policy_default=100,
        minimum=1,
        setting="UMIGE_PROCESS_QUEUE_MAX_CHILDREN",
    )
    return max(4, min(64, int(max_children * 0.48)))


def raw_collector_cap(collector: object = None, *, runtime_int: Callable[..., int] | None = None, runtime_value: Callable[..., int] | None = None) -> int:
    """Return collector admission cap through explicit runtime configuration."""
    runtime_reader = runtime_int if runtime_int is not None else runtime_value
    if runtime_reader is None:
        runtime_reader = lambda _name, default: default
    name, reason = scheduler_text(collector, replacement_text="", unsupported_reason="raw_collector_name_rejected")
    if reason:
        name = ""
    default_cap = runtime_reader("RAW_PER_FILE_ACTIVE_CAP", 128)
    if name == "decode":
        return runtime_reader("RAW_DECODE_CAP", default_cap)
    if name == "payload":
        return runtime_reader("RAW_PAYLOAD_CAP", default_cap)
    if name in {"pe_api", "pe_api_chunk"}:
        return runtime_reader("RAW_PE_API_CAP", default_cap)
    if name == "binary_context":
        return runtime_reader("RAW_BINARY_CONTEXT_CAP", default_cap)
    if name in {"renpy", "renpy_chunk"}:
        return runtime_reader("RAW_RENPY_CAP", default_cap)
    return default_cap


__all__ = ("raw_collector_cap", "raw_worker_pool_cap", "stage_parallel_workers")
