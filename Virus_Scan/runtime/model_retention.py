"""Runtime-owned model retention and pruning hooks.

Runtime owns mutable learned model state, temporal state, cache pruning, and the
periodic dirty-state retention trigger.  Model/profile retention policy remains
in :mod:`Virus_Scan.models.retention`; this module owns live runtime pruning so
callers do not reach into model modules for runtime mutation.
"""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.cache_state import prune_runtime_caches_for_retention
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.model_state import prune_runtime_model_mappings_for_retention
from Virus_Scan.runtime.retention_runtime_state import retention_runtime_state
from Virus_Scan.runtime.temporal_state import prune_temporal_state_for_retention
from Virus_Scan.runtime.structured_failures import record_suppressed_failure


def _retention_limit_reason(name: str, suffix: str) -> str:
    if type(name) is not str or type(suffix) is not str:
        return "runtime_retention_limit_name_rejected"
    name_text = str.__str__(name)
    suffix_text = str.__str__(suffix)
    if not name_text or not suffix_text:
        return "runtime_retention_limit_name_rejected"
    return str.lower(name_text) + suffix_text


def _retention_limit(name: str, default: int) -> int:
    if type(name) is not str:
        raise RuntimeError("runtime_retention_limit_name_rejected")
    rejected_reason = _retention_limit_reason(name, "_rejected")
    below_minimum_reason = _retention_limit_reason(name, "_below_minimum")
    raw = get_init_value(name)
    if raw is None:
        return default
    value, reason = no_hook_exact_nonnegative_int(
        raw,
        default=default,
        reason=rejected_reason,
        non_finite_reason=rejected_reason,
        allow_exact_text=True,
    )
    if reason:
        raise RuntimeError(reason)
    if value < 1:
        raise RuntimeError(below_minimum_reason)
    return value


MAX_TRANSITION_KEYS = _retention_limit("MAX_TRANSITION_KEYS", 50000)
MAX_TRANSITION_NEXT_KEYS = _retention_limit("MAX_TRANSITION_NEXT_KEYS", 512)
MAX_TAG_COUNTER_KEYS = _retention_limit("MAX_TAG_COUNTER_KEYS", 25000)
MAX_PAIR_COUNTER_KEYS = _retention_limit("MAX_PAIR_COUNTER_KEYS", 50000)
MAX_FILETYPE_BASELINES = _retention_limit("MAX_FILETYPE_BASELINES", 1024)
MAX_TEMPORAL_NODES = _retention_limit("MAX_TEMPORAL_NODES", 50000)
MAX_TEMPORAL_HISTORY_PER_NODE = _retention_limit("MAX_TEMPORAL_HISTORY_PER_NODE", 64)
MAX_CACHE_ITEMS_PER_MAP = _retention_limit("MAX_CACHE_ITEMS_PER_MAP", 50000)
CACHE_PRUNE_EVERY_UPDATES = _retention_limit("CACHE_PRUNE_EVERY_UPDATES", 2000)


def prune_runtime_model_state_in_memory() -> None:
    """Bound live runtime model owners before persistence or dirty-state growth."""
    try:
        prune_runtime_model_mappings_for_retention(
            max_transition_keys=MAX_TRANSITION_KEYS,
            max_transition_next_keys=MAX_TRANSITION_NEXT_KEYS,
            max_tag_counter_keys=MAX_TAG_COUNTER_KEYS,
            max_pair_counter_keys=MAX_PAIR_COUNTER_KEYS,
            max_filetype_baselines=MAX_FILETYPE_BASELINES,
        )
        prune_temporal_state_for_retention(
            max_nodes=MAX_TEMPORAL_NODES,
            max_history_per_node=MAX_TEMPORAL_HISTORY_PER_NODE,
        )
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure(
            "runtime_model_prune_failed", exc, domain="runtime"
        )


def maybe_prune_bounded_runtime(*, force: bool = False) -> None:
    """Run the periodic runtime pruning hook without model-layer ownership leaks."""
    try:
        if not retention_runtime_state().should_prune(CACHE_PRUNE_EVERY_UPDATES, force=force):
            return
        prune_runtime_model_state_in_memory()
        prune_runtime_caches_for_retention(max_items=MAX_CACHE_ITEMS_PER_MAP)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure(
            "bounded_runtime_prune_hook_failed", exc, domain="runtime"
        )


__all__ = ("maybe_prune_bounded_runtime", "prune_runtime_model_state_in_memory")
