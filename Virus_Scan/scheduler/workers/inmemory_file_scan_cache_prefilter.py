"""Cache lookup and fast-prefilter helpers for in-memory file scans."""
from __future__ import annotations

import time
from collections.abc import Callable

from Virus_Scan.scheduler.execution.scheduler_yara_result import cached_scheduler_yara_result


def cached_inmemory_scan_result(
    *,
    path: object,
    started_file: float,
    slow_file_warn_sec: float,
    active_timeout_budget: object,
    compiled_rules: object,
    cache_execution_identity: object,
    artifact_read_snapshot: object,
    pre_scan_cache_lookup: Callable[..., object],
) -> tuple[object, object | None]:
    """Return cache hash plus a completed cache-hit result when available."""
    cache_hit_result, cache_sha256 = pre_scan_cache_lookup(
        artifact_read_snapshot, execution_identity=cache_execution_identity,
    )
    if cache_hit_result is None:
        return cache_sha256, None
    if cached_scheduler_yara_result(cache_hit_result, cache_execution_identity) is None:
        return cache_sha256, None
    elapsed_file = time.time() - started_file
    cache_hit_result["scan_duration_seconds"] = round(elapsed_file, 6)
    cache_hit_result["timeout_evidence"] = active_timeout_budget.as_evidence()
    if slow_file_warn_sec and elapsed_file > slow_file_warn_sec:
        cache_hit_result["slow_file_seconds"] = round(elapsed_file, 3)
    return cache_sha256, (path, cache_hit_result)


def prefilter_inmemory_context(
    *,
    path: object,
    compiled_rules: object,
    artifact_read_snapshot: object,
    strict_fast_prefilter: Callable[..., object],
) -> object:
    """Return prefilter context without a mode-specific terminal result."""
    prefilter_info = strict_fast_prefilter(
        path,
        compiled_rules=compiled_rules,
        artifact_read_snapshot=artifact_read_snapshot,
    )
    if not isinstance(prefilter_info, dict):
        raise TypeError("inmemory_prefilter_record_invalid")
    if dict.get(prefilter_info, "fast_result") is None:
        return prefilter_info
    detached = dict(prefilter_info)
    detached["fast_result"] = None
    raw_meta = dict.get(prefilter_info, "meta")
    meta = dict(raw_meta) if type(raw_meta) is dict else {}
    meta["scheduler_terminal_shortcut_rejected"] = "mode_semantic_equivalence_required"
    detached["meta"] = meta
    return detached


__all__ = ("cached_inmemory_scan_result", "prefilter_inmemory_context")
