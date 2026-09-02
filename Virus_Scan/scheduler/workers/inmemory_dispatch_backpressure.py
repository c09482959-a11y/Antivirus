"""Worker-owned in-memory dispatch backpressure decisions."""
from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.scheduler.workers.dispatch_value_support import positive_worker_int
from collections.abc import Mapping
from typing import Callable

_BACKPRESSURE_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError)


def decide_inmemory_dispatch_backpressure(
    *,
    active_heavy_weight: int,
    logical_slots: int,
    workers: int,
    pressure_snapshot: Mapping[str, object] | None,
    suppressed_recorder: Callable[[str, BaseException], None] | None = None,
) -> tuple[bool, str]:
    """Return whether in-memory dispatch should pause and the deterministic reason.

    This owns only worker-dispatch backpressure decisions. It does not mutate
    queue, retry, timeout, evidence, or replay state.
    """
    try:
        if type(pressure_snapshot) is dict:
            pressure_value = dict.get(pressure_snapshot, "pressure")
            pressure = str.__str__(pressure_value) if type(pressure_value) is str else "unknown"
        else:
            pressure = "unknown"
        if pressure == "critical":
            return (True, "memory_critical")
        if pressure == "high":
            safe_slots = positive_worker_int(logical_slots, "dispatch_logical_slots_rejected")
            safe_workers = positive_worker_int(workers, "dispatch_workers_rejected")
            default_cap_value = max(safe_slots * 4, safe_workers * 8)
            heavy_hard_cap = int_env("UMIGE_INMEMORY_HEAVY_BACKPRESSURE_WEIGHT", default_cap_value, 1, None)
            if active_heavy_weight > heavy_hard_cap:
                return (True, "memory_high_heavy_hard_cap")
    except _BACKPRESSURE_EXCEPTIONS as exc:
        if suppressed_recorder is not None:
            try:
                suppressed_recorder("inmemory_runtime_suppressed_exception", exc)
            except _BACKPRESSURE_EXCEPTIONS as record_exc:
                _ = record_exc
    return (False, "")
