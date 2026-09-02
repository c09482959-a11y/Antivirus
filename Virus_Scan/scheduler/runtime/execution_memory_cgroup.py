"""Linux cgroup-v2 execution-memory boundary parsing for scheduler capacity."""
from __future__ import annotations

from pathlib import Path


def _read_int(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8", errors="strict").strip()
        if text == "max":
            return None
        value = int(text, 10)
        return value if value >= 0 else None
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError):
        return None


def cgroup_committed_bytes(memory_stat: str, *, current_bytes: int) -> int:
    """Return non-reclaimable commitment from cgroup ``memory.stat``.

    File cache is excluded by construction. ``kernel`` includes slab, so its
    explicitly reclaimable slab component is removed before admission policy
    consumes the value. Missing required counters fail closed to total current
    usage rather than manufacturing spare capacity.
    """
    if type(memory_stat) is not str or type(current_bytes) is not int or type(current_bytes) is bool or current_bytes < 0:
        raise TypeError("scheduler_cgroup_memory_stat_invalid")
    stats: dict[str, int] = {}
    for line in memory_stat.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            raise ValueError("scheduler_cgroup_memory_stat_invalid")
        name, raw = fields
        value = int(raw, 10)
        if value < 0:
            raise ValueError("scheduler_cgroup_memory_stat_invalid")
        stats[name] = value
    if "anon" not in stats or "kernel" not in stats:
        return current_bytes
    nonreclaimable_kernel = max(0, stats["kernel"] - stats.get("slab_reclaimable", 0))
    return min(current_bytes, stats["anon"] + nonreclaimable_kernel)


def cgroup_v2_memory_boundary() -> tuple[int, int, int] | None:
    root = Path("/sys/fs/cgroup")
    limit, current = _read_int(root / "memory.max"), _read_int(root / "memory.current")
    if limit is None or limit <= 0 or current is None:
        return None
    try:
        stat = (root / "memory.stat").read_text(encoding="utf-8", errors="strict")
        committed = cgroup_committed_bytes(stat, current_bytes=current)
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError):
        committed = current
    return limit, current, committed


__all__ = ("cgroup_committed_bytes", "cgroup_v2_memory_boundary")
