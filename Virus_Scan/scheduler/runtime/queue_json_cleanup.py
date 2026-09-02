"""Temporary queue JSON cleanup decisions for scheduler persistence."""
from __future__ import annotations

import hashlib
import time

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_safe_unlink
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS, record_queue_json_degraded
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

QUEUE_JSON_CLEANUP_NONE_REMOVED = 0
QUEUE_JSON_CLEANUP_DUE = True
QUEUE_JSON_PARENT_NOT_SMALL = False

def queue_cleanup_orphan_json_temps(path: Path, *, max_remove: int = 64, min_age_sec: float = 30.0) -> int:
    try:
        parent = path.parent
        prefixes = (
            path.name + ".tmp.", path.name + ".reclaim.tmp.", path.name + ".failure.tmp.",
            path.name + ".repair.tmp.", path.name + ".claim.tmp.",
        )
        now = time.time()
        removed = 0
        for child in sorted(parent.iterdir(), key=lambda child: child.name):
            if removed >= max_remove:
                break
            if not child.is_file() or not child.name.startswith(prefixes):
                continue
            try:
                if now - child.stat().st_mtime < float(min_age_sec):
                    continue
            except QUEUE_JSON_EXCEPTIONS:
                continue
            if queue_safe_unlink(child, log_context="queue_json_orphan_tmp_cleanup"):
                removed += 1
        return removed
    except QUEUE_JSON_EXCEPTIONS as exc:
        record_queue_json_degraded("queue_json_orphan_cleanup_failed", exc, domain="scheduler")
        return QUEUE_JSON_CLEANUP_NONE_REMOVED

def queue_json_orphan_cleanup_due(path: Path, *, stride: int = 64) -> bool:
    stride_i, stride_reason = scheduler_int(stride, default=64, minimum=1, reason="queue_json_cleanup_stride_rejected")
    if stride_reason:
        record_queue_json_degraded("queue_json_cleanup_stride_rejected", ValueError(stride_reason), domain="scheduler")
    if stride_i <= 1:
        return QUEUE_JSON_CLEANUP_DUE
    try:
        digest = hashlib.blake2b(path.name.encode("utf-8", "surrogatepass"), digest_size=2).digest()
    except QUEUE_JSON_EXCEPTIONS as exc:
        record_queue_json_degraded("queue_json_orphan_cleanup_due_failed", exc, domain="scheduler")
        return QUEUE_JSON_CLEANUP_DUE
    else:
        return int.from_bytes(digest, "big") % stride_i == 0

def queue_json_parent_is_small(parent: Path, *, limit: int = 128) -> bool:
    limit_i, limit_reason = scheduler_int(limit, default=128, minimum=1, reason="queue_json_parent_limit_rejected")
    if limit_reason:
        record_queue_json_degraded("queue_json_parent_limit_rejected", ValueError(limit_reason), domain="scheduler")
    try:
        for count, _ in enumerate(parent.iterdir(), start=1):
            if count > limit_i:
                return QUEUE_JSON_PARENT_NOT_SMALL
        return QUEUE_JSON_CLEANUP_DUE
    except QUEUE_JSON_EXCEPTIONS as exc:
        record_queue_json_degraded("queue_json_parent_probe_failed", exc, domain="scheduler")
        return QUEUE_JSON_PARENT_NOT_SMALL

_queue_cleanup_orphan_json_temps = queue_cleanup_orphan_json_temps
_queue_json_orphan_cleanup_due = queue_json_orphan_cleanup_due
_queue_json_parent_is_small = queue_json_parent_is_small
