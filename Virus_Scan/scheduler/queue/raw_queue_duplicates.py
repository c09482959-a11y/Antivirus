"""Canonical duplicate-claim guard for raw queue lifecycle."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.queue.raw_queue_duplicate_evidence import (
    RawQueueDuplicateMappingDecision,
    raw_queue_duplicate_claim_name,
    raw_queue_duplicate_job_mapping,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.queue.raw_queue_duplicates_support import (
    _collect_duplicate_live_guard_matches,
    _quarantine_duplicate_live_guard_matches,
    _report_path,
)

_DUPLICATE_LIVE_GUARD_BLOCKED = False


def _job_mapping(value: object) -> RawQueueDuplicateMappingDecision:
    return raw_queue_duplicate_job_mapping(value)



def duplicate_live_guard(
    queue_dir: object,
    claim_path: object,
    job: object,
    *,
    job_identity: Callable[..., object],
    job_dirs: Callable[..., tuple[object, object, object, object]],
    safe_listdir: Callable[..., object],
    is_job_json_name: Callable[..., bool],
    read_json: Callable[..., object],
    merge_claim_meta: Callable[..., object],
    quarantine_job: Callable[..., object],
    report: Callable[..., object],
) -> object:
    """Return True when a claimed job is the sole live owner for its identity."""
    allowed = _DUPLICATE_LIVE_GUARD_BLOCKED
    ident = ""
    try:
        claim_name_decision = raw_queue_duplicate_claim_name(claim_path)
        if not claim_name_decision.accepted:
            raise ValueError("queue_duplicate_live_guard_claim_path_rejected")
        claim_name = claim_name_decision.name
        job_mapping_decision = _job_mapping(job)
        if not job_mapping_decision.accepted:
            report(
                "queue_duplicate_live_guard_job_mapping_rejected",
                ValueError(job_mapping_decision.reason),
                fatal=True,
                extra=_report_path({"identity": ident, "reason": job_mapping_decision.reason}, "claim_path", claim_path),
            )
            return _DUPLICATE_LIVE_GUARD_BLOCKED
        ident = job_identity(job_mapping_decision.mapping, claim_name)
        if type(ident) is not str or ident == "" or ident.startswith(("invalid:", "file_incomplete:", "raw_incomplete:")):
            return True
        current_text, current_reason = scheduler_path_text(claim_path)
        if current_reason or current_text == "":
            raise ValueError("queue_duplicate_live_guard_claim_path_rejected")
        current = Path(current_text).resolve()
        matches = _collect_duplicate_live_guard_matches(
            queue_dir=queue_dir,
            current=current,
            ident=ident,
            safe_listdir=safe_listdir,
            is_job_json_name=is_job_json_name,
            read_json=read_json,
            merge_claim_meta=merge_claim_meta,
            job_dirs=job_dirs,
            job_identity=job_identity,
            report=report,
            list_queue_names=lambda safe_listdir, d: queue_listdir_names(safe_listdir(d), context=d),
            job_mapping=_job_mapping,
        )
        if matches is None:
            return _DUPLICATE_LIVE_GUARD_BLOCKED
        allowed = _quarantine_duplicate_live_guard_matches(
            claim_path=claim_path,
            ident=ident,
            current_job=job_mapping_decision.mapping,
            matches=matches,
            quarantine_job=quarantine_job,
            report=report,
        )
    except (OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        report(
            "queue_duplicate_live_guard_failed_closed",
            exc,
            fatal=True,
            extra=_report_path({"identity": ident if type(ident) is str else ""}, "claim_path", claim_path),
        )
        allowed = _DUPLICATE_LIVE_GUARD_BLOCKED
    return allowed


__all__ = ("duplicate_live_guard",)
