"""Queue-owned duplicate live-claim guard."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.queue.raw_queue_path_support import materialize_raw_queue_path
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names

_DUPLICATE_LIVE_GUARD_BLOCKED = False


def queue_duplicate_live_guard(
    queue_dir: object,
    claim_path: object,
    job: object,
    *,
    queue_job_dirs: Callable[..., tuple[object, object, object, object]],
    safe_listdir: Callable[[object], object],
    is_job_name: Callable[[str], bool],
    job_identity: Callable[..., str],
    read_json: Callable[..., object],
    report: Callable[..., object],
) -> bool:
    """Fail-closed duplicate live-claim guard owned by queue authority."""
    try:
        current_path = materialize_raw_queue_path(claim_path, reason="queue_duplicate_live_guard_claim_path_rejected")
        ident = job_identity(job, current_path.name)
        if (
            type(ident) is not str
            or ident == ""
            or ident.startswith(("invalid:", "file_incomplete:", "raw_incomplete:"))
        ):
            return _DUPLICATE_LIVE_GUARD_BLOCKED
        current = current_path.resolve()
        pending, active, done, failed = queue_job_dirs(queue_dir)
        for directory in (pending, active, done, failed):
            directory_path = materialize_raw_queue_path(directory, reason="queue_duplicate_live_guard_directory_rejected")
            for name in queue_listdir_names(
                safe_listdir(directory_path),
                context=directory_path,
            ):
                if type(name) is not str:
                    continue
                if not is_job_name(name):
                    continue
                candidate = directory_path / name
                try:
                    if candidate.resolve() == current:
                        continue
                except (OSError, RuntimeError, ValueError) as exc:
                    report(
                        "process_queue_duplicate_identity_resolve_failed",
                        exc,
                        extra={
                            "claim_path": scheduler_evidence_path(candidate, field_name="claim_path"),
                            "current": scheduler_evidence_path(current, field_name="current"),
                        },
                    )
                record = read_json(candidate, default=None)
                if type(record) is dict and job_identity(record, name) == ident:
                    return _DUPLICATE_LIVE_GUARD_BLOCKED
        return True
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as exc:
        report(
            "queue_duplicate_live_guard_failed_closed",
            exc,
            extra={
                "claim_path": scheduler_evidence_path(claim_path, field_name="claim_path"),
                "queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir"),
            },
            fatal=True,
        )
        return _DUPLICATE_LIVE_GUARD_BLOCKED


__all__ = ("queue_duplicate_live_guard",)
