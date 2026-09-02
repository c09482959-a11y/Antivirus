"""Raw queue directory and admission ownership helpers.

Owns durable raw-queue directory creation and duplicate-admission decisions.
This module returns immutable decisions/paths only; it does not execute work,
enforce timeouts, or serialize evidence.
"""

from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path


def raw_queue_dirs(queue_dir: object, *, job_dirs: Callable[[object], tuple[object, object, object, object]], record_suppressed: object) -> tuple[Path, Path, Path, Path, Path, Path]:
    """Ensure and return canonical raw-queue directories."""
    queue_path, _queue_path_reason = scheduler_filesystem_path(queue_dir)
    q = Path(queue_path)
    pending, active, done, failed = job_dirs(queue_dir)
    accum = q / "accumulators"
    locks = q / "locks"
    for directory in (pending, active, done, failed, accum, locks):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            record_suppressed("raw_dirs_mkdir_failed", exc)
    return pending, active, done, failed, accum, locks


def enqueue_guard(
    queue_dir: object,
    job: object,
    *,
    identity: object=None,
    states: object=("pending", "active", "done", "failed", "quarantine"),
    job_identity: Callable[..., str],
    existing_identities: Callable[..., set[str]],
    record_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    """Return False when admission cannot prove duplicate-free ownership."""
    admitted = False
    try:
        ident = job_identity(job, None) if identity is None else identity
        if (
            type(ident) is not str or ident == "" or ident.startswith(("invalid:", "file_incomplete:", "raw_incomplete:"))
        ):
            admitted = True
        else:
            admitted = ident not in existing_identities(queue_dir, states=states, strict=True)
    except recoverable_exceptions as exc:
        record_suppressed("queue_enqueue_guard_failed_closed", exc)
        admitted = False
    return admitted


__all__ = ("enqueue_guard", "raw_queue_dirs")
