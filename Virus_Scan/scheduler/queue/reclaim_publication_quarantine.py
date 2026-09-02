"""Quarantine publication for reclaimed pending queue jobs."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from Virus_Scan.runtime.api import flush_open_writable_file
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe
from Virus_Scan.scheduler.queue.reclaim_publication_support import (
    OrphanRecoveryActionEvidenceAppendRequest,
    append_action_evidence,
    cleanup_failed_pending,
    exact_bool,
)

_RECLAIM_ANNOTATION_QUARANTINE_MOVE_FAILED = "reclaim annotation quarantine move failed"


def next_reclaim_quarantine_destination(qdir: Path, pending_path: Path) -> Path:
    """Return the first collision-free quarantine destination for a pending job."""

    dest = qdir / ("pending__" + pending_path.name)
    index = 1
    while dest.exists():
        dest = qdir / ("pending__" + pending_path.stem + "__dup%03d.json" % index)
        index += 1
    return dest


def write_reclaim_quarantine_payload(*, dest: Path, stale_job: Mapping[str, object]) -> None:
    """Persist the fail-closed stale job payload at the quarantine destination."""

    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(make_json_safe(stale_job), fh, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        fh.flush()
        flush_open_writable_file(fh.fileno())


def quarantine_failed_reclaimed_pending_job(
    *,
    qdir: Path,
    pending_path: Path,
    failure_info: Mapping[str, object],
    job_record: Mapping[str, object] | None,
    job_id: str,
    safe_unlink: object,
    record_suppressed: object,
    evidence_records: list[Mapping[str, object]] | None,
    pending_path_text: str,
) -> None:
    """Move an unpublishable reclaimed pending job to quarantine or clean it up."""

    try:
        stale_job = dict(job_record) if job_record is not None else {"queue_failure": True}
        stale_job["queue_failure"] = True
        stale_job["failure_info"] = make_json_safe(failure_info)
        qdir.mkdir(parents=True, exist_ok=True)
        dest = next_reclaim_quarantine_destination(qdir, pending_path)
        quarantined = exact_bool(queue_atomic_replace(pending_path, dest, log_context="reclaim_annotation_quarantine_move"))
        if quarantined:
            write_reclaim_quarantine_payload(dest=dest, stale_job=stale_job)
        if not quarantined:
            raise RuntimeError(_RECLAIM_ANNOTATION_QUARANTINE_MOVE_FAILED)
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as qexc:
        record_suppressed(
            "queue_reclaim_annotation_quarantine_failed",
            qexc,
            extra={"pending_path": pending_path_text},
            fatal=True,
        )
        append_action_evidence(
            OrphanRecoveryActionEvidenceAppendRequest(
                evidence_records=evidence_records,
                stage="queue_reclaim_annotation_quarantine_failed",
                action="quarantine_failed_reclaimed_pending_job",
                source_path=pending_path,
                destination_path=qdir,
                error=qexc,
                error_source="reclaim_publication.quarantine_failed_pending",
                job_id=job_id,
            )
        )
        cleanup_failed_pending(
            pending_path,
            safe_unlink=safe_unlink,
            record_suppressed=record_suppressed,
            evidence_records=evidence_records,
            job_id=job_id,
        )


__all__ = (
    "next_reclaim_quarantine_destination",
    "quarantine_failed_reclaimed_pending_job",
    "write_reclaim_quarantine_payload",
)
