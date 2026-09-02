"""Process-queue admission guard ownership.

Owns duplicate-free admission decisions across durable queue states. It returns
immutable admission decisions only; it does not execute scans, enforce timeouts,
or serialize evidence.
"""

import json
from pathlib import Path


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_json import read_json_file
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name, queue_job_identity
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping



def _materialized_admission_guard_evidence(record: dict[str, object], *, fallback_reason: str) -> dict[str, object]:
    evidence = materialize_scheduler_mapping(immutable_mapping(record))
    if type(evidence) is dict:
        return evidence
    return {
        "admission_allowed": False,
        "process_queue_admission_failed_closed": True,
        "failure_reason": fallback_reason,
    }



def process_queue_enqueue_guard(queue_dir: object, job: object, identity: object = None, states: object=("pending", "active", "done", "failed", "quarantine", "file_results")) -> bool:
    """Fail-closed process-queue duplicate admission guard owned by queue authority.

    Scheduler identity owns only deterministic identity derivation and optional
    identity-lock pathing. Queue authority owns the cross-queue state read that
    decides whether a job may enter or be claimed from process-queue storage.
    This function returns an immutable boolean decision; it does not execute
    scans, enforce timeouts, or serialize evidence.
    """
    ident = queue_job_identity(job, None) if identity is None else identity
    if type(ident) is not str:
        identity_rejection_reason = "process_queue_enqueue_guard_identity_type_rejected"
    elif ident == "":
        identity_rejection_reason = "process_queue_enqueue_guard_identity_empty_rejected"
    elif ident.startswith(("invalid:", "file_incomplete:", "raw_incomplete:")):
        identity_rejection_reason = "process_queue_enqueue_guard_identity_incomplete_rejected"
    else:
        identity_rejection_reason = ""
    if identity_rejection_reason:
        _process_queue_record_suppressed(
            "process_queue_enqueue_guard_identity_rejected",
            ValueError(identity_rejection_reason),
            extra=_materialized_admission_guard_evidence(
                {
                    "identity": str.__str__(ident) if type(ident) is str else "",
                    "identity_type": no_hook_type_name(ident),
                    "admission_allowed": False,
                    "process_queue_admission_failed_closed": True,
                    "failure_reason": identity_rejection_reason,
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                },
                fallback_reason="process_queue_enqueue_guard_identity_evidence_unavailable",
            ),
            fatal=True,
        )
        return False
    admission_allowed = False
    try:
        pending, active, done, failed = _queue_job_dirs(queue_dir)
        dirs = {"pending": pending, "active": active, "done": done, "failed": failed}
        active_states = ("pending", "active", "done", "failed") if states is None else states
        for state in tuple(active_states):
            d = dirs.get(str(state))
            if d is None:
                continue
            for name in queue_listdir_names(_safe_queue_listdir(d), context=d):
                if not queue_is_job_json_name(name):
                    continue
                name_text = str.__str__(name) if type(name) is str else ""
                if name_text == "":
                    continue
                rec = read_json_file(Path(d) / name_text, default=None)
                if isinstance(rec, dict) and queue_job_identity(rec, name) == ident:
                    return False
        return True
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        _process_queue_record_suppressed(
            "process_queue_enqueue_guard_failed_closed",
            exc,
            extra=_materialized_admission_guard_evidence(
                {
                    "identity": str.__str__(ident) if type(ident) is str else "",
                    "identity_type": no_hook_type_name(ident),
                    "admission_allowed": False,
                    "process_queue_admission_failed_closed": True,
                    "failure_reason": "process_queue_enqueue_guard_exception",
                    "error_type": no_hook_type_name(exc),
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                },
                fallback_reason="process_queue_enqueue_guard_evidence_unavailable",
            ),
            fatal=True,
        )
    return admission_allowed





__all__ = ("process_queue_enqueue_guard",)
