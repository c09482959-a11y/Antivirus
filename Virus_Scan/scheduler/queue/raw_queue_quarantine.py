"""Canonical raw-queue quarantine lifecycle helpers.

This module owns deterministic quarantine destination, metadata, and sidecar
cleanup. It is intentionally dependency injected for durable filesystem
operations and telemetry so quarantine remains inside canonical reconciliation
ownership without becoming an alternate path around owned internals.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import cast, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_nonnegative_int, scheduler_path_text
from Virus_Scan.scheduler.queue.default_text_support import queue_default_text
from Virus_Scan.scheduler.queue.raw_queue_path_support import raw_queue_accepted_path_extra, raw_queue_path_text_or_error
from Virus_Scan.scheduler.queue.raw_queue_quarantine_decisions import (
    RawQueueQuarantineDecision,
    raw_queue_bool_decision,
    raw_queue_mapping_decision,
    raw_queue_quarantine_accepted,
    raw_queue_quarantine_rejected,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace

if TYPE_CHECKING:
    from collections.abc import Callable


def quarantine_dir(queue_dir: object, *, report: Callable[..., object]) -> Path:
    """Return the durable quarantine directory, reporting creation failures."""
    queue_text = ""
    try:
        queue_text = raw_queue_path_text_or_error(queue_dir, reason="queue_quarantine_dir_rejected")
        d = Path(queue_text) / "quarantine"
        d.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report("queue_quarantine_dir_create_failed", exc, fatal=True, extra=raw_queue_accepted_path_extra("queue_dir", queue_dir))
        d = Path(queue_text) / "quarantine" if queue_text != "" else Path("quarantine")
    return d


def quarantine_destination(path: object, *, quarantine_root: object) -> tuple[Path, str]:
    """Build a deterministic collision-safe quarantine destination."""
    p = Path(raw_queue_path_text_or_error(path, reason="queue_quarantine_source_path_rejected"))
    root = Path(raw_queue_path_text_or_error(quarantine_root, reason="queue_quarantine_root_rejected"))
    source_state = p.parent.name
    dest = root / (source_state + "__" + p.name)
    n = 1
    while dest.exists():
        dest = root / (source_state + "__" + p.stem + "__dup%03d.json" % n)
        n += 1
    return dest, source_state


def quarantine_sidecar_payload(*, reason: object, identity: object, source_state: object, destination: object, now: object = None) -> dict[str, object]:
    """Return immutable quarantine sidecar metadata."""
    parsed_time, time_reason = scheduler_float(
        time.time() if now is None else now,
        default=0.0,
        minimum=0.0,
        reason="queue_quarantine_time_rejected",
    )
    ts = parsed_time if time_reason == "" else 0.0
    if type(identity) is str:
        identity_text = str.__str__(identity)
    elif identity is None:
        identity_text = ""
    else:
        identity_text = "identity_unavailable:" + no_hook_type_name(identity)
    destination_name = Path(raw_queue_path_text_or_error(destination, reason="queue_quarantine_destination_rejected")).name
    return {
        "quarantined": True,
        "quarantine_reason": queue_default_text(reason, "queue_quarantine_reason_unavailable"),
        "quarantine_time": ts,
        "quarantine_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "queue_identity": identity_text,
        "quarantine_source_state": queue_default_text(source_state, "queue_quarantine_source_state_unavailable"),
        "quarantine_job": destination_name,
    }


def remove_claim_sidecar_for_terminal_move(claim_path: object, *, remove_claim_meta: Callable[..., object], report: Callable[..., object], marker: object) -> bool:
    """Best-effort terminal sidecar cleanup with explicit telemetry."""
    removed = False
    try:
        removed = raw_queue_bool_decision(remove_claim_meta(claim_path), rejected_reason="queue_claim_sidecar_remove_result_rejected").as_bool()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report(queue_default_text(marker, "queue_claim_sidecar_remove_failed"), exc, fatal=False, extra=raw_queue_accepted_path_extra("claim_path", claim_path))
    return removed


def cleanup_orphan_claim_sidecars(active_dir: object, *, cleanup_orphans: Callable[..., object], max_remove: object, report: Callable[..., object], marker: object, claim_path: object) -> int:
    """Best-effort orphan sidecar cleanup after terminal claim transition."""
    removed = 0
    try:
        removed = scheduler_nonnegative_int(
            cleanup_orphans(
                active_dir,
                max_remove=scheduler_nonnegative_int(
                    max_remove,
                    reason="queue_quarantine_integer_rejected",
                ),
            ),
            reason="queue_quarantine_integer_rejected",
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report(queue_default_text(marker, "queue_orphan_claim_cleanup_failed"), exc, fatal=False, extra=raw_queue_accepted_path_extra("claim_path", claim_path))
    return removed


def quarantine_job_decision(
    path: object,
    *,
    reason: object = "duplicate_queue_job",
    job: object = None,
    identity: object = None,
    **dependency_callbacks: object,
) -> RawQueueQuarantineDecision:
    """Move a bad/duplicate job out of live queue accounting with replayable decision evidence."""
    active_claim_is_protected_callback = cast("Callable[..., object]", dependency_callbacks["active_claim_is_protected"])
    quarantine_dir_callback = cast("Callable[..., Path]", dependency_callbacks["quarantine_dir"])
    read_json_file_callback = cast("Callable[..., object]", dependency_callbacks["read_json_file"])
    job_identity_callback = cast("Callable[..., object]", dependency_callbacks["job_identity"])
    quarantine_destination_callback = cast("Callable[..., tuple[Path, str]]", dependency_callbacks["quarantine_destination"])
    remove_claim_sidecar_callback = cast("Callable[..., object]", dependency_callbacks["remove_claim_sidecar_for_terminal_move"])
    remove_claim_meta_callback = cast("Callable[..., object]", dependency_callbacks["remove_claim_meta"])
    cleanup_orphan_sidecars_callback = cast("Callable[..., object]", dependency_callbacks["cleanup_orphan_claim_sidecars"])
    cleanup_orphans_callback = cast("Callable[..., object]", dependency_callbacks["cleanup_orphans"])
    orphan_cleanup_max = dependency_callbacks["orphan_cleanup_max"]
    write_quarantine_sidecar_callback = cast("Callable[..., object]", dependency_callbacks["write_quarantine_sidecar"])
    quarantine_sidecar_payload_callback = cast("Callable[..., object]", dependency_callbacks["quarantine_sidecar_payload"])
    report_callback = cast("Callable[..., object]", dependency_callbacks["report"])
    report_issue_callback = cast("Callable[..., object]", dependency_callbacks["report_issue"])
    log_error_callback = cast("Callable[..., object]", dependency_callbacks["log_error"])
    path_text = ""
    try:
        path_text = raw_queue_path_text_or_error(path, reason="queue_quarantine_job_path_rejected")
        p = Path(path_text)
        if not p.exists() or not p.name.endswith(".json"):
            return raw_queue_quarantine_rejected("queue_quarantine_path_missing_or_not_json", path=path_text)
        if p.parent.name == "active" and raw_queue_bool_decision(active_claim_is_protected_callback(p, job=job), rejected_reason="queue_active_claim_protection_result_rejected").as_bool():
            return raw_queue_quarantine_rejected("queue_quarantine_active_claim_protected", path=path_text)
        q = quarantine_dir_callback(p.parent.parent)
        payload = raw_queue_mapping_decision(job, rejected_reason="queue_quarantine_job_mapping_rejected").as_mapping_or_none()
        if payload is None:
            payload = raw_queue_mapping_decision(read_json_file_callback(p), rejected_reason="queue_quarantine_read_json_mapping_rejected").as_mapping_or_none()
        if payload is None:
            raise ValueError("queue quarantine payload must be a mapping: " + path_text)
        ident = identity if identity is not None else job_identity_callback(payload, p.name)
        dest, source_state = quarantine_destination_callback(p, quarantine_root=q)
        remove_claim_sidecar_callback(p, remove_claim_meta=remove_claim_meta_callback, report=report_callback, marker="queue_quarantine_pre_meta_cleanup_failed")
        replace_result = queue_atomic_replace(p, dest, log_context="queue_quarantine_move")
        replace_path_text, replace_path_reason = scheduler_path_text(replace_result)
        if not (raw_queue_bool_decision(replace_result, rejected_reason="queue_quarantine_replace_result_rejected").as_bool() or (replace_path_reason == "" and replace_path_text != "")):
            return raw_queue_quarantine_rejected("queue_quarantine_replace_failed", path=path_text, detail=replace_path_reason)
        remove_claim_sidecar_callback(p, remove_claim_meta=remove_claim_meta_callback, report=report_callback, marker="queue_quarantine_post_meta_cleanup_failed")
        cleanup_orphan_sidecars_callback(
            p.parent,
            cleanup_orphans=cleanup_orphans_callback,
            max_remove=orphan_cleanup_max,
            report=report_callback,
            marker="queue_quarantine_orphan_meta_cleanup_failed",
            claim_path=p,
        )
        write_quarantine_sidecar_callback(dest, quarantine_sidecar_payload_callback(reason=reason, identity=ident, source_state=source_state, destination=dest))
        return raw_queue_quarantine_accepted(path=path_text, destination=dest, source_state=source_state)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        error_text = scheduler_exception_text(exc)
        try:
            log_error_callback("queue quarantine failed for " + (path_text or "queue_quarantine_path_unavailable") + ": " + error_text)
        except (OSError, UnicodeError, RuntimeError) as log_exc:
            report_issue_callback("queue_quarantine_log_failed", log_exc)
        report_issue_callback("queue_quarantine_failed", exc)
    return raw_queue_quarantine_rejected("queue_quarantine_failed", path=path_text, detail=error_text)
