"""No-hook support helpers for process-queue claim sidecars."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_record_suppressed,
    record_scheduler_suppressed,
)

CLAIM_SIDECAR_FAILED = False
ORPHAN_CLAIM_CLEANUP_FAILED = -1
ORPHAN_CLAIM_CLEANUP_NOT_APPLICABLE = 0


def queue_claim_sidecar_write_failed(dst: object, exc: BaseException) -> bool:
    record_scheduler_suppressed(
        "process_queue_claim_sidecar_write_failed",
        exc,
        extra={"claim_path_type": no_hook_type_name(dst)},
        fatal=True,
    )
    return CLAIM_SIDECAR_FAILED


def queue_claim_meta_cleanup_failed(claim_path: object, exc: BaseException) -> bool:
    process_queue_record_suppressed(
        "queue_claim_meta_cleanup_failed",
        exc,
        extra={"claim_path_type": no_hook_type_name(claim_path)},
    )
    return CLAIM_SIDECAR_FAILED


def queue_orphan_cleanup_limit(value: object) -> object:
    if type(value) is int and type(value) is not bool and value >= 0:
        return value, ""
    return 0, "queue_orphan_claim_cleanup_limit_rejected"
