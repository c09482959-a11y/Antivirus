"""Read, write, and sidecar publication for scheduler queue JSON."""
from __future__ import annotations

from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.runtime.queue_filesystem import (
    queue_claim_meta_path,
    queue_safe_unlink,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_common import queue_filesystem_path_text
from Virus_Scan.scheduler.runtime.queue_json_cleanup import (
    queue_cleanup_orphan_json_temps,
    queue_json_orphan_cleanup_due,
    queue_json_parent_is_small,
)
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS, record_queue_json_degraded
from Virus_Scan.scheduler.runtime.queue_json_locks import QUEUE_JSON_REPLACE_LOCK_OWNER
from Virus_Scan.scheduler.runtime.queue_json_publication_read import read_json_file
from Virus_Scan.scheduler.runtime.queue_json_publication_boundary import (
    queue_json_context,
    queue_json_path_name,
    queue_json_tmp_suffix,
    queue_json_verify_flag,
)
from Virus_Scan.scheduler.runtime.queue_json_safety import make_json_safe
from Virus_Scan.scheduler.runtime.queue_json_schema import (
    normalize_persistent_record_schema,
    validate_persistent_record_semantics,
    verify_persistent_json_file,
)
from Virus_Scan.scheduler.runtime.queue_json_replace_publication import queue_write_json_replace_with_dependencies
from Virus_Scan.scheduler.runtime.queue_json_quarantine_sidecar import queue_write_quarantine_sidecar_with_dependencies

QUEUE_JSON_WRITE_OK = True
QUEUE_JSON_WRITE_FAILED = False


def queue_write_json_replace(
    path: object,
    payload: object,
    *,
    tmp_suffix: str = ".tmp",
    verify: bool = False,
    log_context: str | None = None,
    safe_unlink: object = queue_safe_unlink,
) -> bool:
    return bool(
        queue_write_json_replace_with_dependencies(
            path,
            payload,
            tmp_suffix=tmp_suffix,
            verify=verify,
            log_context=log_context,
            safe_unlink=safe_unlink,
            lock_owner=QUEUE_JSON_REPLACE_LOCK_OWNER,
            context_func=queue_json_context,
            tmp_suffix_func=queue_json_tmp_suffix,
            verify_flag_func=queue_json_verify_flag,
            filesystem_path_func=queue_filesystem_path_text,
            path_name_func=queue_json_path_name,
            exception_text_func=scheduler_exception_text,
            make_safe_func=make_json_safe,
            normalize_func=normalize_persistent_record_schema,
            validate_func=validate_persistent_record_semantics,
            verify_file_func=verify_persistent_json_file,
            parent_small_func=queue_json_parent_is_small,
            cleanup_due_func=queue_json_orphan_cleanup_due,
            cleanup_temps_func=queue_cleanup_orphan_json_temps,
            log_func=log_error,
            record_degraded=record_queue_json_degraded,
        )
    )

def queue_write_claim_meta(claim_path: object, meta: object, *, log_context: str = "queue_claim_meta") -> bool:
    try:
        filesystem_path, path_reason = queue_filesystem_path_text(claim_path)
        if path_reason:
            record_queue_json_degraded("queue_claim_meta_path_rejected", ValueError(path_reason), domain="scheduler")
            return QUEUE_JSON_WRITE_FAILED
        meta_path = queue_claim_meta_path(filesystem_path)
        meta_source = {} if meta is None else meta
        return bool(queue_write_json_replace(meta_path, make_json_safe(meta_source), tmp_suffix=".tmp", verify=False, log_context=log_context))
    except QUEUE_JSON_EXCEPTIONS as exc:
        record_queue_json_degraded(
            "queue_claim_meta_write_failed",
            exc,
            domain="scheduler",
        )
        return QUEUE_JSON_WRITE_FAILED

def queue_write_quarantine_sidecar(dest: object, meta: object) -> bool:
    return bool(
        queue_write_quarantine_sidecar_with_dependencies(
            dest,
            meta,
            filesystem_path_func=queue_filesystem_path_text,
            make_safe_func=make_json_safe,
            safe_unlink=queue_safe_unlink,
            record_degraded=record_queue_json_degraded,
        )
    )

_read_json_file = read_json_file
_queue_write_json_replace = queue_write_json_replace
_queue_write_claim_meta = queue_write_claim_meta
_queue_write_quarantine_sidecar = queue_write_quarantine_sidecar
