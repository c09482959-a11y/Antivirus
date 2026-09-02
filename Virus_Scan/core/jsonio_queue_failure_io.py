"""IO support owner for core JSON queue-failure diagnostics."""

from pathlib import Path

from Virus_Scan.runtime.api import (
    FilesystemDurabilityError,
    durable_replace_regular_file,
    flush_open_writable_file,
)

def rewrite_queue_failure_claim(
    claim_text: object,
    payload: dict[object, object],
    *,
    json_module: object,
    open_func: object,
    normalize_record: object,
    make_json_safe_func: object,
    read_json: object,
    safe_unlink: object,
    record_degraded: object,
    record_suppressed: object,
    persistence_exceptions: object,
) -> bool:
    tmp = claim_text + ".failure.tmp"
    if not _queue_failure_dump_json(
        tmp,
        make_json_safe_func(normalize_record(payload)),
        json_module=json_module,
        open_func=open_func,
        record_suppressed=record_suppressed,
        stage="queue_failure_claim_sync_failed",
        persistence_exceptions=persistence_exceptions,
        indent=None,
    ):
        _queue_failure_cleanup(tmp, safe_unlink, record_degraded, persistence_exceptions, "queue_failure_claim_sync_failed")
        return False
    try:
        durable_replace_regular_file(Path(tmp), Path(claim_text))
    except (OSError, FilesystemDurabilityError, TypeError, ValueError):
        _queue_failure_cleanup(tmp, safe_unlink, record_degraded, persistence_exceptions, "queue_failure_claim_replace_failed")
        return False
    verify = read_json(claim_text, default={}) or {}
    failure_info = dict.get(verify, "failure_info") if type(verify) is dict else None
    return type(failure_info) is dict and len(failure_info) > 0


def write_queue_failure_diagnostic(
    queue_dir: object,
    claim_text: object,
    payload: dict[object, object],
    *,
    json_module: object,
    open_func: object,
    path_cls: object,
    diagnostics_dir: object,
    make_json_safe_func: object,
    safe_unlink: object,
    record_degraded: object,
    record_suppressed: object,
    time_module: object,
    persistence_exceptions: object,
    prior_ok: object,
) -> bool:
    diag_dir = diagnostics_dir(queue_dir)
    name = path_cls(claim_text).name if claim_text is not None else "unknown_%s.json" % time_module.time_ns()
    diag_tmp = diag_dir / (name + ".tmp")
    if not _queue_failure_dump_json(
        diag_tmp,
        make_json_safe_func(payload),
        json_module=json_module,
        open_func=open_func,
        record_suppressed=record_suppressed,
        stage="queue_failure_diag_sync_failed",
        persistence_exceptions=persistence_exceptions,
        indent=2,
    ):
        _queue_failure_cleanup(diag_tmp, safe_unlink, record_degraded, persistence_exceptions, "queue_failure_diag_sync_failed")
        return False
    try:
        durable_replace_regular_file(Path(diag_tmp), Path(diag_dir / name))
    except (OSError, FilesystemDurabilityError, TypeError, ValueError):
        _queue_failure_cleanup(diag_tmp, safe_unlink, record_degraded, persistence_exceptions, "queue_failure_diag_replace_failed")
        return False
    return prior_ok is True


def _queue_failure_dump_json(
    target: object,
    payload: object,
    *,
    json_module: object,
    open_func: object,
    record_suppressed: object,
    stage: object,
    persistence_exceptions: object,
    indent: object,
) -> bool:
    try:
        with open_func(target, "w", encoding="utf-8") as handle:
            json_module.dump(payload, handle, ensure_ascii=False, indent=indent, separators=None if indent else (",", ":"), allow_nan=False)
            handle.flush()
            flush_open_writable_file(handle.fileno())
    except persistence_exceptions as exc:
        try:
            record_suppressed(stage, exc, domain="runtime")
        except persistence_exceptions as reporting_exc:
            _ = reporting_exc
        return False
    return True


def _queue_failure_cleanup(target: object, safe_unlink: object, record_degraded: object, persistence_exceptions: object, stage: object) -> None:
    try:
        safe_unlink(target, log_context=stage)
    except persistence_exceptions as cleanup_exc:
        record_degraded("jsonio_cleanup_failed", cleanup_exc, domain="persistence")
