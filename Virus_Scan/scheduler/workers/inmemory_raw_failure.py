"""Failure evidence ownership for in-memory raw scheduler enrichment."""
from __future__ import annotations



from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text


def _raw_failure_path_text(path: object) -> str:
    text, reason = scheduler_path_text(path)
    if reason == "" and text:
        return text[:500]
    return reason[:500]


def inmemory_raw_scan_failure_result(*, path: object, exc: BaseException, deps: object) -> dict[str, object]:
    """Return explicit degraded raw-scan evidence for outer scan failures."""
    error_text = scheduler_exception_text(exc, max_length=500)
    integrity = {
        "raw_queue_degraded": True,
        "had_degraded_stage": True,
        "partial_retry": True,
        "error": error_text,
        "inmemory_raw": True,
        "scan_incomplete": True,
    }
    try:
        tags = deps.normalize_tags([*list(deps.scanner_degraded_tags()), 'inmemory_raw_failed', 'scanner_failure'])
    except (OSError, UnicodeError, RuntimeError, TypeError, ValueError):
        tags = ("inmemory_raw_failed", "scanner_failure")
    try:
        yara_hits = deps.normalize_yara_hits(())
    except (OSError, UnicodeError, RuntimeError, TypeError, ValueError):
        yara_hits = ()
    return {
        "tags": tags,
        "suspicious": True,
        "yara_hits": yara_hits,
        "strings_blob": "",
        "effective_stage": "inmemory_raw_failed",
        "errors": [error_text],
        "file_id": _raw_failure_path_text(path),
        "scan_integrity": integrity,
    }


def record_inmemory_raw_scan_failure(*, path: object, exc: BaseException, deps: object) -> None:
    """Record a failed in-memory raw scan without producing clean evidence."""
    path_text = _raw_failure_path_text(path)
    error_text = scheduler_exception_text(exc, max_length=500)
    deps.record_issue("inmemory_raw_scan_failed", exc, fatal=True, extra={"file": path_text})
    try:
        deps.log_error("in-memory raw scan failed for " + path_text + ": " + error_text)
    except (OSError, UnicodeError, RuntimeError) as log_exc:
        deps.record_issue("inmemory_raw_scan_log_failed", log_exc, fatal=False)
    deps.set_scan_integrity(path, {
        "raw_queue_degraded": True,
        "had_degraded_stage": True,
        "partial_retry": True,
        "error": error_text,
        "inmemory_raw": True,
        "scan_incomplete": True,
    })
