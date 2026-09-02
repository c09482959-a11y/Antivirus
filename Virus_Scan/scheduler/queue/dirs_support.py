"""No-hook support helpers for process-queue directory ownership."""
from __future__ import annotations

import time
from pathlib import Path


from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.queue.text_reason_support import (
    queue_text_or_empty_reason as queue_reason_text,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import (
    queue_failure_diagnostics_dir,
    queue_safe_unlink,
    safe_queue_listdir,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names

DIAGNOSTIC_TMP_CLEANUP_FAILED = -1
DIAGNOSTIC_TMP_CLEANUP_NOT_APPLICABLE = 0
QUEUE_QUARANTINE_FAILED = False
QUEUE_DIRS_FAILED = False


def diagnostic_max_age(value: object) -> tuple[float, str]:
    metric = exact_finite_float_or_none(value)
    if metric is None or metric < 0.0:
        return 0.0, "process_queue_diagnostic_tmp_max_age_rejected"
    return max(1.0, metric), ""


def negative_count(value: object) -> bool:
    if type(value) is int and type(value) is not bool:
        return value < 0
    if type(value) is float:
        return value < 0.0
    return True


def cleanup_diagnostic_tmp_files(queue_dir: object, max_age_sec: float = 60.0, *, record_suppressed: object) -> int:
    """Remove stale process-queue diagnostic temporary files through queue authority."""
    removed = 0
    try:
        d = queue_failure_diagnostics_dir(queue_dir)
        now = time.time()
        max_age, max_age_reason = diagnostic_max_age(max_age_sec)
        if max_age_reason:
            record_suppressed(
                "process_queue_diagnostic_tmp_max_age_rejected",
                ValueError(max_age_reason),
                fatal=False,
                extra={"max_age_type": no_hook_type_name(max_age_sec)},
            )
            return DIAGNOSTIC_TMP_CLEANUP_FAILED
        for name in sorted(
            queue_listdir_names(safe_queue_listdir(d), context=d),
            key=lambda value: str.__str__(value) if type(value) is str else "",
        ):
            name_text, name_reason = queue_reason_text(
                name,
                missing_reason="process_queue_diagnostic_tmp_name_missing",
                unsupported_reason="process_queue_diagnostic_tmp_name_rejected",
                empty_reason="process_queue_diagnostic_tmp_name_empty",
            )
            if name_reason or not name_text.endswith(".tmp"):
                continue
            item = Path(d) / name_text
            try:
                age = now - item.stat().st_mtime
            except (FileNotFoundError, PermissionError, OSError, RuntimeError, ValueError) as exc:
                record_suppressed("process_queue_diagnostic_tmp_stat_failed", exc, extra={"path": scheduler_evidence_path(item, field_name="path")})
                age = max_age + 1.0
            if age >= max_age and queue_safe_unlink(item, log_context="process_queue_diagnostic_tmp_cleanup"):
                removed += 1
        return removed
    except (FileNotFoundError, NotADirectoryError) as exc:
        record_suppressed(
            "process_queue_diagnostic_tmp_dir_missing",
            exc,
            fatal=False,
            extra={"queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir")},
        )
        return DIAGNOSTIC_TMP_CLEANUP_NOT_APPLICABLE
    except (PermissionError, OSError, RuntimeError, TypeError, ValueError) as exc:
        record_suppressed("process_queue_diagnostic_tmp_cleanup_failed", exc, fatal=False, extra={"queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir")})
        return DIAGNOSTIC_TMP_CLEANUP_FAILED
