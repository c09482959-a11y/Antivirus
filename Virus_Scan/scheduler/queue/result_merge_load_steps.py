"""Bounded queue-result readback steps."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.api.contracts import (
    QueueResultMergeError,
    QueueResultReadError,
    QueueResultSchemaError,
)
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.queue.result_merge_load_support import (
    queue_file_result_payload,
    result_listdir_names,
    result_listdir_sort_key,
    result_text,
)


def listed_queue_result_names(
    *,
    result_root: Path,
    safe_listdir: object,
    report: object,
) -> tuple[str, ...]:
    """List and sort durable queue-result filenames or fail closed."""
    try:
        return tuple(
            sorted(
                result_listdir_names(
                    safe_listdir,
                    result_root,
                    field_name="file_result_directory",
                ),
                key=result_listdir_sort_key,
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        detail = scheduler_error_detail(exc, max_length=500)
        listing_failure = QueueResultReadError("queue result listing failed: " + detail)
        report(
            "queue_file_result_list_failed",
            listing_failure,
            fatal=True,
            extra={"result_dir": result_root},
        )
        raise QueueResultMergeError(
            scheduler_error_detail(listing_failure, max_length=500)
        ) from exc


def merge_one_queue_file_result(
    *,
    merged: dict[str, object],
    result_root: Path,
    name: object,
    read_json: object,
    report: object,
) -> None:
    """Merge one result file into the in-memory result snapshot."""
    path: Path | None = None
    try:
        name_text = result_text(name, field_name="filename")
        if not name_text.endswith(".result.json"):
            return
        path = result_root / name_text
        record = read_json(path, default=None)
        file_key, payload = queue_file_result_payload(record)
        merged[result_text(file_key, field_name="file_key")] = payload
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        QueueResultSchemaError,
    ) as exc:
        read_failure: QueueResultSchemaError | QueueResultReadError = (
            exc
            if isinstance(exc, QueueResultSchemaError)
            else QueueResultReadError(scheduler_error_detail(exc, max_length=500))
        )
        report(
            "queue_file_result_readback_failed",
            read_failure,
            fatal=True,
            extra={
                "result_file": (
                    path
                    if path is not None
                    else {"filename_type": no_hook_type_name(name)}
                )
            },
        )
        raise QueueResultMergeError(
            scheduler_error_detail(read_failure, max_length=500)
        ) from exc


__all__ = ("listed_queue_result_names", "merge_one_queue_file_result")
