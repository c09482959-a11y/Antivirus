"""Queue-owned workload ordering for process-queue publication."""
from __future__ import annotations



from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as record_scheduler_suppressed
from Virus_Scan.scheduler.queue.admission import classify_workload
from Virus_Scan.scheduler.runtime.queue_filesystem import process_weight_for_path as _process_weight_for_path


def _process_queue_ordered_items(files: object) -> object:
    """Return (order, original_index, file, workload_class) tuples for queue feed."""
    ordered = []
    for idx, path in enumerate(files or []):
        try:
            cls = classify_workload(path)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            record_scheduler_suppressed("process_queue_workload_classify_failed", exc, extra={"path": str(path)})
            cls = "generic"
        order_rank = {"image": 0, "generic": 1, "raw": 2, "yara": 3, "script": 4, "dotnet": 5, "archive": 6}.get(str(cls), 1)
        try:
            weight = float(_process_weight_for_path(path))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            record_scheduler_suppressed("process_queue_weight_failed", exc, extra={"path": str(path)})
            weight = 1.0
        ordered.append((order_rank, idx, path, cls, weight))
    ordered.sort(key=lambda item: (item[0], item[4], item[1], str(item[2])))
    return [(order, idx, path, cls) for order, (_rank, idx, path, cls, _weight) in enumerate(ordered)]


__all__ = ("_process_queue_ordered_items",)
