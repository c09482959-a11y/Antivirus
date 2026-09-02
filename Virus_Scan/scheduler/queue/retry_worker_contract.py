"""Queue-owned worker-result contract boundary for retry policy."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.queue.retry_callback_evidence import retry_policy_callback_evidence


def safe_worker_result_mapping(
    *,
    last_result: object,
    path: object,
    attempt: int,
    retry_failures: list[dict[str, object]],
) -> dict[str, object]:
    items = no_hook_mapping_items(last_result)
    if items is not None:
        result: dict[str, object] = {}
        rejected: list[dict[str, object]] = []
        for key, value in items:
            if type(key) is str:
                result[key] = value
            else:
                rejected.append({
                    "worker_result_key_rejected": True,
                    "reason": "worker_result_key_type_rejected",
                    "key_type": no_hook_type_name(key),
                })
        if rejected:
            result["worker_result_key_rejections"] = tuple(rejected)
        return result
    evidence = retry_policy_callback_evidence(
        path=path,
        attempt=attempt,
        callback_name="worker_result_schema",
        error=TypeError("worker result must be a mapping, got " + no_hook_type_name(last_result)),
    )
    retry_failures.append(evidence.as_record())
    result: dict[str, object] = {
        "scan_integrity": {
            **evidence.as_scan_integrity(),
            "file_failed": True,
            "allow_learning": False,
        },
    }
    if last_result is None or type(last_result) in {str, bool, int} or type(last_result) is float:
        result["result"] = last_result
    else:
        result["result_unavailable"] = True
        result["result_unavailable_reason"] = "worker_result_schema_rejected"
        result["result_type"] = no_hook_type_name(last_result)
    return result


__all__ = ("safe_worker_result_mapping",)
