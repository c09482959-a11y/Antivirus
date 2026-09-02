"""No-hook text helpers for process-queue result merge diagnostics."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.queue.exact_bool_support import exact_bool as merge_bool


def merge_text(value: object, *, field_name: str) -> str:
    text, reason = no_hook_text(value, unsupported_reason="process_queue_" + field_name + "_rejected")
    if reason == "":
        return text
    return "<" + field_name + ":" + reason + ">"



def merge_record_value(record: object, key: str) -> object:
    if type(record) is dict:
        return dict.get(record, key)
    return record


def merge_count_message(pending: object, active: object, failed: object) -> str:
    return "process queue incomplete: pending=" + merge_text(pending, field_name="pending") + " active=" + merge_text(active, field_name="active") + " failed=" + merge_text(failed, field_name="failed")


def merge_failure_reason_message(count: object, job_type: object, stage: object, exc_type: object, err: object) -> str:
    return "process queue failed reason count=" + merge_text(count, field_name="failed_reason_count") + " job_type=" + merge_text(job_type, field_name="failed_job_type") + " stage=" + merge_text(stage, field_name="failed_stage") + " exception=" + merge_text(exc_type, field_name="failed_exception") + " error=" + merge_text(err, field_name="failed_error")


__all__ = (
    "merge_bool",
    "merge_count_message",
    "merge_failure_reason_message",
    "merge_record_value",
    "merge_text",
)
