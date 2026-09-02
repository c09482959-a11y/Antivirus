"""No-hook scalar projection for in-memory result completion."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float

_BAD_MESSAGE_PREFIX = "in-memory scheduler ignored bad result message: type="
_ITEMS_TEXT = " items="


def bad_result_message_text(message: object, item_count: int) -> str:
    count = item_count if type(item_count) is int and type(item_count) is not bool else 0
    return _BAD_MESSAGE_PREFIX + no_hook_type_name(message) + _ITEMS_TEXT + int.__str__(count)


def exact_record(value: object) -> dict[str, object] | None:
    return value if type(value) is dict else None


def record_start_time(record: dict[str, object], *, default: float) -> tuple[float, str]:
    for field in ("started_at", "running_at", "queued_at"):
        value = dict.get(record, field)
        parsed, reason = scheduler_float(value, default=default, reason="inmemory_result_start_time_rejected")
        if reason == "" and value is not None:
            return parsed, ""
    return default, ""


def result_queue_failure(result: object) -> bool:
    if type(result) is not dict:
        return False
    failed, reason = scheduler_bool(dict.get(result, "queue_failure"), default=False, reason="inmemory_result_queue_failure_rejected")
    return failed if reason == "" else False


def exact_mapping_count(value: object) -> int:
    return len(value) if type(value) is dict else 0


__all__ = (
    "bad_result_message_text",
    "exact_mapping_count",
    "exact_record",
    "record_start_time",
    "result_queue_failure",
)
