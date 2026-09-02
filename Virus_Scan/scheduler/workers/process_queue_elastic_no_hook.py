"""No-hook helpers for process-queue elastic scaling boundaries."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value, scheduler_mapping_items_tuple


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision, unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_error_detail
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_int, worker_optional_float


def elastic_bool(value: object, *, default: bool = False, reason: str) -> tuple[bool, str]:
    return scheduler_bool(value, default=default, reason=reason)


def elastic_int(value: object, *, replacement: int = 0, minimum: int | None = 0, maximum: int | None = None, reason: str) -> tuple[int, str]:
    return worker_int(value, replacement=replacement, minimum=minimum, maximum=maximum, reason=reason)


def elastic_float_or_none(value: object, *, minimum: float | None = None, reason: str) -> tuple[float | None, str]:
    return worker_optional_float(value, minimum=minimum, reason=reason)


def _elastic_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    items = scheduler_mapping_items_tuple(value)
    if items is not None:
        return items
    frozen_decision = frozen_scheduler_items_decision(value)
    if frozen_decision.accepted:
        return frozen_decision.items
    return None


def elastic_io_sample(value: object) -> tuple[object, str]:
    if value is None:
        return immutable_mapping((('pressure', False), ('reason', 'missing_elastic_io_sample'))), ""
    items = _elastic_mapping_items(value)
    if items is None:
        return immutable_mapping((
            ('pressure', False),
            ('reason', 'process_queue_elastic_io_sample_rejected'),
            ('scheduler_elastic_io_sample_unavailable', True),
            ('evidence', unsupported_scheduler_value_evidence(value, field_name='process_queue_elastic_io_sample')),
        )), 'process_queue_elastic_io_sample_rejected'
    return immutable_mapping(tuple(items)), ""


def elastic_io_field(value: object, field_name: str, default: object = None) -> object:
    if type(field_name) is not str:
        return default
    return scheduler_mapping_item_value(_elastic_mapping_items(value), field_name, default)


def elastic_io_bool_field(value: object, field_name: str, *, default: bool = False) -> bool:
    parsed, issue = scheduler_bool(elastic_io_field(value, field_name, default), default=default, reason='process_queue_elastic_io_bool_rejected')
    return parsed if issue == "" else default


def elastic_io_reason(value: object) -> str:
    reason = elastic_io_field(value, 'reason', 'n/a')
    if type(reason) is str:
        return str.__str__(reason)
    return 'n/a'


def elastic_error_category(error: BaseException) -> str:
    return no_hook_type_name(error)


def elastic_error_detail(error: BaseException) -> str:
    detail = scheduler_error_detail(error)
    category = elastic_error_category(error)
    prefix = category + ": "
    if str.startswith(detail, prefix):
        return str.__getitem__(detail, slice(len(prefix), None))
    return detail


def elastic_log_message(*, action_text: str, amount: int, live: int, process_count: int, target: int, cpu_sample: float | None, io_sample: object) -> str:
    safe_action = str.__str__(action_text) if type(action_text) is str else "elastic_action"
    cpu_text = "n/a" if cpu_sample is None else float.__format__(cpu_sample, ".1f") + "%"
    return (
        "bulk scan elastic scheduler: " + safe_action + "=" + int.__str__(amount)
        + " live_workers=" + int.__str__(live) + "/" + int.__str__(process_count)
        + " target=" + int.__str__(target) + " cpu=" + cpu_text
        + " io_pressure=" + bool.__str__(elastic_io_bool_field(io_sample, 'pressure'))
        + " io_reason=" + elastic_io_reason(io_sample)
        + " queue_metadata_latency=" + bool.__str__(elastic_io_bool_field(io_sample, 'metadata_latency'))
        + " actual_disk_io_pressure=" + bool.__str__(elastic_io_bool_field(io_sample, 'actual_disk_io_pressure'))
    )

__all__ = (
    'elastic_bool',
    'elastic_error_category',
    'elastic_error_detail',
    'elastic_float_or_none',
    'elastic_int',
    'elastic_io_bool_field',
    'elastic_io_reason',
    'elastic_io_sample',
    'elastic_log_message',
)
