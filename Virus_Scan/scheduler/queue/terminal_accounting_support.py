"""No-hook queue terminal accounting input support."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
)
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_path_text,
    scheduler_value_snapshot,
)
from Virus_Scan.scheduler.queue.terminal_accounting_evidence import (
    report_terminal_accounting_failure,
    terminal_rejection_reason,
    terminal_unsupported_file_key,
)
from Virus_Scan.scheduler.queue.terminal_accounting_support_evidence import (
    durable_results_decision,
    terminal_accounting_sequence_decision,
)

_INPUT_REJECTED_MARKER = "queue_terminal_accounting_input_rejected"
_SEQUENCE_REJECTED_MARKER = "queue_terminal_accounting_sequence_rejected"
_FILE_REJECTED_MARKER = "queue_missing_finalization_file_rejected"
_RESULT_MAPPING_REJECTED = "queue_missing_finalization_result_mapping_rejected"
_RESULT_KEY_REJECTED = "queue_missing_finalization_result_key_rejected"


def accounting_int(
    value: object, *, field_name: str, report: Callable[..., object]
) -> tuple[int, bool]:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        reason=terminal_rejection_reason(field_name),
        non_finite_reason="queue_terminal_integer_non_finite",
    )
    if reason:
        report_terminal_accounting_failure(
            report,
            _INPUT_REJECTED_MARKER,
            ValueError(reason),
            extra={
                "field_name": field_name,
                "value": scheduler_value_snapshot(value, field_name=field_name),
            },
        )
        return parsed, False
    return parsed, True


def accounting_float(
    value: object, *, field_name: str, report: Callable[..., object]
) -> tuple[float, bool]:
    parsed, reason = no_hook_finite_float(
        value,
        minimum=0.0,
        reason=terminal_rejection_reason(field_name),
        non_finite_reason="queue_terminal_float_non_finite",
        allow_exact_text=True,
    )
    if reason:
        report_terminal_accounting_failure(
            report,
            _INPUT_REJECTED_MARKER,
            ValueError(reason),
            extra={
                "field_name": field_name,
                "value": scheduler_value_snapshot(value, field_name=field_name),
            },
        )
        return parsed, False
    return parsed, True


def owned_sequence(
    value: object, *, field_name: str, report: Callable[..., object] | None
) -> tuple[object, ...]:
    decision = terminal_accounting_sequence_decision(
        value,
        field_name=field_name,
        rejection_reason=terminal_rejection_reason(field_name),
    )
    if not decision.accepted:
        report_terminal_accounting_failure(
            report,
            _SEQUENCE_REJECTED_MARKER,
            ValueError(decision.reason),
            extra={
                "field_name": field_name,
                "value": scheduler_value_snapshot(value, field_name=field_name),
                "terminal_accounting_sequence_decision": dict(decision.evidence),
            },
        )
    return decision.items


def path_entries(
    value: object, *, report: Callable[..., object]
) -> tuple[tuple[str, object], ...]:
    out: list[tuple[str, object]] = []
    for index, item in enumerate(
        owned_sequence(value, field_name="all_files", report=report)
    ):
        text, reason = scheduler_path_text(item)
        if reason or text == "":
            synthetic = terminal_unsupported_file_key(index)
            error = ValueError(reason or "queue_file_path_blank")
            report_terminal_accounting_failure(
                report,
                _FILE_REJECTED_MARKER,
                error,
                extra={
                    "file_key": synthetic,
                    "value": scheduler_value_snapshot(item, field_name="queue_file"),
                },
            )
            out.append((synthetic, error))
        else:
            out.append((text, None))
    return tuple(out)


def durable_results(value: object, *, report: Callable[..., object]) -> dict[str, object]:
    if scheduler_mapping_items(value) is None:
        decision = durable_results_decision(
            value,
            materialized=None,
            reason="queue durable results mapping rejected",
        )
        report_terminal_accounting_failure(
            report,
            _RESULT_MAPPING_REJECTED,
            ValueError(decision.reason),
            extra={
                "value": scheduler_value_snapshot(value, field_name="durable_results"),
                "terminal_accounting_durable_results_decision": dict(decision.evidence),
            },
        )
        return decision.results
    materialized = materialize_scheduler_mapping(value)
    if type(materialized) is not dict:
        decision = durable_results_decision(
            value,
            materialized=materialized,
            reason="queue durable results materialization failed",
        )
        report_terminal_accounting_failure(
            report,
            _RESULT_MAPPING_REJECTED,
            ValueError(decision.reason),
            extra={"terminal_accounting_durable_results_decision": dict(decision.evidence)},
        )
        return decision.results
    out: dict[str, object] = {}
    for key in tuple(dict.keys(materialized)):
        item = dict.__getitem__(materialized, key)
        text, reason = scheduler_path_text(key)
        if reason or text == "":
            report_terminal_accounting_failure(
                report,
                _RESULT_KEY_REJECTED,
                ValueError(reason or "queue result key blank"),
                extra={"key": scheduler_value_snapshot(key, field_name="durable_result_key")},
            )
        else:
            out[text] = item
    decision = durable_results_decision(
        value,
        materialized=out,
        reason="accepted_queue_durable_results",
    )
    return decision.results


__all__ = (
    "accounting_float",
    "accounting_int",
    "durable_results",
    "durable_results_decision",
    "owned_sequence",
    "path_entries",
    "terminal_accounting_sequence_decision",
)
