"""No-hook scalar and log helpers for process queue setup."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_minimum_int


def process_queue_setup_weight(value: object) -> float:
    weight, issue = no_hook_finite_float(
        value,
        default=1.0,
        minimum=0.0,
        reason="process_queue_setup_weight_rejected",
        allow_exact_text=True,
    )
    return 1.0 if issue else weight


def process_queue_setup_cpu_text(value: object) -> str:
    if value is None:
        return "n/a"
    cpu_sample, issue = no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        reason="process_queue_setup_cpu_sample_rejected",
        allow_exact_text=True,
    )
    if issue:
        return "unavailable"
    return str.__add__(float.__format__(cpu_sample, ".1f"), "%")


def process_queue_setup_nonnegative_int_or(value: object, default_value: int, *, reason: str) -> tuple[int, str]:
    parsed, issue = scheduler_minimum_int(value, minimum=0, reason=reason)
    if issue:
        safe_default, _default_issue = scheduler_minimum_int(default_value, minimum=0, reason=reason)
        return safe_default, issue
    return parsed, ""


def process_queue_setup_log_message(*, fed_now: int, total_files: int, target_workers: int, cpu_text: str) -> str:
    return "".join((
        "bulk scan dynamic queue feed: initial_enqueued=",
        int.__str__(fed_now),
        " total_files=",
        int.__str__(total_files),
        " target_workers=",
        int.__str__(target_workers),
        " cpu=",
        cpu_text if type(cpu_text) is str else "unavailable",
    ))
