"""No-hook support for raw-stage job execution."""
from __future__ import annotations

import math
import os
from typing import Protocol, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence

if TYPE_CHECKING:
    from collections.abc import Callable


class RawFailureInfoOwner(Protocol):
    default_failure_info: Callable[..., dict[str, object]]



def raw_job_text(value: object, default_text: str, *, field_name: str) -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason="raw_job_" + field_name + "_missing", unsupported_reason="raw_job_" + field_name + "_rejected")
    if reason == "" and text:
        return text, ""
    return default_text, reason


def raw_job_attempt(value: object) -> tuple[int, str]:
    if value is None:
        return 0, ""
    if type(value) is bool:
        return 0, "raw_job_attempt_rejected"
    if type(value) is int:
        return max(value, 0), ""
    if type(value) is float and math.isfinite(value) and value.is_integer():
        parsed = int(value)
        return max(parsed, 0), ""
    if type(value) is str:
        text = str.__str__(value).strip()
        if text.isdecimal():
            parsed = int(text, 10)
            return max(parsed, 0), ""
    return 0, "raw_job_attempt_rejected"


def raw_failure_info(deps: RawFailureInfoOwner, exc: BaseException, *, stage_value: object, attempt_value: object, default_stage: str) -> dict[str, object]:
    stage_text, stage_reason = raw_job_text(stage_value, default_stage, field_name="collector")
    attempt, attempt_reason = raw_job_attempt(attempt_value)
    extra: dict[str, object] = {}
    if stage_reason:
        extra["collector_unavailable"] = unsupported_scheduler_value_evidence(stage_value, field_name="collector")
    if attempt_reason:
        extra["attempt_unavailable"] = unsupported_scheduler_value_evidence(attempt_value, field_name="attempt")
    return deps.default_failure_info(
        stage=stage_text,
        exception_type=no_hook_type_name(exc),
        error=scheduler_error_detail(exc),
        worker_pid=os.getpid(),
        attempt=attempt,
        extra=extra,
    )


__all__ = ("RawFailureInfoOwner", "raw_failure_info", "raw_job_attempt", "raw_job_text")
