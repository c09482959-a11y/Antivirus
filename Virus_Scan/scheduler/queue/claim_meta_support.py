"""No-hook support helpers for queue claim metadata."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    no_hook_failure,
    no_hook_text,
)
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path

CLAIM_META_REMOVE_FAILED = False


def claim_time(value: object) -> object:
    parsed = exact_finite_float_or_none(value)
    if parsed is None or parsed < 0.0:
        reason = (
            "scheduler_claim_time_non_finite"
            if type(value) is float and not math.isfinite(value)
            else "scheduler_claim_time_rejected"
        )
        return no_hook_failure(reason, value), reason
    return parsed, ""


def claim_time_suffix(value: object) -> str:
    parsed = exact_finite_float_or_none(value)
    if parsed is None or parsed < 0.0:
        return "unavailable"
    return str(int(parsed * 1000000))


def claim_marker(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="scheduler_claim_marker_missing",
        unsupported_reason="scheduler_claim_marker_rejected",
    )
    if reason:
        return reason, reason
    if text:
        return text, ""
    return "scheduler_claim_marker_empty", "scheduler_claim_marker_empty"


def claim_meta_path_value(claim_path: object, claim_meta_path: Callable[..., object]) -> Path:
    safe_claim_path, claim_path_reason = scheduler_filesystem_path(claim_path)
    if claim_path_reason:
        raise ValueError(claim_path_reason)
    raw_meta_path = claim_meta_path(safe_claim_path)
    safe_meta_path, meta_path_reason = scheduler_filesystem_path(raw_meta_path)
    if meta_path_reason:
        raise ValueError(meta_path_reason)
    return Path(safe_meta_path)


def claim_meta_path_extra(meta_path: object) -> dict[str, str]:
    return {"claim_meta": scheduler_evidence_path(meta_path, field_name="claim_meta")}


def claim_meta_remove_failed(report: object, where: str, exc: BaseException) -> bool:
    report(where, exc)
    return CLAIM_META_REMOVE_FAILED
