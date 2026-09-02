"""Immutable-failure-aware strict prefilter state helpers."""
from __future__ import annotations


from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence


def new_prefilter_info() -> dict[str, object]:
    failure_evidence: list[object] = []
    return {
        "fast_result": None,
        "hits": [],
        "tags": [],
        "meta": {},
        "force_full": True,
        "failure_evidence": failure_evidence,
    }


def append_prefilter_failure(
    info: dict[str, object],
    *,
    stage_name: str,
    error_source: str,
    error: BaseException,
    affected_context: str,
) -> None:
    failures = info.setdefault("failure_evidence", [])
    failures.append(
        recoverable_failure_evidence(
            stage_name=stage_name,
            error_source=error_source,
            error=error,
            affected_context=affected_context,
        )
    )


__all__ = ("append_prefilter_failure", "new_prefilter_info")
