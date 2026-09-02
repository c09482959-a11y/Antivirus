"""Finalization ownership for in-memory raw scheduler enrichment."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.scheduler.workers.inmemory_raw_finalization_support import safe_raw_text, summarize_inmemory_raw_results
from Virus_Scan.scheduler.workers.inmemory_raw_finalization_steps import (
    apply_raw_finalization_failures,
    build_raw_final_result,
    build_raw_integrity,
    finalize_raw_tags,
    persist_raw_evidence,
    raw_finalization_tags,
    raw_suspicious_value,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.inmemory_raw import InMemoryRawScanDependencies
    from Virus_Scan.scheduler.workers.inmemory_raw_plan import InMemoryRawPlan


def finalize_inmemory_raw_scan_result(
    *,
    path: object,
    pretriage_tags: object,
    raw_results: list[dict[str, object]],
    plan: InMemoryRawPlan,
    deps: InMemoryRawScanDependencies,
) -> dict[str, object]:
    """Finalize in-memory raw evidence, integrity, and replay-visible result."""
    summary = summarize_inmemory_raw_results(raw_results)
    effective_stage = safe_raw_text(plan.effective_stage, replacement_text="raw")
    raw_tags, identity_tags = raw_finalization_tags(
        plan=plan,
        pretriage_tags=pretriage_tags,
        summary=summary,
        effective_stage=effective_stage,
    )
    strings_blob = summary["strings_blob"]
    tags_final, tag_evidence, finalization_failures = finalize_raw_tags(
        path=path,
        deps=deps,
        raw_tags=raw_tags,
        strings_blob=strings_blob,
        effective_stage=effective_stage,
    )
    suspicious = raw_suspicious_value(summary, identity_tags)
    integrity, _jobs, _raw_result_items = build_raw_integrity(
        plan=plan,
        raw_results=raw_results,
        finalization_failures=finalization_failures,
    )
    apply_raw_finalization_failures(
        integrity=integrity,
        summary=summary,
        finalization_failures=finalization_failures,
    )
    tags_final = persist_raw_evidence(
        path=path,
        deps=deps,
        plan=plan,
        strings_blob=strings_blob,
        effective_stage=effective_stage,
        suspicious=suspicious,
        tags_final=tags_final,
        integrity=integrity,
    )
    return build_raw_final_result(
        deps=deps,
        plan=plan,
        summary=summary,
        tags_final=tags_final,
        tag_evidence=tag_evidence,
        integrity=integrity,
        suspicious=suspicious,
        strings_blob=strings_blob,
        effective_stage=effective_stage,
    )


__all__ = ("finalize_inmemory_raw_scan_result",)
