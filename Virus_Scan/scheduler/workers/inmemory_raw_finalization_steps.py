"""Bounded steps for in-memory raw scan finalization."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_type_name
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value
from Virus_Scan.scheduler.workers.inmemory_raw_finalization_support import (
    InMemoryRawSummary,
    raw_tag_values,
    result_error_present,
    safe_raw_text,
)


def raw_finalization_tags(
    *,
    plan: object,
    pretriage_tags: object,
    summary: InMemoryRawSummary,
    effective_stage: str,
) -> tuple[list[str], list[str]]:
    identity_tags = raw_tag_values(scheduler_mapping_value(plan.identity, "tags", ()))
    common_tags = identity_tags + raw_tag_values(pretriage_tags) + [
        "router_stage_" + effective_stage,
        "global_raw_post_triage_escalated",
        "inmemory_raw_enrichment",
    ]
    return list(dict.fromkeys(common_tags + raw_tag_values(summary["tags"]))), identity_tags


def finalize_raw_tags(
    *,
    path: object,
    deps: object,
    raw_tags: list[str],
    strings_blob: str,
    effective_stage: str,
) -> tuple[list[object], TagEvidence, list[str]]:
    tags_final: list[object] = list(raw_tags)
    tag_evidence = TagEvidence()
    finalization_failures: list[str] = []
    try:
        generation = deps.finalize_tag_evidence_generation(
            raw_tags, path=path, strings_blob=strings_blob, source="inmemory_raw",
        )
        tag_evidence = generation.evidence
        tags_final = list(tag_evidence.tags)
    except deps.recoverable_exceptions as exc:
        record_optional_suppressed(deps, exc)
        finalization_failures.append("finalize_tag_evidence_generation:" + no_hook_type_name(exc))
        tags_final = list(raw_tags)
        tags_final.extend(raw_tag_values(deps.scanner_degraded_tags()))
    try:
        stage_score, stage_hits = deps.staged_enrichment_score(
            tag_evidence, effective_stage, 0.0,
        )
        if stage_score >= 12:
            tags_final.extend(["staged_detection", *["stage_hit:" + hit for hit in raw_tag_values(stage_hits)[:8]]])
    except deps.recoverable_exceptions as exc:
        record_optional_suppressed(deps, exc)
    return tags_final, tag_evidence, finalization_failures


def raw_suspicious_value(summary: InMemoryRawSummary, identity_tags: list[str]) -> bool:
    if "extension_mismatch" in identity_tags:
        return True
    return bool(summary["suspicious"])


def build_raw_integrity(
    *,
    plan: object,
    raw_results: list[dict[str, object]],
    finalization_failures: list[str],
) -> tuple[dict[str, object], tuple[object, ...], tuple[object, ...]]:
    jobs = no_hook_sequence_items(plan.jobs)
    raw_result_items = no_hook_sequence_items(raw_results)
    integrity: dict[str, object] = {
        "raw_expected": len(jobs),
        "raw_completed": len(raw_result_items),
        "missing_chunks": max(0, len(jobs) - len(raw_result_items)),
        "raw_failed": sum(1 for result in raw_result_items if result_error_present(result)),
        "had_degraded_stage": bool(
            finalization_failures
            or len(raw_result_items) < len(jobs)
            or any(result_error_present(result) for result in raw_result_items)
        ),
        "inmemory_raw": True,
    }
    return integrity, jobs, raw_result_items


def apply_raw_finalization_failures(
    *,
    integrity: dict[str, object],
    summary: InMemoryRawSummary,
    finalization_failures: list[str],
) -> None:
    if not finalization_failures:
        return
    integrity["worker_raw_finalization_failed"] = True
    integrity["worker_raw_finalization_failures"] = tuple(finalization_failures)
    summary["errors"].extend(finalization_failures)


def persist_raw_evidence(
    *,
    path: object,
    deps: object,
    plan: object,
    strings_blob: str,
    effective_stage: str,
    suspicious: bool,
    tags_final: list[object],
    integrity: dict[str, object],
) -> list[object]:
    try:
        deps.set_scan_integrity(path, integrity)
        deps.remember_scan_evidence(
            path,
            strings_blob=strings_blob,
            effective_stage=effective_stage,
            identity=plan.identity,
            suspicious=suspicious,
            asset_score=0.0,
            binary_failover_ran=False,
            tags=tuple(tags_final),
        )
        return tags_final
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        deps.record_issue("inmemory_raw_integrity_evidence_failed", exc, fatal=True, extra={"file": safe_raw_text(path)[:500]})
        integrity["had_degraded_stage"] = True
        integrity["integrity_persistence_failed"] = True
        return list(deps.normalize_tags(list(tags_final) + raw_tag_values(deps.scanner_degraded_tags())))


def build_raw_final_result(
    *,
    deps: object,
    plan: object,
    summary: InMemoryRawSummary,
    tags_final: list[object],
    tag_evidence: TagEvidence,
    integrity: dict[str, object],
    suspicious: bool,
    strings_blob: str,
    effective_stage: str,
) -> dict[str, object]:
    return {
        "tags": deps.normalize_tags(deps.apply_integrity_tags(tags_final, integrity, marker="inmemory_raw_incomplete")),
        "tag_evidence": tag_evidence,
        "suspicious": suspicious,
        "yara_hits": deps.normalize_yara_hits(summary["yara_hits"]),
        "yara_evidence": summary["yara_evidence"],
        "strings_blob": strings_blob,
        "effective_stage": effective_stage,
        "errors": summary["errors"],
        "file_id": plan.file_id,
        "scan_integrity": integrity,
    }


def record_optional_suppressed(deps: object, exc: BaseException) -> None:
    try:
        deps.record_suppressed("monitor_loop_suppressed", exc)
    except deps.recoverable_exceptions as record_exc:
        _ = record_exc


__all__ = (
    "apply_raw_finalization_failures",
    "build_raw_final_result",
    "build_raw_integrity",
    "finalize_raw_tags",
    "persist_raw_evidence",
    "raw_finalization_tags",
    "raw_suspicious_value",
)
