"""Canonical global raw-queue scan result assembly.

This module owns the final accumulator-to-scan-result boundary for the raw
queue. Keeping this logic out of ``raw_queue.py`` makes the finalization path
independently testable and prevents the scheduler orchestrator from also owning
scanner/evidence assembly policy.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from typing import Protocol
from dataclasses import dataclass

from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot


PLR2004N12 = 12

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
RawQueueValue = object
RawQueueRecord = dict[str, RawQueueValue]
RawQueueMapping = Mapping[str, RawQueueValue]
RawQueueMutableMapping = MutableMapping[str, RawQueueValue]
RawQueueList = list[RawQueueValue]


class __RawQueueTagEvidence(Protocol):
    @property
    def tags(self) -> tuple[str, ...]: ...

    @property
    def records(self) -> tuple[object, ...]: ...

    def to_record(self, *, record_limit: int = 256) -> dict[str, object]: ...


class _RawQueueTagEvidenceGeneration(Protocol):
    @property
    def evidence(self) -> _RawQueueTagEvidence: ...


@dataclass(frozen=True)
class RawQueueScanResultDependencies:
    """Explicit dependencies for final raw queue result assembly."""

    ordered_unique_tags: Callable[[RawQueueValue], RawQueueList]
    finalize_tag_evidence_generation: Callable[..., _RawQueueTagEvidenceGeneration]
    apply_integrity_tags: Callable[..., RawQueueList]
    normalize_tags: Callable[[RawQueueValue], RawQueueList]
    staged_enrichment_score: Callable[[object, str, float], tuple[float, RawQueueList]]
    scanner_degraded_tags: Callable[[RawQueueValue], RawQueueList]
    mark_raw_integrity_failure: Callable[..., RawQueueMutableMapping]
    remember_scan_evidence: Callable[..., RawQueueValue]
    normalize_yara_hits: Callable[[RawQueueValue], RawQueueList]
    set_scan_integrity: Callable[[str, RawQueueMapping], RawQueueValue]


def _raw_queue_int(value: RawQueueValue, default: int = 0) -> int:
    if type(value) is int and type(value) is not bool:
        return value
    if type(value) is float:
        try:
            return int(value)
        except (OverflowError, ValueError):
            return default
    if type(value) is str:
        try:
            return int(str.strip(str.__str__(value)))
        except (TypeError, ValueError):
            return default
    return default


def _raw_queue_bool(value: RawQueueValue) -> bool:
    if type(value) is bool:
        return value
    if type(value) is int and type(value) is not bool:
        return value != 0
    return False


def _raw_queue_text(value: RawQueueValue, default: str = "") -> str:
    if type(value) is str:
        text = str.__str__(value)
        return text or default
    if type(value) is int and type(value) is not bool:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value)
    return default


def _raw_queue_sequence(value: RawQueueValue) -> RawQueueList:
    if type(value) is list:
        return list(value)
    if type(value) is tuple:
        return list(value)
    return []


def _raw_integrity(accum: RawQueueMapping) -> RawQueueMutableMapping:
    expected_i = _raw_queue_int(accum.get("expected", 0))
    completed_i = _raw_queue_int(accum.get("completed", 0))
    failed_i = _raw_queue_int(accum.get("failed", 0))
    return {
        "raw_expected": expected_i,
        "raw_completed": completed_i,
        "missing_chunks": max(0, expected_i - completed_i),
        "raw_failed": failed_i,
        "raw_retried": _raw_queue_int(accum.get("retried", 0)),
        "had_degraded_stage": _raw_queue_bool(accum.get("degraded", False)) or failed_i > 0 or completed_i < expected_i,
    }


def _strings_blob(accum: RawQueueMapping) -> str:
    raw = "\n".join(_raw_queue_text(part) for part in _raw_queue_sequence(accum.get("strings_parts", ())))
    return raw[:_SCANNER_LIMITS_POLICY.raw_queue_strings_blob_max_chars]


def _merge_raw_evidence(
    *,
    path: str,
    strings_blob: str,
    source: str,
    generation: _RawQueueTagEvidenceGeneration,
    tags: object,
    deps: RawQueueScanResultDependencies,
) -> _RawQueueTagEvidenceGeneration:
    published = frozenset(
        str.__str__(tag) for tag in generation.evidence.tags if type(tag) is str
    )
    missing = [
        str.__str__(tag) for tag in _raw_queue_sequence(tags)
        if type(tag) is str and str.__str__(tag) and str.__str__(tag) not in published
    ]
    if not missing:
        return generation
    return deps.finalize_tag_evidence_generation(
        missing,
        path=path,
        strings_blob=strings_blob,
        source=source + ":merge",
        previous_generation=generation,
    )


def _initial_raw_tags(
    *, path: str, strings_blob: str, accum: RawQueueMapping, integrity: RawQueueMapping, deps: RawQueueScanResultDependencies
) -> tuple[RawQueueList, _RawQueueTagEvidenceGeneration]:
    raw_tags = deps.ordered_unique_tags(_raw_queue_sequence(accum.get("tags", ())))
    generation = deps.finalize_tag_evidence_generation(
        raw_tags, path=path, strings_blob=strings_blob, source="global_raw_queue",
    )
    tags = deps.apply_integrity_tags(list(generation.evidence.tags), integrity, marker="global_raw_accumulator_incomplete")
    generation = _merge_raw_evidence(
        path=path,
        strings_blob=strings_blob,
        source="global_raw_queue_integrity",
        generation=generation,
        tags=tags,
        deps=deps,
    )
    return list(tags), generation


def _apply_stage_scoring(
    *,
    path: str,
    strings_blob: str,
    tags: RawQueueList,
    tag_generation: _RawQueueTagEvidenceGeneration,
    accum: RawQueueMapping,
    effective_stage: str,
    integrity: RawQueueMutableMapping,
    deps: RawQueueScanResultDependencies,
) -> tuple[RawQueueList, _RawQueueTagEvidenceGeneration, RawQueueMutableMapping]:
    try:
        stage_score, stage_hits = deps.staged_enrichment_score(
            tag_generation.evidence,
            _raw_queue_text(accum.get("effective_stage", ""), effective_stage),
            0.0,
        )
        if stage_score >= PLR2004N12:
            tags.extend(["staged_detection", *["stage_hit:" + _raw_queue_text(hit) for hit in stage_hits[:8]]])
            tag_generation = _merge_raw_evidence(
                path=path,
                strings_blob=strings_blob,
                source="global_raw_queue_stage_scoring",
                generation=tag_generation,
                tags=tags,
                deps=deps,
            )
    except (TypeError, ValueError, KeyError, RuntimeError) as score_exc:
        tags = deps.scanner_degraded_tags([*list(tags), "raw_stage_scoring_failed"])
        integrity = deps.mark_raw_integrity_failure(
            path,
            integrity,
            marker="raw_stage_scoring_failed",
            exc=score_exc,
            where="raw_queue.stage_scoring_failed",
        )
        tag_generation = _merge_raw_evidence(
            path=path,
            strings_blob=strings_blob,
            source="global_raw_queue_scoring_failure",
            generation=tag_generation,
            tags=tags,
            deps=deps,
        )
    return tags, tag_generation, integrity


def _remember_raw_evidence(
    *,
    path: str,
    strings_blob: str,
    effective_stage: str,
    accum: RawQueueMapping,
    identity: RawQueueMapping,
    suspicious: bool,
    tags: RawQueueList,
    integrity: RawQueueMutableMapping,
    deps: RawQueueScanResultDependencies,
) -> tuple[RawQueueList, RawQueueMutableMapping]:
    try:
        deps.remember_scan_evidence(
            path,
            strings_blob=strings_blob,
            effective_stage=_raw_queue_text(accum.get("effective_stage", ""), effective_stage),
            identity=identity,
            suspicious=suspicious,
            asset_score=0.0,
            binary_failover_ran=False,
            tags=list(tags),
        )
    except (OSError, TypeError, ValueError, RuntimeError) as evidence_exc:
        tags = deps.scanner_degraded_tags([*list(tags), 'raw_evidence_record_failed'])
        integrity = deps.mark_raw_integrity_failure(
            path,
            integrity,
            marker="raw_evidence_record_failed",
            exc=evidence_exc,
            where="raw_queue.evidence_record_failed",
        )
    return tags, integrity


def _raw_result_dict(
    *,
    file_id: str,
    accum: RawQueueMapping,
    effective_stage: str,
    strings_blob: str,
    suspicious: bool,
    tags: RawQueueList,
    tag_evidence: _RawQueueTagEvidence,
    integrity: RawQueueMapping,
    deps: RawQueueScanResultDependencies,
) -> RawQueueRecord:
    final_tags = deps.apply_integrity_tags(tags, integrity, marker="global_raw_accumulator_incomplete")
    return {
        "tags": deps.normalize_tags(final_tags),
        "tag_evidence": tag_evidence.to_record(record_limit=256),
        "suspicious": suspicious,
        "yara_hits": deps.normalize_yara_hits(_raw_queue_sequence(accum.get("yara_hits", ()))),
        "strings_blob": strings_blob,
        "effective_stage": _raw_queue_text(accum.get("effective_stage", ""), effective_stage),
        "errors": _raw_queue_sequence(accum.get("errors", ())),
        "file_id": file_id,
        "scan_integrity": dict(integrity),
    }


def build_global_raw_scan_result(
    *,
    path: str,
    file_id: str,
    accum: RawQueueMapping,
    identity: RawQueueMapping,
    effective_stage: str,
    deps: RawQueueScanResultDependencies,
) -> RawQueueRecord:
    """Assemble a deterministic scan result from a completed raw accumulator."""

    integrity = _raw_integrity(accum)
    deps.set_scan_integrity(path, integrity)
    strings_blob = _strings_blob(accum)
    tags, tag_generation = _initial_raw_tags(
        path=path, strings_blob=strings_blob, accum=accum, integrity=integrity, deps=deps,
    )
    tags, tag_generation, integrity = _apply_stage_scoring(
        path=path,
        strings_blob=strings_blob,
        tags=tags,
        tag_generation=tag_generation,
        accum=accum,
        effective_stage=effective_stage,
        integrity=integrity,
        deps=deps,
    )
    suspicious = _raw_queue_bool(accum.get("suspicious", False)) or any(
        type(tag) is str and tag == "extension_mismatch"
        for tag in _raw_queue_sequence(identity.get("tags", ()))
    )
    tags, integrity = _remember_raw_evidence(
        path=path,
        strings_blob=strings_blob,
        effective_stage=effective_stage,
        accum=accum,
        identity=identity,
        suspicious=suspicious,
        tags=tags,
        integrity=integrity,
        deps=deps,
    )
    tags = deps.apply_integrity_tags(tags, integrity, marker="global_raw_accumulator_incomplete")
    tag_generation = _merge_raw_evidence(
        path=path,
        strings_blob=strings_blob,
        source="global_raw_queue_final",
        generation=tag_generation,
        tags=tags,
        deps=deps,
    )
    return _raw_result_dict(
        file_id=file_id,
        accum=accum,
        effective_stage=effective_stage,
        strings_blob=strings_blob,
        suspicious=suspicious,
        tags=tags,
        tag_evidence=tag_generation.evidence,
        integrity=integrity,
        deps=deps,
    )


__all__ = ("RawQueueScanResultDependencies", "build_global_raw_scan_result")
