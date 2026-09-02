"""Scanner-owned bounded public-export smoke case builders.

The public export gate owns discovery and result reporting in
``public_export_smoke``.  This module owns only the synthetic callable case
matrix so the CI gate cannot regress into one oversized mixed-purpose function.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from Virus_Scan.scanners import raw_chunk_core, raw_queue_scan_result
from Virus_Scan.scanners.ci.public_export_smoke_case_domains import (
    archive_and_binary_cases,
    dotnet_entropy_image_cases,
    payload_pickle_pipeline_cases,
    raw_chunk_queue_cases,
    text_engine_cases,
    text_policy_cases,
)
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.scanners.config.immutable_policy import freeze_policy_contract_value


def _case_text(value: object) -> str:
    if value is None:
        return ""
    if type(value) is str:
        return value
    if type(value) is int and type(value) is not bool:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value)
    if isinstance(value, Path):
        return Path.__str__(value)
    return "public_export_case_text_rejected:" + no_hook_type_name(value)


def _case_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if type(value) is bytes:
        return bytes(value)
    if type(value) is bytearray:
        return bytes(value)
    return b""


def _tag_values(tags: object) -> tuple[object, ...]:
    if tags is None:
        return ()
    if type(tags) is tuple:
        return tags
    if type(tags) is list:
        return tuple(tags)
    if type(tags) is frozenset:
        return tuple(tags)
    return ("tag_sequence_rejected:" + no_hook_type_name(tags),)


def _tag_text(tag: object) -> str:
    if type(tag) is str:
        return tag
    if type(tag) is int and type(tag) is not bool:
        return int.__str__(tag)
    return "tag_rejected:" + no_hook_type_name(tag)


def _integrity_mapping(integrity: object) -> dict[str, object]:
    if integrity is None:
        return {}
    if type(integrity) is dict:
        return dict(dict.items(integrity))
    return {"integrity_rejected": no_hook_type_name(integrity)}


@dataclass(frozen=True, slots=True)
class PublicExportSmokeCaseContext:
    text_path: str
    binary_path: str
    image_path: str
    rpa_path: str
    zip_path: str
    text_blob: str
    bytes_blob: bytes
    chunk_kwargs: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "text_path", _case_text(self.text_path))
        object.__setattr__(self, "binary_path", _case_text(self.binary_path))
        object.__setattr__(self, "image_path", _case_text(self.image_path))
        object.__setattr__(self, "rpa_path", _case_text(self.rpa_path))
        object.__setattr__(self, "zip_path", _case_text(self.zip_path))
        object.__setattr__(self, "text_blob", _case_text(self.text_blob))
        object.__setattr__(self, "bytes_blob", _case_bytes(self.bytes_blob))
        object.__setattr__(self, "chunk_kwargs", freeze_policy_contract_value(_integrity_mapping(self.chunk_kwargs)))


def _report_failure(_label: str, _exc: BaseException, **_kwargs: object) -> None:
    return None


def _context_failure(current: object, collector: str, exc: BaseException, **_kwargs: object) -> list[str]:
    tags = list(_tag_values(current))
    tags.extend(scanner_failure_evidence_tags("raw_chunk_policy", collector, exc, ["raw_chunk_context_failure"]))
    return tags


def _scanner_degraded_tags(tags: object) -> list[str]:
    out = list(_tag_values(tags))
    if "scanner_degraded" not in out:
        out.append("scanner_degraded")
    return out


def _normalize_tags(tags: object) -> list[str]:
    out: list[str] = []
    for tag in _tag_values(tags):
        value = _tag_text(tag)
        if value not in out:
            out.append(value)
    return out


def _raw_queue_normalize_tags(tags: object) -> raw_queue_scan_result.RawQueueList:
    out: raw_queue_scan_result.RawQueueList = []
    out.extend(_normalize_tags(tags))
    return out


def _raw_queue_scanner_degraded_tags(tags: object) -> raw_queue_scan_result.RawQueueList:
    out: raw_queue_scan_result.RawQueueList = []
    out.extend(_scanner_degraded_tags(tags))
    return out


def _identity_tags(tags: object, *_args: object, **_kwargs: object) -> raw_queue_scan_result.RawQueueList:
    return _raw_queue_normalize_tags(tags)


def _stage_score(
    _tags: raw_queue_scan_result.RawQueueList,
    _stage: str,
    _base: float,
) -> tuple[float, raw_queue_scan_result.RawQueueList]:
    return (0.0, [])


def _mark_integrity(
    _path: str,
    integrity: raw_queue_scan_result.RawQueueMutableMapping,
    **_kwargs: object,
) -> raw_queue_scan_result.RawQueueMutableMapping:
    out = _integrity_mapping(integrity)
    out["had_degraded_stage"] = True
    return out


def _set_integrity(_path: str, _integrity: raw_queue_scan_result.RawQueueMapping) -> None:
    return None


def _remember_evidence(*_args: object, **_kwargs: object) -> None:
    return None


@dataclass(frozen=True, slots=True)
class _SmokeTagEvidence:
    tags: tuple[str, ...] = ()
    records: tuple[object, ...] = ()

    def to_record(self, *, record_limit: int = 256) -> dict[str, object]:
        limit = max(0, min(record_limit, 256)) if type(record_limit) is int else 256
        return {"tags": self.tags, "records": self.records[:limit]}


@dataclass(frozen=True, slots=True)
class _SmokeTagEvidenceGeneration:
    evidence: _SmokeTagEvidence


def _smoke_finalize_tag_evidence_generation(
    inputs: object,
    *,
    previous_generation: _SmokeTagEvidenceGeneration | None = None,
    **_kwargs: object,
) -> _SmokeTagEvidenceGeneration:
    previous = () if previous_generation is None else previous_generation.evidence.tags
    if hasattr(inputs, "tags") and type(getattr(inputs, "tags", None)) is tuple:
        incoming = tuple(getattr(inputs, "tags"))
    else:
        incoming = tuple(_normalize_tags(inputs))
    values = previous + incoming
    unique = tuple(dict.fromkeys(values))
    return _SmokeTagEvidenceGeneration(
        evidence=_SmokeTagEvidence(tags=unique, records=unique),
    )


def _raw_queue_deps() -> raw_queue_scan_result.RawQueueScanResultDependencies:
    return raw_queue_scan_result.RawQueueScanResultDependencies(
        ordered_unique_tags=_raw_queue_normalize_tags,
        finalize_tag_evidence_generation=_smoke_finalize_tag_evidence_generation,
        apply_integrity_tags=_identity_tags,
        normalize_tags=_raw_queue_normalize_tags,
        staged_enrichment_score=_stage_score,
        scanner_degraded_tags=_raw_queue_scanner_degraded_tags,
        mark_raw_integrity_failure=_mark_integrity,
        remember_scan_evidence=_remember_evidence,
        normalize_yara_hits=_raw_queue_normalize_tags,
        set_scan_integrity=_set_integrity,
    )


def _case_context(samples: dict[str, Path]) -> PublicExportSmokeCaseContext:
    text_path = str(samples["text"])
    return PublicExportSmokeCaseContext(
        text_path=text_path,
        binary_path=str(samples["binary"]),
        image_path=str(samples["image"]),
        rpa_path=str(samples["rpa"]),
        zip_path=str(samples["zip"]),
        text_blob=samples["text"].read_text(encoding="utf-8"),
        bytes_blob=samples["binary"].read_bytes(),
        chunk_kwargs={
            "read_range_text_func": raw_chunk_core.read_range_text,
            "should_context_scan_func": raw_chunk_core.should_context_scan,
            "contextual_scan": lambda *_args, **_kwargs: [],
            "context_failure": _context_failure,
        },
    )



def build_public_export_smoke_cases(samples: dict[str, Path]) -> dict[tuple[str, str], Callable[[], object]]:
    ctx = _case_context(samples)
    cases: dict[tuple[str, str], Callable[[], object]] = {}
    cases.update(archive_and_binary_cases(ctx))
    cases.update(dotnet_entropy_image_cases(ctx))
    cases.update(payload_pickle_pipeline_cases(ctx))
    cases.update(raw_chunk_queue_cases(ctx, scanner_degraded_tags=_scanner_degraded_tags, report_failure=_report_failure, raw_queue_deps=_raw_queue_deps))
    cases.update(text_engine_cases(ctx))
    cases.update(text_policy_cases(ctx))
    return cases


__all__ = (
    "PublicExportSmokeCaseContext",
    "build_public_export_smoke_cases",
)
