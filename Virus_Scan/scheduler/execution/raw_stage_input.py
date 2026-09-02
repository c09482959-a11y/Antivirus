"""No-hook raw-stage input normalization helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol, TypeAlias

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.execution.exact_int_support import execution_exact_int
from Virus_Scan.scheduler.execution.raw_stage_input_support import exact_bool, exact_text, runtime_cache_max
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text, scheduler_tag_texts

RawStageMappingItems: TypeAlias = tuple[tuple[object, object], ...]
RawStageOutput: TypeAlias = dict[str, object]
RawStageJob: TypeAlias = dict[str, object]


class RawChunkBytesReader(Protocol):
    def raw_chunk_bytes(self) -> object: ...


class RawCollectorNormalizer(Protocol):
    @property
    def normalize_raw_collector_value(self) -> Callable[[object], Mapping[str, object]]: ...


class RawStageRuntimeValueReader(Protocol):
    def runtime_value(self, key: str, default: object) -> object: ...


@dataclass(frozen=True)
class RawStageInput:
    out: RawStageOutput
    safe_job: RawStageJob
    path: str
    start: int
    size: int
    boundary_failed: bool


@dataclass(frozen=True)
class RawStageSequenceDecision:
    value: int | str | None
    available: bool
    reason: str


def _field(items: RawStageMappingItems | None, key: str, default: object = None) -> object:
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and item_key == key:
            return item_value
    return default


def _evidence(value: object, *, field_name: str, reason: str) -> RawStageOutput:
    evidence: RawStageOutput = dict(unsupported_scheduler_value_evidence(value, field_name=field_name))
    evidence["raw_stage_input_rejection_reason"] = reason
    return evidence


def _add(out: RawStageOutput, key: str, evidence: RawStageOutput) -> None:
    issues = dict.get(out, "raw_stage_boundary_evidence")
    updated = dict(issues) if type(issues) is dict else {}
    updated[key] = evidence
    out["raw_stage_boundary_evidence"] = updated
def _seq(value: object) -> RawStageSequenceDecision:
    if value is None:
        return RawStageSequenceDecision(None, available=False, reason="raw_stage_seq_missing")
    if type(value) is int and type(value) is not bool:
        return RawStageSequenceDecision(value, available=True, reason="")
    text, reason = exact_text(value, "", field_name="seq")
    if reason == "" and text:
        return RawStageSequenceDecision(text, available=True, reason="")
    return RawStageSequenceDecision(None, available=False, reason=reason or "raw_stage_seq_rejected")


def build_raw_stage_input(job: object, deps: RawChunkBytesReader) -> RawStageInput:
    items = no_hook_mapping_items(job)
    raw_path = _field(items, "file")
    path, path_reason = scheduler_path_text(raw_path)
    raw_collector = _field(items, "collector", "")
    collector, collector_reason = exact_text(raw_collector, "", field_name="collector")
    raw_start = _field(items, "start", 0)
    start, start_reason = execution_exact_int(raw_start, 0, reason="raw_stage_start_rejected")
    raw_size = _field(items, "size", None)
    try:
        chunk_bytes = deps.raw_chunk_bytes()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raw_chunk_bytes = 0
        raw_chunk_bytes_evidence: RawStageOutput | None = {
            "raw_stage_input_rejection_reason": "raw_stage_chunk_bytes_unavailable",
            "exception_type": no_hook_type_name(exc),
            "scheduler_value_status": "unsupported",
            "field_name": "raw_stage_chunk_bytes",
        }
    else:
        raw_chunk_bytes, raw_chunk_bytes_reason = execution_exact_int(
            chunk_bytes,
            0,
            minimum=0,
            reason="raw_stage_chunk_bytes_rejected",
        )
        raw_chunk_bytes_evidence = (
            _evidence(chunk_bytes, field_name="raw_stage_chunk_bytes", reason=raw_chunk_bytes_reason)
            if raw_chunk_bytes_reason
            else None
        )
    size, size_reason = execution_exact_int(raw_size, raw_chunk_bytes, reason="raw_stage_size_rejected")
    raw_attempt = _field(items, "attempt", 0)
    attempt, attempt_reason = execution_exact_int(raw_attempt, 0, reason="raw_stage_attempt_rejected")
    raw_retried = _field(items, "retried", default=False)
    retried, retried_reason = exact_bool(raw_retried, default_value=False, reason="raw_stage_retried_rejected")
    raw_group_index = _field(items, "group_index", 0)
    group_index, group_index_reason = execution_exact_int(raw_group_index, 0, reason="raw_stage_group_index_rejected")
    raw_group_count = _field(items, "group_count", 1)
    group_count, group_count_reason = execution_exact_int(raw_group_count, 1, minimum=1, reason="raw_stage_group_count_rejected")
    raw_yara_source = _field(items, "yara_source", "")
    yara_source, yara_source_reason = scheduler_path_text(raw_yara_source)
    file_id = _field(items, "file_id")
    seq_decision = _seq(_field(items, "seq"))
    seq = seq_decision.value
    safe_job: RawStageJob = {
        "file": path,
        "collector": collector,
        "start": start,
        "size": size,
        "file_id": file_id if type(file_id) in {str, int} else None,
        "seq": seq,
        "attempt": attempt,
        "retried": retried,
        "group_index": group_index,
        "group_count": group_count,
        "yara_source": yara_source,
    }
    out: RawStageOutput = {
        "tags": [],
        "yara_hits": [],
        "yara_evidence": None,
        "strings_blob": "",
        "ordered_events": [],
        "suspicious": False,
        "errors": [],
        "file": path,
        "file_id": safe_job["file_id"],
        "seq": seq,
        "collector": collector,
        "attempt": attempt,
        "retried": retried,
    }
    if items is None:
        _add(out, "job_unavailable", _evidence(job, field_name="raw_stage_job", reason="non_materializable_raw_stage_job"))
    if raw_chunk_bytes_evidence is not None:
        _add(out, "raw_chunk_bytes_unavailable", raw_chunk_bytes_evidence)
    if seq_decision.reason and _field(items, "seq") is not None:
        _add(out, "seq_unavailable", _evidence(_field(items, "seq"), field_name="seq", reason=seq_decision.reason))
    rejections = (
        ("file_unavailable", raw_path, "file", path_reason),
        ("collector_unavailable", raw_collector, "collector", collector_reason),
        ("start_unavailable", raw_start, "start", start_reason),
        ("size_unavailable", raw_size, "size", size_reason),
        ("attempt_unavailable", raw_attempt, "attempt", attempt_reason),
        ("retried_unavailable", raw_retried, "retried", retried_reason),
        ("group_index_unavailable", raw_group_index, "group_index", group_index_reason),
        ("group_count_unavailable", raw_group_count, "group_count", group_count_reason),
        ("yara_source_unavailable", raw_yara_source, "yara_source", yara_source_reason),
    )
    for issue_key, raw_value, field_name, reason in rejections:
        if reason:
            _add(out, issue_key, _evidence(raw_value, field_name=field_name, reason=reason))
    return RawStageInput(out, safe_job, path, start, size, bool(dict.get(out, "raw_stage_boundary_evidence")))
def normalise_raw_stage_out_tags(out: RawStageOutput, deps: RawCollectorNormalizer) -> None:
    raw_tags = dict.get(out, "tags")
    if type(raw_tags) is tuple:
        tmp = deps.normalize_raw_collector_value(raw_tags)
        out["tags"] = dict.get(tmp, "tags", []) if type(tmp) is dict else []
        if type(tmp) is dict and dict.__contains__(tmp, "meta"):
            out["meta"] = dict.__getitem__(tmp, "meta")
        return
    tags = scheduler_tag_texts(raw_tags)
    if raw_tags is not None and not tags:
        _add(out, "tags_unavailable", _evidence(raw_tags, field_name="raw_stage_tags", reason="raw_stage_tags_rejected"))
    out["tags"] = list(tags)


def raw_stage_runtime_cache_max(deps: RawStageRuntimeValueReader) -> int:
    return runtime_cache_max(deps)


__all__ = ("RawStageInput", "build_raw_stage_input", "normalise_raw_stage_out_tags", "raw_stage_runtime_cache_max")
