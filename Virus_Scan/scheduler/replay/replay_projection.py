"""Replay projection identity helpers for deterministic scheduler validation."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.api import contracts as scheduler_contracts
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.replay.replay_result_fields import (
    exact_replay_text,
    first_replay_text,
    is_replay_mapping,
    replay_mapping_value,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_file_identity_for_path


_MISSING = object()
_MALFORMED_REPLAY_EVIDENCE_SEQUENCE = "scheduler replay evidence sequence is malformed"
_REPLAY_RESULT_MISSING_JOB_IDENTITY = "scheduler replay result missing job identity"
_REPLAY_RESULT_MISSING_FILE_PATH = "scheduler replay result missing file path"
_REPLAY_RESULT_MISSING_FIELD_PREFIX = "scheduler replay result missing "

@dataclass(frozen=True, slots=True)
class ReplaySequenceDecision:
    sequence: tuple[str, ...]
    accepted: bool
    reason: str
    source_type: str

@dataclass(frozen=True, slots=True)
class ReplayEvidenceKeyDecision:
    text: str
    accepted: bool
    reason: str
    source_type: str

def canonical_replay_sequence_decision(value: object) -> ReplaySequenceDecision:
    if value is None:
        return ReplaySequenceDecision((), accepted=False, reason="missing_replay_sequence", source_type="NoneType")
    if type(value) in {str, int, float}:
        raw = (value,)
    elif type(value) in {list, tuple, set, frozenset}:
        raw = value
    else:
        raise scheduler_contracts.SchedulerReplayEvidenceSequenceError()
    canonical: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = exact_replay_text(item)
        if text is None:
            raise scheduler_contracts.SchedulerReplayEvidenceSequenceError()
        if not text or text in seen:
            continue
        seen.add(text)
        canonical.append(text)
    return ReplaySequenceDecision(tuple(sorted(canonical, key=str.casefold)), accepted=True, reason="accepted", source_type=no_hook_type_name(value))


def replay_evidence_key_text_decision(key: object) -> ReplayEvidenceKeyDecision:
    text = exact_replay_text(key)
    if text is None:
        source_type = no_hook_type_name(key)
        return ReplayEvidenceKeyDecision(
            "unsupported_replay_evidence_key:" + source_type,
            accepted=False,
            reason="unsupported_replay_evidence_key",
            source_type=source_type,
        )
    return ReplayEvidenceKeyDecision(text, accepted=True, reason="accepted", source_type=no_hook_type_name(key))


def queue_replay_result_job_identity(result: Mapping[str, object] | None) -> str:
    job_id = first_replay_text(result, "job_id", "queue_id", "raw_job_id", "id", default="")
    if job_id:
        return job_id
    file_path = first_replay_text(result, "file", "path", "file_path", default="")
    if file_path:
        return queue_file_identity_for_path(file_path)
    raise scheduler_contracts.SchedulerReplayMissingJobIdentityError()


def queue_replay_result_file_identity(result: Mapping[str, object] | None) -> str:
    file_path = first_replay_text(result, "file", "path", "file_path", default="")
    if not file_path:
        raise scheduler_contracts.SchedulerReplayMissingFilePathError()
    archive_identity = first_replay_text(
        result,
        "archive_child_identity",
        "archive_member",
        "container_child",
        default="",
    )
    base_identity = queue_file_identity_for_path(file_path)
    return base_identity + "::" + archive_identity if archive_identity else base_identity


def canonical_replay_label(value: object, *, field_name: str) -> str:
    text = exact_replay_text(value)
    if not text:
        field_text = str.__str__(field_name) if type(field_name) is str and field_name else "replay field"
        raise scheduler_contracts.SchedulerReplayMissingFieldError(field_text)
    return text.casefold()

def canonical_replay_sequence(value: object) -> tuple[str, ...]:
    """Return canonical immutable tag/chain ordering for replay comparison."""
    return canonical_replay_sequence_decision(value).sequence


_VOLATILE_REPLAY_EVIDENCE_KEYS = frozenset({
    "time",
    "timestamp",
    "duration",
    "elapsed",
    "pid",
    "process_id",
    "thread_id",
    "worker_pid",
})


def replay_evidence_key_text(key: object) -> str:
    return replay_evidence_key_text_decision(key).text


def is_volatile_replay_evidence_key(key: object) -> bool:
    return replay_evidence_key_text(key).casefold() in _VOLATILE_REPLAY_EVIDENCE_KEYS


def stable_replay_evidence_value(value: object) -> object:
    value = materialize_scheduler_mapping(value)
    if type(value) is dict:
        ordered = sorted(dict.items(value), key=lambda pair: replay_evidence_key_text(pair[0]).casefold())
        return {
            replay_evidence_key_text(key): stable_replay_evidence_value(item)
            for key, item in ordered
            if not is_volatile_replay_evidence_key(key)
        }
    if type(value) in {list, tuple, set, frozenset}:
        projected = [stable_replay_evidence_value(item) for item in value]
        return sorted(projected, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return value


def iter_replay_evidence_items(value: object) -> object:
    if value is None:
        return
    if type(value) is dict:
        yield value
        return
    if type(value) in {list, tuple, set, frozenset}:
        for item in value:
            yield from iter_replay_evidence_items(item)
        return
    yield value


def canonical_replay_evidence(value: object) -> tuple[str, ...]:
    """Return deterministic evidence tokens for replay comparison."""
    tokens: list[str] = []
    seen: set[str] = set()
    for item in iter_replay_evidence_items(value):
        stable = stable_replay_evidence_value(item)
        token = json.dumps(stable, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if token and token not in seen:
            seen.add(token)
            tokens.append(token)
    return tuple(sorted(tokens))


def replay_result_evidence(result: Mapping[str, object]) -> tuple[str, ...]:
    scheduler = replay_mapping_value(result, "scheduler", default=None)
    sources: list[object] = []
    for key in ("scheduler_evidence", "scheduler_failure_evidence", "evidence"):
        value = replay_mapping_value(result, key, default=_MISSING)
        if value is not _MISSING:
            sources.append(value)
    if is_replay_mapping(scheduler):
        for key in ("evidence", "scheduler_evidence", "scheduler_failure_evidence"):
            value = replay_mapping_value(scheduler, key, default=_MISSING)
            if value is not _MISSING:
                sources.append(value)
    return canonical_replay_evidence(sources)


__all__ = (
    "canonical_replay_evidence",
    "canonical_replay_label",
    "canonical_replay_sequence",
    "queue_replay_result_file_identity",
    "queue_replay_result_job_identity",
    "replay_result_evidence",
)
