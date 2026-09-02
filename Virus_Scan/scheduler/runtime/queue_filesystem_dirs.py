"""Scheduler queue directory layout helpers."""
from __future__ import annotations

import os
from pathlib import Path
from pathlib import PurePath
from typing import Tuple

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text, no_hook_type_name
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.runtime.queue_filesystem_common import (
    QUEUE_FILESYSTEM_EXCEPTIONS,
    queue_filesystem_path_text,
    record_queue_filesystem_failure as _record_queue_dir_failure,
)

_UNSUPPORTED_STATE_MARKER = "unsupported_scheduler_queue_state"


def _safe_queue_path(value: object, *, stage: str) -> Path:
    safe_path, reason = queue_filesystem_path_text(value)
    if reason:
        _record_queue_dir_failure(stage, reason, value)
        raise ValueError(reason)
    return Path(safe_path)


def _record_mkdir_failure(stage: str, exc: BaseException) -> None:
    try:
        record_suppressed_failure(stage, exc, domain="runtime")
    except QUEUE_FILESYSTEM_EXCEPTIONS as reporting_exc:
        _ = reporting_exc


def _mkdir(path: Path, *, stage: str) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        _record_mkdir_failure(stage, exc)


def _state_tokens(states: object) -> tuple[str, ...]:
    if states is None:
        return ()
    if type(states) not in (tuple, list, set, frozenset, str, bytes, bytearray, int, float, bool):
        _record_queue_dir_failure("queue_identity_index_states_rejected", "queue_identity_index_states_rejected", states)
        return (_UNSUPPORTED_STATE_MARKER,)
    items = no_hook_sequence_items(states)
    tokens: list[str] = []
    for index, item in enumerate(items):
        text, reason = no_hook_text(item, unsupported_reason="queue_identity_index_state_rejected")
        if reason:
            _record_queue_dir_failure("queue_identity_index_state_rejected", reason, item)
            tokens.append("_".join((_UNSUPPORTED_STATE_MARKER, int.__str__(index), no_hook_type_name(item))))
        else:
            tokens.append(text)
    if type(states) in (set, frozenset):
        return tuple(sorted(tokens))
    return tuple(tokens)


def queue_claim_meta_path(claim_path: object) -> Path:
    """Sidecar path for active claim ownership metadata."""
    cp = _safe_queue_path(claim_path, stage="queue_claim_meta_path_rejected")
    return cp.with_name(str.__add__(cp.name, ".claim"))


def queue_failure_diagnostics_dir(queue_dir: object) -> Path:
    q = _safe_queue_path(queue_dir, stage="queue_failure_diagnostics_dir_rejected")
    d = q / "failure_diagnostics"
    _mkdir(d, stage="queue_failure_diagnostics_dir_create_failed")
    return d


def queue_identity_index_cache_key(queue_dir: object, states: object) -> object:
    q = _safe_queue_path(queue_dir, stage="queue_identity_index_dir_rejected")
    try:
        queue_key = os.path.abspath(PurePath.__str__(q))
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        _record_mkdir_failure("queue_identity_index_abspath_failed", exc)
        raise ValueError("queue_identity_index_path_unavailable") from exc
    return (queue_key, _state_tokens(states))


def queue_job_dirs(queue_dir: object) -> Tuple[Path, Path, Path, Path]:
    q = _safe_queue_path(queue_dir, stage="queue_job_dirs_rejected")
    return (q / "pending", q / "active", q / "done", q / "failed")


def queue_retire_dir(queue_dir: object) -> Path:
    q = _safe_queue_path(queue_dir, stage="queue_retire_dir_rejected")
    d = q / "retire"
    _mkdir(d, stage="queue_retire_dir_create_failed")
    return d


def queue_file_results_dir(queue_dir: object) -> Path:
    q = _safe_queue_path(queue_dir, stage="queue_file_results_dir_rejected")
    d = q / "file_results"
    _mkdir(d, stage="queue_file_results_dir_create_failed")
    return d
