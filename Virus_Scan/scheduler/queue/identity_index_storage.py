"""Filesystem storage primitives for queue identity indexes."""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_type_name
from Virus_Scan.runtime.api import durable_replace_regular_file, flush_open_writable_file
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path, scheduler_path_text, scheduler_text
from Virus_Scan.scheduler.queue.identity_index_contract import (
    IdentityIndexKeyDigestDecision, IdentityIndexPathDecision, IdentityIndexQueueDirDecision,
    IdentityIndexReadDecision, IdentityIndexSnapshotDecision, IdentityIndexWriteDecision,
    identity_index_key_digest_decision, identity_index_path_decision, identity_index_queue_dir_decision,
    identity_index_read_decision, identity_index_snapshot_decision, identity_index_write_decision,
)

_INDEX_DIR_NAME = "identity_index"
StorageReport = Callable[[str, BaseException | str], None]


def index_dir(queue_dir: os.PathLike[str] | str) -> Path:
    queue_path, reason = scheduler_filesystem_path(queue_dir)
    if reason or (type(queue_path) is str and queue_path == ""):
        raise ValueError(reason or "scheduler_path_missing")
    return Path(str(Path(queue_path).resolve())) / _INDEX_DIR_NAME


def queue_dir_from_key_decision(key: object, report: StorageReport) -> IdentityIndexQueueDirDecision:
    if type(key) is not tuple or len(key) == 0:
        report("missing_queue_key", ValueError("queue identity index key is empty"))
        return identity_index_queue_dir_decision("rejected", "missing_queue_key")
    queue_path, reason = scheduler_filesystem_path(key[0])
    if reason or (type(queue_path) is str and queue_path == ""):
        failure_reason = reason or "scheduler_path_missing"
        report("queue_dir_key_failed", ValueError(failure_reason))
        return identity_index_queue_dir_decision("rejected", failure_reason)
    resolved_queue_dir: Path | None = None
    queue_dir_resolution_failed = False
    try:
        resolved_queue_dir = Path(str(Path(queue_path).resolve()))
    except (TypeError, ValueError, OSError) as exc:
        report("queue_dir_key_failed", exc)
        queue_dir_resolution_failed = True
    if queue_dir_resolution_failed or resolved_queue_dir is None:
        return identity_index_queue_dir_decision("rejected", "queue_dir_key_failed")
    return identity_index_queue_dir_decision("resolved", "", resolved_queue_dir)


def queue_dir_from_key(key: object, report: StorageReport) -> Path | None:
    decision = queue_dir_from_key_decision(key, report)
    return decision.path if decision.status == "resolved" else None


def key_digest_decision(key: object, report: StorageReport) -> IdentityIndexKeyDigestDecision:
    if type(key) is not tuple:
        report("key_container_rejected", ValueError("queue identity index key must be an exact tuple"))
        return identity_index_key_digest_decision("rejected", "key_container_rejected")
    parts: list[str] = []
    for index, part in enumerate(key):
        if index == 0:
            text, reason = scheduler_path_text(part)
        else:
            text, reason = scheduler_text(part, unsupported_reason="queue_identity_index_key_part_rejected")
        if reason:
            report("key_part_rejected", ValueError(reason + ":" + no_hook_type_name(part)))
            return identity_index_key_digest_decision("rejected", reason)
        parts.append(text)
    payload = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()
    return identity_index_key_digest_decision("resolved", "", digest)


def key_digest(key: object, report: StorageReport) -> str | None:
    decision = key_digest_decision(key, report)
    return decision.digest if decision.status == "resolved" else None


def index_path_for_key_decision(key: object, report: StorageReport) -> IdentityIndexPathDecision:
    queue_dir_decision = queue_dir_from_key_decision(key, report)
    digest_decision = key_digest_decision(key, report)
    if queue_dir_decision.status != "resolved":
        return identity_index_path_decision("rejected", queue_dir_decision.reason)
    if digest_decision.status != "resolved":
        return identity_index_path_decision("rejected", digest_decision.reason)
    if queue_dir_decision.path is None:
        return identity_index_path_decision("rejected", "identity_index_queue_dir_unavailable")
    path = index_dir(queue_dir_decision.path) / (digest_decision.digest + ".json")
    return identity_index_path_decision("resolved", "", path)


def index_path_for_key(key: object, report: StorageReport) -> Path | None:
    decision = index_path_for_key_decision(key, report)
    return decision.path if decision.status == "resolved" else None


def read_index_decision(path: Path, report: StorageReport) -> IdentityIndexReadDecision:
    if not path.exists():
        return identity_index_read_decision("missing", "identity_index_payload_missing")
    with path.open("r", encoding="utf-8") as fh:
        payload: object = json.load(fh)
    if type(payload) is not dict:
        report("invalid_payload", TypeError("identity index payload is " + no_hook_type_name(payload)))
        return identity_index_read_decision("rejected", "invalid_payload")
    return identity_index_read_decision("loaded", "", dict(payload))


def read_index(path: Path, report: StorageReport) -> dict[str, object] | None:
    decision = read_index_decision(path, report)
    return dict(decision.payload) if decision.status == "loaded" and decision.payload is not None else None


def identity_snapshot_decision(identities: object, report: StorageReport) -> IdentityIndexSnapshotDecision:
    if type(identities) not in {tuple, list, set, frozenset}:
        report("identities_container_rejected", ValueError("queue identity index identities require exact container"))
        return identity_index_snapshot_decision("rejected", "identities_container_rejected")
    out: list[str] = []
    for item in no_hook_sequence_items(identities):
        text, reason = scheduler_text(item, unsupported_reason="queue_identity_index_identity_rejected")
        if reason or text == "":
            failure_reason = reason or "queue_identity_index_identity_missing"
            report("identity_rejected", ValueError(failure_reason))
            return identity_index_snapshot_decision("rejected", failure_reason)
        out.append(text)
    return identity_index_snapshot_decision("accepted", "", tuple(sorted(set(out))))


def identity_snapshot(identities: object, report: StorageReport) -> tuple[str, ...] | None:
    decision = identity_snapshot_decision(identities, report)
    return decision.identities if decision.status == "accepted" else None


def write_index_decision(path: Path, identities: object, report: StorageReport) -> IdentityIndexWriteDecision:
    snapshot = identity_snapshot_decision(identities, report)
    if snapshot.status != "accepted":
        return identity_index_write_decision("rejected", snapshot.reason)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"time": time.time(), "ids": list(snapshot.identities)}
    tmp = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, sort_keys=True, separators=(",", ":"))
        fh.flush()
        flush_open_writable_file(fh.fileno())
    durable_replace_regular_file(tmp, path)
    return identity_index_write_decision("written", "", written=True)


def write_index(path: Path, identities: object, report: StorageReport) -> bool:
    return write_index_decision(path, identities, report).written


def prune_index_dir(path: Path, *, max_entries: int, report: StorageReport | None = None) -> None:
    files: list[Path] = []
    list_failed = False
    try:
        files = sorted(path.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError as exc:
        if report is not None:
            report("prune_scan_failed", exc)
        list_failed = True
    if list_failed:
        return
    unlink_failed = False
    for stale in files[max_entries:]:
        try:
            stale.unlink()
        except OSError as exc:
            if report is not None:
                report("prune_unlink_failed", exc)
            unlink_failed = True
        if unlink_failed:
            return

__all__ = (
    "StorageReport", "identity_snapshot", "identity_snapshot_decision", "index_dir", "index_path_for_key",
    "index_path_for_key_decision", "key_digest", "key_digest_decision", "prune_index_dir",
    "queue_dir_from_key", "queue_dir_from_key_decision", "read_index", "read_index_decision",
    "write_index", "write_index_decision",
)
