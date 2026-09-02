"""Append-only committed checkpoint journal and bounded recovery projection."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Iterator

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.contracts.checkpoint import JsonSafeCheckpointDelta
from Virus_Scan.publication.json_finalization.checkpoint_journal_append_policy import (
    checkpoint_append_is_idempotent,
)
from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_open_writable_file,
)

_JOURNAL_MAGIC = "UMIGE_PARTIAL_CHECKPOINT_JOURNAL_V2"
_SCHEMA_VERSION = "partial_checkpoint_journal_v2"
_RECORD_KIND = "record"
_COMMIT_KIND = "commit"


def _json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _record_digest(sequence: int, key: str, record: object) -> str:
    payload = {"key": key, "record": record, "sequence": sequence}
    return hashlib.sha256(_json_text(payload).encode("utf-8")).hexdigest()


def _batch_digest(records: tuple[tuple[int, str, str], ...]) -> str:
    return hashlib.sha256(_json_text(records).encode("utf-8")).hexdigest()


def is_checkpoint_journal(path: str | Path) -> bool:
    source = Path(path)
    try:
        with source.open("r", encoding="utf-8") as stream:
            return stream.readline().rstrip("\n") == _JOURNAL_MAGIC
    except TELEMETRY_FAILURE_ERRORS:
        return False



def _journal_tail_is_committed(path: Path) -> bool:
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 65536), os.SEEK_SET)
        lines = stream.read().splitlines()
    if not lines:
        return False
    try:
        entry = json.loads(lines[-1])
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return (
        type(entry) is dict
        and dict.get(entry, "schema_version") == _SCHEMA_VERSION
        and dict.get(entry, "kind") == _COMMIT_KIND
    )


def _truncate_uncommitted_tail(path: Path) -> None:
    with path.open("r+b") as stream:
        if stream.readline().rstrip(b"\n") != _JOURNAL_MAGIC.encode("utf-8"):
            raise ValueError("checkpoint_journal_magic_invalid")
        last_commit_offset = stream.tell()
        while True:
            line = stream.readline()
            if not line:
                break
            try:
                entry = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                break
            if (
                type(entry) is dict
                and dict.get(entry, "schema_version") == _SCHEMA_VERSION
                and dict.get(entry, "kind") == _COMMIT_KIND
            ):
                last_commit_offset = stream.tell()
        stream.truncate(last_commit_offset)
        stream.flush()
        flush_open_writable_file(stream.fileno())


def _write_delta_records(stream: object, delta: JsonSafeCheckpointDelta) -> tuple[tuple[int, str, str], ...]:
    digests: list[tuple[int, str, str]] = []
    sequence = delta.first_sequence
    for key, record in delta.items:
        digest = _record_digest(sequence, key, record)
        entry = {
            "kind": _RECORD_KIND,
            "schema_version": _SCHEMA_VERSION,
            "sequence": sequence,
            "key": key,
            "record": record,
            "record_digest": digest,
        }
        stream.write(_json_text(entry) + "\n")
        digests.append((sequence, key, digest))
        sequence += 1
    return tuple(digests)


def _write_delta_commit(stream: object, delta: JsonSafeCheckpointDelta, digests: tuple[tuple[int, str, str], ...]) -> None:
    commit = {
        "kind": _COMMIT_KIND,
        "schema_version": _SCHEMA_VERSION,
        "first_sequence": delta.first_sequence,
        "last_sequence": delta.total_records,
        "total_records": delta.total_records,
        "batch_digest": _batch_digest(digests),
    }
    stream.write(_json_text(commit) + "\n")



def append_checkpoint_delta(path: str | Path, delta: JsonSafeCheckpointDelta) -> bool:
    """Append one record batch followed by a durable commit boundary."""
    if type(delta) is not JsonSafeCheckpointDelta:
        raise TypeError("checkpoint_delta_required")
    if not delta.items:
        return True
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    exists = target.exists()
    if exists and not is_checkpoint_journal(target):
        raise RuntimeError("checkpoint_journal_format_conflict:" + str(target))
    if exists and not _journal_tail_is_committed(target):
        _truncate_uncommitted_tail(target)
    if exists and checkpoint_append_is_idempotent(
        load_checkpoint_journal(target), delta,
    ):
        return True
    with target.open("a" if exists else "w", encoding="utf-8", newline="\n") as stream:
        if not exists:
            stream.write(_JOURNAL_MAGIC + "\n")
        digests = _write_delta_records(stream, delta)
        _write_delta_commit(stream, delta, digests)
        stream.flush()
        flush_open_writable_file(stream.fileno())
    return True


def _entry_from_line(line: str, *, final_line: bool) -> dict[str, object] | None:
    if not line.endswith("\n"):
        if final_line:
            return None
        raise ValueError("checkpoint_journal_truncated_line")
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        if final_line:
            return None
        raise ValueError("checkpoint_journal_json_invalid") from None
    if type(entry) is not dict or dict.get(entry, "schema_version") != _SCHEMA_VERSION:
        raise ValueError("checkpoint_journal_entry_invalid")
    return entry



def _validated_record_entry(
    entry: dict[str, object],
    expected_sequence: int,
    seen: set[str],
) -> tuple[int, str, object, str]:
    sequence = dict.get(entry, "sequence")
    key = dict.get(entry, "key")
    record = dict.get(entry, "record")
    if sequence != expected_sequence or type(key) is not str or key in seen:
        raise ValueError("checkpoint_journal_sequence_or_identity_invalid")
    digest = dict.get(entry, "record_digest")
    if type(digest) is not str or digest != _record_digest(sequence, key, record):
        raise ValueError("checkpoint_journal_digest_mismatch")
    return sequence, key, record, digest


def _validate_commit_entry(
    entry: dict[str, object],
    pending: list[tuple[int, str, object, str]],
) -> None:
    if dict.get(entry, "kind") != _COMMIT_KIND or not pending:
        raise ValueError("checkpoint_journal_commit_invalid")
    first = pending[0][0]
    last = pending[-1][0]
    digest_rows = tuple((sequence, key, digest) for sequence, key, _record, digest in pending)
    if (
        dict.get(entry, "first_sequence") != first
        or dict.get(entry, "last_sequence") != last
        or dict.get(entry, "total_records") != last
        or dict.get(entry, "batch_digest") != _batch_digest(digest_rows)
    ):
        raise ValueError("checkpoint_journal_commit_mismatch")

def _validated_entries(path: Path) -> Iterator[tuple[str, object]]:
    with path.open("r", encoding="utf-8") as stream:
        if stream.readline().rstrip("\n") != _JOURNAL_MAGIC:
            raise ValueError("checkpoint_journal_magic_invalid")
        expected_sequence = 1
        seen: set[str] = set()
        pending: list[tuple[int, str, object, str]] = []
        line = stream.readline()
        while line:
            following = stream.readline()
            entry = _entry_from_line(line, final_line=following == "")
            if entry is None:
                break
            if dict.get(entry, "kind") == _RECORD_KIND:
                pending.append(_validated_record_entry(entry, expected_sequence, seen))
                expected_sequence += 1
                line = following
                continue
            _validate_commit_entry(entry, pending)
            for _sequence, key, record, _digest in pending:
                seen.add(key)
                yield key, record
            pending.clear()
            line = following
    # A final uncommitted batch is intentionally ignored after abrupt termination.


def load_checkpoint_journal(path: str | Path) -> dict[str, object]:
    recovered: dict[str, object] = {}
    for key, record in _validated_entries(Path(path)):
        recovered[key] = record
    return recovered


def materialize_checkpoint_journal(journal_path: str | Path, output_path: str | Path) -> int:
    """Project committed journal batches into one durable JSON object."""
    journal = Path(journal_path)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=output.name + ".",
        suffix=".tmp",
        dir=str(output.parent),
        text=True,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    count = 0
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            stream.write("{")
            first = True
            for key, record in _validated_entries(journal):
                if not first:
                    stream.write(",")
                first = False
                stream.write(_json_text(key))
                stream.write(":")
                stream.write(_json_text(record))
                count += 1
            stream.write("}")
            stream.flush()
            flush_open_writable_file(stream.fileno())
        durable_replace_regular_file(temporary, output)
        return count
    except TELEMETRY_FAILURE_ERRORS:
        temporary.unlink(missing_ok=True)
        raise


__all__ = (
    "append_checkpoint_delta",
    "is_checkpoint_journal",
    "load_checkpoint_journal",
    "materialize_checkpoint_journal",
)
