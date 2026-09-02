from __future__ import annotations

import hashlib
import os
from pathlib import Path
import threading
import time

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import (
    ARTIFACT_FAST_FINGERPRINT_SAMPLE,
    ARTIFACT_READ_PREFIX_LIMIT,
    ArtifactReadLedger,
    ArtifactReadSnapshot,
    attach_artifact_read_record,
    build_artifact_read_snapshot,
    require_artifact_read_snapshot,
)


def test_phase9_snapshot_owns_exact_small_artifact_bytes_and_digest(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    payload = b"print('phase9')\n"
    target.write_bytes(payload)

    snapshot = build_artifact_read_snapshot(target)

    assert snapshot.complete is True
    assert snapshot.canonical_path == str(target.resolve())
    assert snapshot.size == len(payload)
    assert snapshot.read_ledger.stream_bytes_read == len(payload)
    assert snapshot.prefix_bytes == payload
    assert snapshot.tail_bytes == b""
    assert snapshot.content_sha256 == hashlib.sha256(payload).hexdigest()
    assert snapshot.extension == ".py"
    assert snapshot.read_prefix(5) == payload[:5]
    assert snapshot.prefix_truncated is False


def test_phase9_snapshot_bounds_prefix_and_owns_exact_tail(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    payload = bytes(range(256)) * ((ARTIFACT_READ_PREFIX_LIMIT // 256) + 1024)
    target.write_bytes(payload)

    snapshot = build_artifact_read_snapshot(target)

    assert snapshot.complete is True
    assert snapshot.prefix_bytes == payload[:ARTIFACT_READ_PREFIX_LIMIT]
    assert snapshot.tail_bytes == payload[-ARTIFACT_FAST_FINGERPRINT_SAMPLE:]
    assert snapshot.prefix_truncated is True
    assert snapshot.content_sha256 == hashlib.sha256(payload).hexdigest()
    fast_key, fast_meta = snapshot.fast_fingerprint()
    assert len(fast_key) == 64
    assert fast_meta == {
        "extension": ".bin",
        "mtime_ns": snapshot.mtime_ns,
        "size": len(payload),
    }


def test_phase9_snapshot_record_never_publishes_raw_bytes(tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    payload = b"raw bytes must not be published"
    target.write_bytes(payload)
    snapshot = build_artifact_read_snapshot(target)

    record = snapshot.to_record()
    attached: dict[str, object] = {}
    attach_artifact_read_record(attached, snapshot)

    assert "prefix_bytes" not in record
    assert "tail_bytes" not in record
    assert payload not in tuple(record.values())
    assert attached["source_sha256"] == hashlib.sha256(payload).hexdigest()
    assert attached["artifact_read"] == record


def test_phase9_snapshot_missing_and_nonregular_artifacts_fail_closed(tmp_path: Path) -> None:
    missing = build_artifact_read_snapshot(tmp_path / "missing.bin")
    directory = build_artifact_read_snapshot(tmp_path)

    assert missing.complete is False
    assert missing.state == "unavailable"
    assert missing.unavailable_reason
    assert missing.prefix_bytes == b""
    assert missing.content_sha256 == ""
    assert directory.complete is False
    assert directory.unavailable_reason == "artifact_not_regular_file"


def test_phase9_snapshot_path_identity_is_mandatory(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    snapshot = build_artifact_read_snapshot(first)

    assert require_artifact_read_snapshot(snapshot, first) is snapshot
    with pytest.raises(ValueError, match="artifact_read_snapshot_path_mismatch"):
        require_artifact_read_snapshot(snapshot, second)
    with pytest.raises(TypeError, match="artifact_read_snapshot_required"):
        require_artifact_read_snapshot(object(), first)


def test_phase9_snapshot_constructor_rejects_inconsistent_complete_state() -> None:
    with pytest.raises(ValueError, match="artifact_read_complete_contract_invalid"):
        ArtifactReadSnapshot(
            canonical_path="/tmp/x",
            size=3,
            mtime_ns=1,
            inode=1,
            device=1,
            extension=".bin",
            prefix_bytes=b"ab",
            tail_bytes=b"",
            content_sha256="a" * 64,
            read_ledger=ArtifactReadLedger(
                physical_open_count=1,
                stream_bytes_read=3,
                verification_bytes_read=0,
                total_physical_bytes_read=3,
                retained_prefix_bytes=2,
                retained_tail_bytes=0,
            ),
            state="complete",
        )


def test_phase9_snapshot_detects_concurrent_in_place_mutation(tmp_path: Path) -> None:
    target = tmp_path / "mutating.bin"
    target.write_bytes(b"A" * (32 * 1024 * 1024))
    started = threading.Event()
    stop = threading.Event()

    def mutate() -> None:
        with target.open("r+b", buffering=0) as handle:
            started.set()
            value = 0
            while not stop.is_set():
                handle.seek(0)
                handle.write(bytes((value,)))
                handle.flush()
                os.fsync(handle.fileno())
                value = (value + 1) % 256

    worker = threading.Thread(target=mutate, daemon=True)
    worker.start()
    assert started.wait(timeout=2.0)
    time.sleep(0.01)
    try:
        snapshot = build_artifact_read_snapshot(target)
    finally:
        stop.set()
        worker.join(timeout=2.0)

    assert snapshot.complete is False
    assert snapshot.state == "mutated"
    assert snapshot.unavailable_reason == "artifact_changed_during_read"
    assert snapshot.content_sha256 == ""
    assert snapshot.prefix_bytes == b""
