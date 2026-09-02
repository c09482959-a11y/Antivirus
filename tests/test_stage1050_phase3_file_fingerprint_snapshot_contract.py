"""Phase 3 immutable fingerprint contract regression tests."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from Virus_Scan.contracts.file_fingerprint import (
    FileFingerprintSnapshot,
    source_fingerprint,
    source_fingerprint_snapshot,
)


def test_source_fingerprint_snapshot_is_immutable_and_materializes_legacy_shape(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    snapshot = source_fingerprint_snapshot(sample)
    assert isinstance(snapshot, FileFingerprintSnapshot)
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.sha256 = "changed"  # type: ignore[misc]

    assert source_fingerprint(sample) == snapshot.as_dict()
    assert tuple(snapshot.as_dict()) == ("path", "size", "mtime", "sha256")


def test_missing_source_fingerprint_snapshot_fails_closed_without_mutable_defaults(tmp_path: Path):
    missing = tmp_path / "missing.bin"
    snapshot = source_fingerprint_snapshot(missing)
    assert snapshot.as_dict() == {
        "path": str(missing.resolve()),
        "size": 0,
        "mtime": 0,
        "sha256": "",
    }
