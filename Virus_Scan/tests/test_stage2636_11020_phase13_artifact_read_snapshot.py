from __future__ import annotations

import inspect
from pathlib import Path
from unittest.mock import patch

from Virus_Scan.contracts.artifact_read_snapshot import (
    ARTIFACT_FAST_FINGERPRINT_SAMPLE,
    ArtifactReadLedger,
    build_artifact_read_snapshot,
    read_artifact_prefix,
)
from Virus_Scan.routing.magic import sniff_file_identity
import Virus_Scan.routing.magic as magic
import Virus_Scan.utils.pathing as pathing
from Virus_Scan.runtime.engine_hint_runtime import detect_startup_engine_context
from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget
from Virus_Scan.scheduler.timeout.timeout_workload_inspection import image_pixel_count


def _png(width: int = 2, height: int = 3) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"X" * 64
    )


def _jpeg(width: int = 17, height: int = 19) -> bytes:
    # SOI + baseline SOF0 segment.  Timeout inspection needs only bounded
    # physical header bytes and must not perform a second artifact open.
    sof = (
        b"\xff\xc0"
        + (17).to_bytes(2, "big")
        + b"\x08"
        + height.to_bytes(2, "big")
        + width.to_bytes(2, "big")
        + b"\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00"
    )
    return b"\xff\xd8" + sof + b"\xff\xd9"


def test_phase13_snapshot_publishes_one_exact_physical_read_ledger(tmp_path: Path) -> None:
    target = tmp_path / "ledger.bin"
    payload = b"phase13-ledger" * 100
    target.write_bytes(payload)

    snapshot = build_artifact_read_snapshot(target)
    ledger = snapshot.read_ledger

    assert type(ledger) is ArtifactReadLedger
    assert ledger.physical_open_count == 1
    assert ledger.stream_bytes_read == len(payload)
    assert ledger.verification_bytes_read == len(payload)
    assert ledger.total_physical_bytes_read == len(payload) * 2
    assert ledger.retained_prefix_bytes == len(payload)
    assert ledger.retained_tail_bytes == 0
    assert snapshot.to_record()["read_ledger"] == ledger.to_record()
    assert "bytes_read" not in snapshot.to_record()


def test_phase13_large_snapshot_verification_is_bounded(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    payload = b"A" * (ARTIFACT_FAST_FINGERPRINT_SAMPLE * 3)
    target.write_bytes(payload)
    snapshot = build_artifact_read_snapshot(target)

    assert snapshot.complete is True
    assert snapshot.read_ledger.physical_open_count == 1
    assert snapshot.read_ledger.stream_bytes_read == len(payload)
    assert snapshot.read_ledger.verification_bytes_read == ARTIFACT_FAST_FINGERPRINT_SAMPLE * 2


def test_phase13_presession_prefix_owner_reads_only_requested_prefix(tmp_path: Path) -> None:
    target = tmp_path / "prefix.bin"
    target.write_bytes(b"A" * (4 * 1024 * 1024))
    assert read_artifact_prefix(target, 32) == b"A" * 32


def test_phase13_startup_engine_hint_no_longer_uses_path_read_bytes(tmp_path: Path) -> None:
    target = tmp_path / "opaque.bin"
    target.write_bytes(_png())
    with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read forbidden")):
        context = detect_startup_engine_context(tmp_path)
    assert context["media"] > 0.0


def test_phase13_standalone_magic_uses_canonical_bounded_prefix_owner(tmp_path: Path) -> None:
    target = tmp_path / "sample.png"
    target.write_bytes(_png())
    with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read forbidden")):
        identity = sniff_file_identity(target)
    assert identity["magic_type"] == "png"


def test_phase13_timeout_budget_reuses_snapshot_size_and_image_header(tmp_path: Path) -> None:
    target = tmp_path / "image.png"
    target.write_bytes(_png(11, 13))
    snapshot = build_artifact_read_snapshot(target)

    with patch("os.path.getsize", side_effect=AssertionError("size reprobe forbidden")), patch(
        "builtins.open", side_effect=AssertionError("image header reopen forbidden")
    ):
        budget = compute_timeout_budget(
            target,
            configured_timeout_seconds=20,
            artifact_read_snapshot=snapshot,
        )
        pixels, error = image_pixel_count(target, artifact_read_snapshot=snapshot)

    assert budget.file_size == snapshot.size
    assert budget.image_pixels == 143
    assert pixels == 143
    assert error is None


def test_phase13_jpeg_timeout_reuses_snapshot_without_hidden_reopen(tmp_path: Path) -> None:
    target = tmp_path / "image.jpg"
    target.write_bytes(_jpeg(23, 29))
    snapshot = build_artifact_read_snapshot(target)

    with patch("builtins.open", side_effect=AssertionError("jpeg header reopen forbidden")):
        pixels, error = image_pixel_count(target, artifact_read_snapshot=snapshot)

    assert pixels == 667
    assert error is None


def test_phase13_active_read_owner_has_no_superseded_header_helper() -> None:
    assert not hasattr(pathing, "read_file_header")
    source = inspect.getsource(magic.sniff_file_identity)
    assert "read_artifact_prefix" in source
    assert "read_file_header" not in source
