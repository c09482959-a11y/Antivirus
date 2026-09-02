import os
import zipfile
from pathlib import Path

from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget, annotate_timeout_result


def test_tiny_image_budget_is_bounded_and_explicit(tmp_path):
    image = tmp_path / "tiny.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
    budget = compute_timeout_budget(image, configured_timeout_seconds=20)
    assert budget.workload_class == "image_fast_triage"
    assert budget.hard_timeout_seconds >= 60
    assert budget.hard_timeout_seconds < 300
    evidence = budget.as_evidence()
    assert evidence["timeout_budget"] == budget.hard_timeout_seconds
    assert evidence["file_size"] == image.stat().st_size


def test_archive_budget_scales_with_members_and_expansion(tmp_path):
    small = tmp_path / "small.zip"
    large = tmp_path / "large.zip"
    with zipfile.ZipFile(small, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"a" * 1024)
    with zipfile.ZipFile(large, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(25):
            zf.writestr(f"member_{i}.bin", b"b" * 65536)
    small_budget = compute_timeout_budget(small, configured_timeout_seconds=20)
    large_budget = compute_timeout_budget(large, configured_timeout_seconds=20)
    assert small_budget.workload_class == "archive"
    assert large_budget.workload_class == "archive"
    assert large_budget.archive_member_count == 25
    assert large_budget.estimated_uncompressed_size > small_budget.estimated_uncompressed_size
    assert large_budget.hard_timeout_seconds > small_budget.hard_timeout_seconds
    assert large_budget.hard_timeout_seconds >= 900


def test_deep_scan_multiplier_is_permissive(tmp_path):
    target = tmp_path / "payload.bin"
    target.write_bytes(os.urandom(1024 * 64))
    normal = compute_timeout_budget(target, configured_timeout_seconds=20, method="generic_scan")
    deep = compute_timeout_budget(target, configured_timeout_seconds=20, method="deep_scan", deep_scan=True)
    assert deep.hard_timeout_seconds > normal.hard_timeout_seconds
    assert deep.stall_timeout_seconds > normal.stall_timeout_seconds


def test_timeout_annotation_records_worker_state(tmp_path):
    target = tmp_path / "x.dll"
    target.write_bytes(b"MZ" + b"0" * 1024)
    budget = compute_timeout_budget(target, configured_timeout_seconds=20, method="dotnet_decompile")
    result = annotate_timeout_result({"file": str(target), "scan_integrity": {}}, budget, worker_state="queue_worker_hard_timeout", reason="unit_test", elapsed_seconds=budget.hard_timeout_seconds + 1)
    assert result["timeout_evidence"]["worker_state"] == "queue_worker_hard_timeout"
    assert result["timeout_evidence"]["timeout_reason"] == "unit_test"
    assert result["scan_integrity"]["allow_learning"] is False


def test_image_budget_uses_static_png_dimensions_without_decode(tmp_path):
    target = tmp_path / "large_canvas.png"
    # PNG signature + IHDR length/type + width/height + minimal padding; the
    # timeout owner only needs bounded header parsing, not a valid decoded image.
    target.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + (4000).to_bytes(4, "big")
        + (3000).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"0" * 32
    )
    budget = compute_timeout_budget(target, configured_timeout_seconds=20)
    evidence = budget.as_evidence()
    assert evidence["workload_class"] == "image_fast_triage"
    assert evidence["image_pixels"] == 12_000_000
    tiny = tmp_path / "tiny_canvas.png"
    tiny.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + (10).to_bytes(4, "big")
        + (10).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"0" * 32
    )
    assert budget.hard_timeout_seconds > compute_timeout_budget(tiny, configured_timeout_seconds=20).hard_timeout_seconds


def test_tiny_high_compression_archive_budget_is_not_ratio_exploded(tmp_path):
    target = tmp_path / "tiny_high_ratio.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"0" * (1024 * 1024))
    budget = compute_timeout_budget(target, configured_timeout_seconds=20)
    evidence = budget.as_evidence()
    assert budget.workload_class == "archive"
    assert evidence["compression_ratio"] and evidence["compression_ratio"] > 100
    assert evidence["estimated_uncompressed_size"] == 1024 * 1024
    assert budget.hard_timeout_seconds < 1500
    assert budget.hard_timeout_seconds >= 900

def test_malformed_png_header_records_budget_inspection_error(tmp_path):
    target = tmp_path / "malformed_large.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"X" * (1024 * 1024))
    budget = compute_timeout_budget(target, configured_timeout_seconds=20)
    evidence = budget.as_evidence()
    assert budget.workload_class == "image_fast_triage"
    assert evidence["inspection_error"] == "png_missing_ihdr"
    assert evidence["image_pixels"] is None
