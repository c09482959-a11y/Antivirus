import pytest

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.runtime.scanner_governance import (
    ScannerContext,
    ScannerContractViolation,
    run_analyzer,
    run_collector,
    scanner_failure_tags,
)
from Virus_Scan.scanners import rpgm, unity, renpy, image, binary
from Virus_Scan.scanners import image_scan


def test_collector_degrades_hostile_io_without_false_clean():
    ctx = ScannerContext(path="x")
    def bad_read():
        raise OSError("permission denied")
    result = run_collector(ctx, "unit.read", bad_read, default=b"")
    assert result == b""
    assert "failure_parse_unit.read" in ctx.tags


def test_analyzer_degraded_result_has_failure_tags():
    ctx = ScannerContext(path="x")
    def malformed_payload():
        raise EOFError("truncated")
    result = run_analyzer(ctx, "unit.analyze", malformed_payload)
    assert result["degraded"] is True
    assert "scanner_failure" in result["tags"]
    assert "scan_incomplete" in result["tags"]


def test_programmer_error_is_not_suppressed_by_contract():
    ctx = ScannerContext(path="x")
    def broken_interface():
        raise TypeError("wrong scanner signature")
    with pytest.raises(ScannerContractViolation):
        run_collector(ctx, "unit.contract", broken_interface)


def test_scanner_failure_tags_preserve_engine_base_tag():
    tags = scanner_failure_tags("unit.scan", OSError("locked"), ["unity"])
    assert "unity" in tags
    assert "scanner_failure" in tags
    assert "scanner_degraded" in tags
    assert "scan_incomplete" in tags
    assert any(t.startswith("failure_scanner_unit.scan") for t in tags)


@pytest.mark.parametrize("module, func_name, base", [
    (rpgm, "scan_rpgm_file", "rpgm"),
    (unity, "scan_unity_file", "unity"),
    (renpy, "scan_renpy_file", "renpy"),
])
def test_engine_scanners_unreadable_input_returns_structured_failure(module, func_name, base):
    def locked_reader(*_args, **_kwargs):
        raise OSError("locked")

    tags = getattr(module, func_name)("locked.asset", read_bytes=locked_reader)
    assert base in tags
    assert "scanner_failure" in tags
    assert "scan_incomplete" in tags


def test_image_scanner_unreadable_input_is_suspicious_degraded():
    path = "locked.png"
    tags, suspicious = image.scan_image_file(
        path,
        artifact_read_snapshot=artifact_read_snapshot_fixture(path),
        deep_scan_fast_assets_reader=lambda: False,
    )
    assert suspicious is True
    assert "image" in tags
    assert "scanner_failure" in tags
    assert "scan_incomplete" in tags


def test_pe_scanner_unreadable_input_not_empty_false_clean(tmp_path):
    missing = tmp_path / "locked.exe"
    tags, meta = binary.scan_pure_python_pe_file(str(missing))
    assert meta["is_pe"] is False
    assert "scanner_failure" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:binary:scan_pure_python_pe_file" in tags
    assert "binary_final_json_must_record" in tags
    assert "pure_pe_scan_error" in tags
