"""Stage 911 Phase 10 continuous binary error-path hardening tests."""
from __future__ import annotations

from Virus_Scan.scanners.binary_pe_bytes import pe_rva_to_offset
from Virus_Scan.scanners.binary_pe_sections import parse_pe_import_names
from Virus_Scan.scanners.binary_raw_escalation import _umige_raw_should_escalate_after_triage_inmemory
from Virus_Scan.scanners.binary_text_signals import binary_ascii_visibility_ratio
from Virus_Scan.scanners.binary_strict_fast import _strict_fast_file_is_boring_text


class _BadBoolBuffer:
    def __bool__(self):
        raise ValueError("visibility buffer bool failed")


class _BadTag:
    def __str__(self):
        raise ValueError("tag normalization failed")


class _BadPath:
    def __str__(self):
        raise ValueError("path normalization failed")


class _BadSection:
    def get(self, key, default=None):
        raise ValueError("section mapping failed")


def test_binary_text_signal_recoverable_error_is_not_hidden_as_sentinel() -> None:
    try:
        binary_ascii_visibility_ratio(_BadBoolBuffer())
    except ValueError as exc:
        assert "visibility buffer bool failed" in str(exc)
    else:
        raise AssertionError("binary ASCII visibility helper failure was hidden")


def test_binary_raw_escalation_tag_parse_failure_does_not_fail_closed() -> None:
    assert _umige_raw_should_escalate_after_triage_inmemory(
        "sample.bin",
        [_BadTag()],
        False,
        {},
        "fast",
    ) is True


def test_binary_raw_escalation_extension_failure_does_not_fail_closed() -> None:
    assert _umige_raw_should_escalate_after_triage_inmemory(
        _BadPath(),
        [],
        False,
        {},
        "fast",
    ) is True


def test_pe_rva_mapping_error_flows_to_import_parser_evidence() -> None:
    data = bytearray(320)
    data[:2] = b"MZ"
    data[60:64] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0xF8 + 8:0xF8 + 12] = (0x1000).to_bytes(4, "little")
    result = parse_pe_import_names(bytes(data), (_BadSection(),))
    assert result.error_tags
    assert any("pe_import_parse" in tag for tag in result.error_tags)


def test_pe_rva_mapping_unmapped_valid_sections_stays_plain_unmapped() -> None:
    assert pe_rva_to_offset(0x1000, ({"virtual_address": 0x2000, "virtual_size": 0x100, "raw_size": 0x100, "raw_ptr": 0x40},)) is None


def test_strict_fast_stat_failure_remains_evidence_driven_rejection(tmp_path) -> None:
    missing = tmp_path / "missing.txt"
    ok, metadata = _strict_fast_file_is_boring_text(missing)
    assert ok is False
    assert metadata["binary_strict_fast_failure"] == "stat"
    assert metadata["scanner_failure_evidence_recorded"] is True
