"""Stage 919 Phase 10 embedded PE malformed-header visibility tests."""
from __future__ import annotations

from Virus_Scan.scanners.binary_embedded_payloads import validated_embedded_payload_hits


def _sample_with_mz_at(offset: int = 64, total: int = 256) -> bytearray:
    sample = bytearray(b"A" * total)
    sample[offset:offset + 2] = b"MZ"
    return sample


def test_embedded_pe_valid_signature_is_preserved() -> None:
    sample = _sample_with_mz_at(total=256)
    sample[64 + 60:64 + 64] = (80).to_bytes(4, "little")
    sample[64 + 80:64 + 84] = b"PE\x00\x00"

    assert validated_embedded_payload_hits(bytes(sample), min_offset=32) == [(64, "embedded_pe_signature")]


def test_embedded_pe_truncated_signature_offset_is_visible() -> None:
    sample = _sample_with_mz_at(total=128)
    sample[64 + 60:64 + 64] = (80).to_bytes(4, "little")

    assert validated_embedded_payload_hits(bytes(sample), min_offset=32) == [(64, "embedded_pe_header_truncated")]


def test_embedded_pe_missing_signature_is_visible_without_false_valid_hit() -> None:
    sample = _sample_with_mz_at(total=256)
    sample[64 + 60:64 + 64] = (80).to_bytes(4, "little")
    sample[64 + 80:64 + 84] = b"PX!!"

    assert validated_embedded_payload_hits(bytes(sample), min_offset=32) == [(64, "embedded_pe_signature_missing")]


def test_plain_mz_text_without_plausible_pe_offset_stays_non_hit() -> None:
    sample = bytearray(b"A" * 180)
    sample[64:66] = b"MZ"

    assert validated_embedded_payload_hits(bytes(sample), min_offset=32) == []
