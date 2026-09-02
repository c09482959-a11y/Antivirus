from __future__ import annotations

from Virus_Scan.scanners.image_malformed import fast_image_sample_malformed_status
from Virus_Scan.scanners.text import _looks_like_base64_payload, _looks_like_base64_payload_status


class _BadBytes:
    def __bool__(self):
        return True

    def __bytes__(self):
        raise ValueError("bad bytes")


class _BadText:
    def __bool__(self):
        return True

    def __str__(self):
        raise ValueError("bad text")


def test_fast_image_magic_probe_failure_is_status_not_malformed_fail_open():
    assert fast_image_sample_malformed_status("asset.png", _BadBytes()) == "probe_error"


def test_fast_image_magic_mismatch_still_detects_real_malformed_sample():
    assert fast_image_sample_malformed_status("asset.png", b"not-png") == "malformed"


def test_text_base64_probe_failure_is_status_not_payload_fail_open():
    assert _looks_like_base64_payload_status(_BadText()) == "probe_error"
    assert _looks_like_base64_payload(_BadText()) is False
