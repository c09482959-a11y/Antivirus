"""Scanner-owned immutable image limit policy accessors."""
from __future__ import annotations

from Virus_Scan.runtime.api import deep_scan_auto_enabled, deep_scan_thorough_enabled
from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()

IMAGE_STEGO_MAX_FILE_BYTES = _SCANNER_LIMITS_POLICY.image_stego_max_file_bytes
IMAGE_STEGO_MAX_PIXELS = _SCANNER_LIMITS_POLICY.image_stego_max_pixels
IMAGE_STEGO_SAMPLE_PIXELS = _SCANNER_LIMITS_POLICY.image_stego_sample_pixels
IMAGE_STEGO_RESIZE_SAMPLE_MAX_SIDE = _SCANNER_LIMITS_POLICY.image_stego_resize_sample_max_side


def deep_scan_image_enrichment_limit(*, escalated: bool = False) -> int:
    if deep_scan_thorough_enabled():
        return _SCANNER_LIMITS_POLICY.image_enrichment_thorough_bytes
    if deep_scan_auto_enabled() and escalated:
        return _SCANNER_LIMITS_POLICY.image_enrichment_auto_escalated_bytes
    return _SCANNER_LIMITS_POLICY.image_enrichment_fast_bytes


__all__ = (
    "IMAGE_STEGO_MAX_FILE_BYTES",
    "IMAGE_STEGO_MAX_PIXELS",
    "IMAGE_STEGO_RESIZE_SAMPLE_MAX_SIDE",
    "IMAGE_STEGO_SAMPLE_PIXELS",
    "deep_scan_image_enrichment_limit",
)
