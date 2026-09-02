"""Scanner-owned image/stego tag normalization."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.image_bits import image_is_jpeg

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
_CONFIRMED_IMAGE_PAYLOAD_TAGS = frozenset(_SCANNER_LIMITS_POLICY.image_confirmed_tags)
_JPEG_LSB_WEAK_TAGS = frozenset(_SCANNER_LIMITS_POLICY.image_jpeg_lsb_weak_tags)
_WEAK_IMAGE_STEGO_TAG_REWRITE = MappingProxyType(dict(_SCANNER_LIMITS_POLICY.image_stego_tag_rewrite_map))

_WEAK_UNCONFIRMED_PAYLOAD_TAGS = frozenset({
    "possible_stego_payload",
    "image_payload_confirmed",
    "image_appended_payload",
    "embedded_payload_after_eof",
    "high_confidence_image_payload",
})


def stego_tag_rewrite_map() -> dict[str, str]:
    """Return a copy of the scanner-owned image/stego rewrite policy."""
    return dict(_WEAK_IMAGE_STEGO_TAG_REWRITE)


def confirmed_image_payload_tags() -> frozenset[str]:
    """Return scanner-owned confirmed image payload tags."""
    return frozenset(_CONFIRMED_IMAGE_PAYLOAD_TAGS)


def rewrite_stego_tags(tags: object, data: object = None, path: object = None, *, extracted_payload: bool = False) -> list[str]:
    """Normalize image/stego tags into weak observations vs confirmed payloads."""
    out: list[str] = []
    seen: set[str] = set()
    input_tags = [str(t).strip().lower() for t in tags or [] if str(t).strip()]
    jpeg = image_is_jpeg(data=data, path=path, read_path=False)
    confirmed = bool(extracted_payload) or bool(set(input_tags) & _CONFIRMED_IMAGE_PAYLOAD_TAGS)
    for raw_low in input_tags:
        low = raw_low
        if jpeg and low in _JPEG_LSB_WEAK_TAGS:
            low = "jpeg_lsb_check_suppressed"
        else:
            low = _WEAK_IMAGE_STEGO_TAG_REWRITE.get(low, low)
        if low in _WEAK_UNCONFIRMED_PAYLOAD_TAGS and not confirmed:
            low = "stego_candidate_observation"
        if low == "network_activity" and jpeg:
            low = "image_metadata_url_reference"
        if low not in seen:
            seen.add(low)
            out.append(low)
    return out


__all__ = ("confirmed_image_payload_tags", "rewrite_stego_tags", "stego_tag_rewrite_map")
