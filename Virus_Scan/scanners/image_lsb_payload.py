"""Scanner-owned helpers for confirmed image LSB payload evidence.

This module owns payload-trigger policy lookup, payload magic/needle matching,
and decoded payload evidence tags used by the Pillow LSB extraction path.  The
pixel traversal and image sampling logic remains in ``image_lsb`` so payload
classification cannot grow a second image traversal implementation.
"""
from __future__ import annotations

from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_contract_join, scanner_contract_lower_token
from Virus_Scan.scanners.payload_decode import decoded_payload_behavior_tags, safe_decode_payloads

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
_PAYLOAD_MAGIC_PREFIXES = tuple(
    item.encode("latin1", errors="ignore")
    for item in _SCANNER_LIMITS_POLICY.image_payload_magic_prefixes
)
_PAYLOAD_NEEDLES = tuple(
    item.encode("latin1", errors="ignore")
    for item in _SCANNER_LIMITS_POLICY.image_payload_needles
)
_LSB_TRIGGER_TAGS = tuple(_SCANNER_LIMITS_POLICY.image_lsb_trigger_tags)


def has_lsb_trigger_tags(tags: list[str]) -> bool:
    """Return whether the current image tags allow gated LSB payload extraction."""
    observed = set(tags or [])
    return any(tag in observed for tag in _LSB_TRIGGER_TAGS)


def lsb_payload_magic_or_needle_hit(extracted: bytes) -> bool:
    """Return whether extracted LSB bytes contain configured payload anchors."""
    low = extracted[:8192].lower()
    return extracted.startswith(_PAYLOAD_MAGIC_PREFIXES) or any(needle in low for needle in _PAYLOAD_NEEDLES)


def decoded_lsb_payload_behavior_tags(extracted: bytes) -> list[str]:
    """Return scanner-owned decoded-payload evidence tags for extracted LSB bytes."""
    if type(extracted) is not bytes:
        return []
    text = extracted.decode("latin1", errors="ignore")
    decoded_tags: list[str] = []
    for rec in safe_decode_payloads(text):
        decoded_tags.extend(decoded_payload_behavior_tags(rec, []))
        binary_magic = rec.get("binary_magic") if type(rec) is dict else None
        binary_magic_token = scanner_contract_lower_token(binary_magic, replacement="")
        if binary_magic_token:
            decoded_tags.extend([
                "payload_decode_candidate",
                "decoded_binary_payload",
                scanner_contract_join("decoded_", binary_magic_token, "_payload"),
            ])
    return decoded_tags


def append_confirmed_lsb_payload_tags(tags: list[str]) -> None:
    """Append evidence tags for raw LSB payload confirmation."""
    tags.extend([
        "image_payload_confirmed",
        "image_lsb_payload_extracted",
        "stego_payload_extracted",
        "evidence_link:stego_payload_to_content",
    ])


def append_decoded_lsb_payload_tags(tags: list[str], decoded_tags: list[str]) -> None:
    """Append evidence tags for decoded LSB payload behavior."""
    tags.extend([
        "image_payload_confirmed",
        "image_lsb_payload_extracted",
        "decoded_stego_payload",
        "evidence_link:stego_payload_to_decoded_payload",
    ])
    tags.extend(decoded_tags)


__all__ = (
    "append_confirmed_lsb_payload_tags",
    "append_decoded_lsb_payload_tags",
    "decoded_lsb_payload_behavior_tags",
    "has_lsb_trigger_tags",
    "lsb_payload_magic_or_needle_hit",
)
