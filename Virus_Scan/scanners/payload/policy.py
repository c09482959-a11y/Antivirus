"""Immutable payload decoder policy constants loaded through scanner config."""
from __future__ import annotations

from Virus_Scan.scanners.config.loader import load_payload_policy_snapshot

_PAYLOAD_POLICY = load_payload_policy_snapshot()
DECODE_LAYER_MAX_CANDIDATES = _PAYLOAD_POLICY.max_candidates
DECODE_LAYER_MAX_TEXT_BYTES = _PAYLOAD_POLICY.max_text_bytes
DECODE_LAYER_MIN_B64_CHARS = _PAYLOAD_POLICY.min_base64_chars
DECODE_LAYER_MIN_HEX_CHARS = _PAYLOAD_POLICY.min_hex_chars

__all__ = (
    "DECODE_LAYER_MAX_CANDIDATES",
    "DECODE_LAYER_MAX_TEXT_BYTES",
    "DECODE_LAYER_MIN_B64_CHARS",
    "DECODE_LAYER_MIN_HEX_CHARS",
    "_PAYLOAD_POLICY",
)
