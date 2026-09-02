"""Canonical scanner payload decoding public API.

Implementation lives in bounded scanner-owned payload modules. This module is
the stable scanner API surface imported by scanner domains, detection evidence,
and public contracts; it contains no duplicate decoder implementation.
"""
from __future__ import annotations

from Virus_Scan.scanners.payload.chain import expand_payload_decoder_chain
from Virus_Scan.scanners.payload.behavior import decoded_payload_behavior_tags
from Virus_Scan.scanners.payload.decode import safe_decode_payloads
from Virus_Scan.scanners.payload.tags import decoded_payload_tags
from Virus_Scan.scanners.payload.policy import (
    DECODE_LAYER_MAX_CANDIDATES,
    DECODE_LAYER_MAX_TEXT_BYTES,
    DECODE_LAYER_MIN_B64_CHARS,
    DECODE_LAYER_MIN_HEX_CHARS,
)
from Virus_Scan.scanners.payload.records import decoded_payload_records_from_bytes, embedded_payload_records_from_bytes

__all__ = (
    "DECODE_LAYER_MAX_CANDIDATES",
    "DECODE_LAYER_MAX_TEXT_BYTES",
    "DECODE_LAYER_MIN_B64_CHARS",
    "DECODE_LAYER_MIN_HEX_CHARS",
    "decoded_payload_behavior_tags",
    "decoded_payload_records_from_bytes",
    "decoded_payload_tags",
    "embedded_payload_records_from_bytes",
    "expand_payload_decoder_chain",
    "safe_decode_payloads",
)
