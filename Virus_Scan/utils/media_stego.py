"""Canonical low-level media/stego policy helpers."""
from __future__ import annotations

from types import MappingProxyType


from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value

JPEG_LSB_WEAK_TAGS = frozenset({
    "possible_lsb_stego",
    "lsb_randomness_anomaly",
    "strong_lsb_balance_anomaly",
    "image_stego_lsb_anomaly",
})
CONFIRMED_IMAGE_PAYLOAD_TAGS = frozenset({
    "confirmed_embedded_pe_payload",
    "decoded_pe_payload",
    "embedded_executable_payload",
    "image_payload_confirmed",
    "image_appended_payload",
    "embedded_payload_after_eof",
    "embedded_executable_or_command",
    "high_confidence_image_payload",
    "suspicious_png_text_payload",
    "suspicious_jpeg_metadata_payload",
})
WEAK_IMAGE_STEGO_TAG_REWRITE = MappingProxyType({
    "possible_lsb_stego": "weak_image_stego_observation",
    "lsb_randomness_anomaly": "weak_image_stego_observation",
    "strong_lsb_balance_anomaly": "weak_image_stego_observation",
    "image_stego_lsb_anomaly": "weak_image_stego_observation",
    "possible_stego_payload": "stego_candidate_observation",
    "stego_payload_suspect": "stego_candidate_observation",
    "image_payload_candidate": "stego_candidate_observation",
    "jpeg_metadata_url_reference": "image_metadata_url_reference",
    "url_in_image": "image_metadata_url_reference",
    "jpeg_metadata_encoded_reference": "image_metadata_encoded_reference",
})


def image_is_jpeg(data: bytes | None = None, path: object = None) -> bool:
    is_jpeg = False
    try:
        if data is not None:
            if type(data) is bytes:
                is_jpeg = bytes.__getitem__(data, slice(0, 3)) == bytes((0xFF, 0xD8, 0xFF))
            return is_jpeg
        path_text = text_boundary_value(path, unsupported="")
        if type(path_text) is str and path_text:
            with open(path_text, "rb") as fh:
                is_jpeg = fh.read(3) == bytes((0xFF, 0xD8, 0xFF))
    except IO_CONFIGURATION_ERRORS:
        is_jpeg = False
    return is_jpeg


def bits_to_bytes(bits: object, max_bytes: int = 262144) -> bytes:
    out = bytearray()
    cur = 0
    count = 0
    for bit in no_hook_sequence_items(bits):
        bit_value = 1 if type(bit) is bool and bit else 0
        if type(bit) is int and type(bit) is not bool and bit != 0:
            bit_value = 1
        cur = (cur << 1) | bit_value
        count += 1
        if count == 8:
            out.append(cur & 0xFF)
            if len(out) >= max_bytes:
                break
            cur = 0
            count = 0
    return bytes(out)


def canonical_stego_tag_rewrite_map() -> dict[str, str]:
    """Return a copy of the scanner-owned stego rewrite policy."""
    return dict(WEAK_IMAGE_STEGO_TAG_REWRITE)
