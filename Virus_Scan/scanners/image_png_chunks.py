"""Scanner-owned PNG metadata/chunk anomaly scanning."""
from __future__ import annotations

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join, scanner_failure_evidence_tags

from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot

PLR2004N4 = 4
PLR2004N8192 = 8192

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
_SUSPICIOUS_PNG_TEXT_NEEDLES = tuple(
    item.encode("latin1", errors="ignore")
    for item in _SCANNER_LIMITS_POLICY.image_suspicious_png_text_needles
)


def scan_png_chunks(data: object, tags: object) -> bool:
    """Conservative PNG ancillary/chunk anomaly checks with explicit evidence."""
    suspicious = False
    try:
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return False
        pos = 8
        seen_iend = False
        unusual_private = 0
        text_payload = b""
        while pos + 12 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "big")
            ctype = data[pos + 4:pos + 8]
            if length < 0 or length > 64 * 1024 * 1024:
                tags += ["png_invalid_chunk_length", "stego_statistical_anomaly"]
                return True
            chunk_start = pos + 8
            chunk_end = chunk_start + length
            crc_end = chunk_end + 4
            if crc_end > len(data):
                tags += ["png_truncated_or_malformed_chunk", "stego_statistical_anomaly"]
                return True
            name = ctype.decode("latin1", errors="ignore")
            if len(name) == PLR2004N4 and name[1:2].islower():
                unusual_private += 1
            if ctype in {b"tEXt", b"zTXt", b"iTXt"}:
                text_payload += data[chunk_start:min(chunk_end, chunk_start + 8192)]
                if length >= PLR2004N8192:
                    tags += ["large_png_text_chunk", "stego_statistical_anomaly"]
                    suspicious = True
            if ctype == b"IEND":
                seen_iend = True
                break
            pos = crc_end
        if unusual_private >= 2:
            tags += ["png_private_chunks", "stego_statistical_anomaly"]
            suspicious = True
        low = text_payload.lower()
        if any(needle in low for needle in _SUSPICIOUS_PNG_TEXT_NEEDLES):
            tags += ["suspicious_png_text_payload", "embedded_command_or_url"]
            suspicious = True
        if not seen_iend:
            tags += ["png_missing_iend", "stego_statistical_anomaly"]
            suspicious = True
    except SCAN_CONTENT_ERRORS as exc:
        log_error(scanner_contract_join("PNG chunk stego scan failed: ", scanner_contract_error_message(exc)))
        tags.extend(scanner_failure_evidence_tags(
            "image",
            "png_chunk_scan",
            exc,
            ["image_metadata_parse_failed", "malformed_image_input"],
            state="malformed",
            error_category="malformed_image",
        ))
        suspicious = True
    return suspicious


__all__ = ("scan_png_chunks",)
