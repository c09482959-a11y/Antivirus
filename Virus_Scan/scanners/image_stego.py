"""Scanner-owned image steganography orchestration."""
from __future__ import annotations

import os
from pathlib import Path

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import report_scan_stage_progress, has_any_tag, log_error, read_file_bytes
from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.scanners.binary_appended_payload import scan_appended_payload
from Virus_Scan.scanners.image_jpeg_segments import _scan_jpeg_segments
from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.image_limits import IMAGE_STEGO_MAX_FILE_BYTES
from Virus_Scan.scanners.image_lsb import extract_lsb_payload_gated, scan_pillow_lsb
from Virus_Scan.scanners.image_png_chunks import scan_png_chunks
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join
from Virus_Scan.scanners.image_tags import rewrite_stego_tags
from Virus_Scan.utils.tagging import normalize_tags

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
_IMAGE_CONFIRMED_TAGS = _SCANNER_LIMITS_POLICY.image_confirmed_tags


def scan_image_stego(path: object, data: object = None) -> object:
    """Image steganography layer: EOF payloads, PNG/JPEG metadata, and Pillow LSB checks."""
    tags = ["image_stego_checked"]
    suspicious = False
    try:
        report_scan_stage_progress("image_stego_start")
        path_value = Path(os.fsdecode(path))
        if not path_value.exists():
            return (tags, False)
        if not path_value.is_file():
            return (tags, False)
        size = path_value.stat().st_size
        if size > IMAGE_STEGO_MAX_FILE_BYTES:
            return ([*tags, 'image_stego_scan_skipped_large_file'], False)
        if data is None:
            data = read_file_bytes(path, max_size=IMAGE_STEGO_MAX_FILE_BYTES)
        if not data:
            return (tags, False)
        suspicious = scan_appended_payload(data, tags) or suspicious
        report_scan_stage_progress("image_appended_payload_done", bytes_delta=len(data or b""))
        suspicious = scan_png_chunks(data, tags) or suspicious
        report_scan_stage_progress("image_metadata_chunks_done")
        suspicious = _scan_jpeg_segments(data, tags) or suspicious
        report_scan_stage_progress("image_jpeg_segments_done")
        suspicious = scan_pillow_lsb(path, tags, data=data) or suspicious
        report_scan_stage_progress("image_lsb_scan_done")
        suspicious = extract_lsb_payload_gated(path, tags, data=data) or suspicious
        report_scan_stage_progress("image_lsb_extract_done")
        if "image_decode_failed" in tags and not has_any_tag(tags, *_IMAGE_CONFIRMED_TAGS):
            tags.extend(["malformed_image_input", "image_malformed_evidence_recorded", "image_final_json_must_record"])
            suspicious = True
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        log_error(scanner_contract_join("scan_image_stego failed: ", scanner_contract_error_message(exc)))
        tags.extend(scanner_failure_tags("scan_image_stego", exc, tags))
        tags.append("image_stego_scan_error")
    tags = rewrite_stego_tags(tags, data=data, path=path)
    return (normalize_tags(tags), suspicious)


__all__ = ("scan_image_stego",)
