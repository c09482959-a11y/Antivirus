"""SHA-256 projection helpers for final JSON records."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Mapping

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    projection_text_result,
    projection_unavailable_text,
)
from Virus_Scan.publication.json_finalization.truthiness import first_present_value


def _sha_record_path(record: Mapping[str, object]) -> str:
    path = first_present_value(record, "input_file_path", "path", "file", "node")
    if path is None:
        return ""
    text, reason = projection_text_result(path)
    if reason:
        return projection_unavailable_text(path, reason)
    if text == "":
        return ""
    return os.path.normpath(text).replace("\\", "/")


def _sha256_text_is_valid(text: str) -> bool:
    return len(text) == 64 and all(item in "0123456789abcdef" for item in text)


def _sha256_file_for_final_json(path: str) -> str:
    try:
        source = Path(path)
        if not source.is_file():
            return ""
        digest = hashlib.sha256()
        with source.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if chunk == b"":
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except TELEMETRY_FAILURE_ERRORS:
        return ""


def record_sha256(record: Mapping[str, object]) -> str:
    """Return the canonical final SHA-256 for a published scan record."""
    existing = first_present_value(record, "final_sha256", "sha256", "source_sha256", "cache_sha256", "sample_sha256")
    if existing is not None:
        text, reason = projection_text_result(existing)
        if not reason:
            candidate = text.strip().lower()
            if _sha256_text_is_valid(candidate):
                return candidate
    stable_path = _sha_record_path(record)
    if stable_path == "":
        return ""
    return _sha256_file_for_final_json(stable_path)


__all__ = ("record_sha256",)
