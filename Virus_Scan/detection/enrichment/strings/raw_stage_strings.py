"""Canonical detection enrichment owner for raw stage string IO helpers."""

from __future__ import annotations

import hashlib
from typing import Iterator

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty

_STRING_SCAN_RULES: tuple[tuple[str, str], ...] = (
    ("powershell", "powershell_exec"),
    ("encodedcommand", "encoded_powershell"),
    (" -enc ", "encoded_powershell"),
    ("http://", "url_present"),
    ("https://", "url_present"),
    ("downloadstring", "network_download"),
    ("downloadfile", "network_download"),
    ("invoke-webrequest", "network_download"),
    ("certutil", "certutil_exec"),
    ("bitsadmin", "bitsadmin_exec"),
    ("mshta", "mshta_exec"),
    ("rundll32", "rundll32_exec"),
    ("regsvr32", "regsvr32_exec"),
    ("writeprocessmemory", "memory_write"),
    ("virtualalloc", "memory_allocate"),
    ("createremotethread", "thread_execution"),
)


def _safe_stage_text(data: object) -> str:
    if data is None:
        return ""
    return detection_enrichment_text_or_empty(data, default="string_enrichment_input_unavailable")


def stage_decode_latin1(data: object) -> str:
    """Decode raw stage bytes as latin-1 without mutating detection state."""
    try:
        if data is None:
            return ""
        if type(data) is bytes:
            return bytes(data).decode("latin1", errors="ignore")
        if type(data) is bytearray:
            return bytes(data).decode("latin1", errors="ignore")
        if type(data) is memoryview:
            return bytes(data).decode("latin1", errors="ignore")
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return _safe_stage_text(data)
    return _safe_stage_text(data)


def _scan_string_content(data: object) -> list[str]:
    text = _safe_stage_text(data)
    lowered = " " + text.lower() + " "
    tags = [tag for needle, tag in _STRING_SCAN_RULES if needle in lowered]
    tagset = set(tags)
    if {"network_download", "url_present"} <= tagset:
        tags.append("download_observable")
    if "powershell_exec" in tagset:
        tags.append("process_exec")
    if {"powershell_exec", "encoded_powershell"} <= tagset:
        tags.append("encoded_script_execution")
    return list(ordered_unique_tags(tags))


def raw_stage_scan_strings(data: object) -> list[str]:
    """Return raw stage string-evidence tags through detection-owned rules."""
    return _scan_string_content(data)


def scan_strings(data: object, path: object = None, *, finalize: bool = True) -> list[str]:
    """Return scanner string-evidence tags through detection-owned rules."""
    del finalize, path  # Explicitly unused contract parameters.
    return list(_scan_string_content(data))


def iter_ordered_string_events(data: object) -> Iterator[tuple[int, dict[str, object]]]:
    """Yield ordered string events through the same bounded detection rule set."""
    text = _safe_stage_text(data)
    low = text.lower()
    events: list[tuple[int, dict[str, object]]] = []
    for needle, tag in _STRING_SCAN_RULES:
        idx = low.find(needle.strip())
        if idx >= 0:
            events.append((idx, {"tag": tag, "raw": text[idx:idx + len(needle.strip())]}))
    return iter(sorted(events, key=lambda item: item[0]))


def scan_hash_for_staging(path: object) -> str:
    """Return a deterministic short path hash for extraction-stage staging metadata."""
    return hashlib.sha256(_safe_stage_text(path).encode("utf-8", errors="ignore")).hexdigest()[:16]


__all__ = (
    "iter_ordered_string_events",
    "raw_stage_scan_strings",
    "scan_hash_for_staging",
    "scan_strings",
    "stage_decode_latin1",
)
