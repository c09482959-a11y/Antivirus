"""Scanner-owned immutable scan evidence cache publication records."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.scan_evidence_cache_publication import (
    freeze_scan_evidence_cache_items,
    scan_evidence_cache_item_keys,
    scan_evidence_cache_path_text,
)
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags


def remember_scan_evidence(path: object, **items: object) -> object:
    try:
        path_text, path_evidence = scan_evidence_cache_path_text(path)
        key = str(Path(path_text).resolve())
        safe_items = dict(items)
        if path_evidence is not None:
            safe_items["path_evidence"] = path_evidence
        safe = freeze_scan_evidence_cache_items(safe_items)
        return {
            "ok": True,
            "cache_publication_request": {
                "kind": "scan_evidence_cache_write",
                "path": key,
                "keys": list(scan_evidence_cache_item_keys(safe)),
                "items": safe,
            },
            "failure_evidence": [],
        }
    except SCAN_CONTENT_ERRORS as exc:
        return {
            "ok": False,
            "cache_publication_request": None,
            "failure_evidence": scanner_failure_evidence_tags(
                "binary",
                "scan_evidence_cache_write",
                exc,
                ["scanner_failure_evidence_recorded", "binary_final_json_must_record"],
                state="degraded",
                error_category="binary_evidence_publication_failure",
                file_type="binary",
            ),
        }


__all__ = ("remember_scan_evidence",)
