"""Scan-local immutable evidence cache handoff ownership.

Detection records evidence cache writes as JSON/replay-visible immutable handoff
records.  It does not mutate runtime detection state directly.
"""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.scan_evidence_cache_publication import (
    freeze_scan_evidence_cache_items,
    scan_evidence_cache_item_keys,
    scan_evidence_cache_path_text,
)
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence


def remember_scan_evidence(path: object, **items: object) -> object:
    """Return an immutable cache-publication record without runtime mutation."""
    try:
        path_text, path_evidence = scan_evidence_cache_path_text(path)
        key = str(Path(path_text).resolve())
        safe_items = dict(items)
        if path_evidence is not None:
            safe_items["path_evidence"] = path_evidence
        safe = freeze_scan_evidence_cache_items(safe_items)
        return {
            'ok': True,
            'cache_publication_request': {
                'kind': 'scan_evidence_cache_write',
                'path': key,
                'keys': list(scan_evidence_cache_item_keys(safe)),
                'items': safe,
            },
            'failure_evidence': [],
        }
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        failure = recoverable_failure_evidence(
            stage_name='scan_evidence_cache_write',
            error=exc,
            error_source='remember_scan_evidence',
            affected_context=path,
        )
        return {'ok': False, 'cache_publication_request': None, 'failure_evidence': [failure.to_record()]}


def get_scan_evidence(path: object) -> object:
    """Return explicit evidence that runtime cache reads are no longer detection-owned."""
    failure = recoverable_failure_evidence(
        stage_name='scan_evidence_cache_read',
        error='runtime scan-evidence cache read is external to detection ownership',
        error_source='get_scan_evidence',
        affected_context=path,
    )
    return {'failure_evidence': [failure.to_record()], 'cache_read_external_to_detection': True}


__all__ = ('get_scan_evidence', 'remember_scan_evidence')
