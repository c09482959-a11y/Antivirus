"""Canonical immutable pickle failure-record construction."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scanners.contracts import (
    scanner_failure_evidence_record,
    scanner_failure_evidence_tags,
)
from Virus_Scan.scanners.pickle.literal_text import pickle_literal_text


@dataclass(frozen=True, slots=True)
class PickleFailureRequest:
    stage: object
    error: object
    path: object = None
    encoding: object = 'pickle'
    pickle_offset: object = None
    container_offset: object = None


def pickle_failure_record(request: PickleFailureRequest) -> object:
    stage_text = pickle_literal_text(request.stage, default='pickle') or 'pickle'
    encoding_text = pickle_literal_text(request.encoding, default='pickle_failure') or 'pickle_failure'
    tags = scanner_failure_evidence_tags(
        'pickle',
        stage_text,
        request.error,
        [stage_text + '_error', 'pickle_parse_failed'],
        input_path=request.path,
        state='malformed',
        error_category='pickle_parse_failure',
    )
    evidence = scanner_failure_evidence_record(
        'pickle',
        stage_text,
        request.error,
        input_path=request.path,
        state='malformed',
        error_category='pickle_parse_failure',
        error_source='pickle.' + stage_text,
        file_type='pickle',
    )
    record = {
        'encoding': encoding_text,
        'text': '',
        'byte_len': 0,
        'sha256': '',
        'binary_magic': '',
        'failure_tags': list(tags),
        'failure_evidence': [evidence],
    }
    if request.pickle_offset is not None:
        record['pickle_offset'] = request.pickle_offset
    if request.container_offset is not None:
        record['container_offset'] = request.container_offset
    return record


__all__ = ('PickleFailureRequest', 'pickle_failure_record')
