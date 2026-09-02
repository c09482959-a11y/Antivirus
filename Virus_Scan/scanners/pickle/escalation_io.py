"""Input, output, and failure shaping for pickle fast escalation."""
from __future__ import annotations

from pathlib import Path
from Virus_Scan.runtime.api import scanner_failure_tags
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.runtime.api import log_error
from Virus_Scan.contracts.path_identity import path_identity
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join, scanner_failure_evidence_tags
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_FAST_ESCALATION_MAX_BYTES = _PICKLE_POLICY.fast_escalation_max_bytes
PICKLE_FAST_READ_FAILURE = object()


def _pickle_fast_empty_info() -> object:
    return {'hits': [], 'tags': [], 'force_full': False, 'meta': {}}


def _pickle_fast_path_info(path: object) -> object:
    identity = path_identity(path)
    return identity.suffix.lower(), identity.name.lower()


def _pickle_fast_read_sample(path: object, ext: object, info: object) -> object:
    try:
        with Path(path).open('rb') as handle:
            return handle.read(PICKLE_FAST_ESCALATION_MAX_BYTES)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        read_tags = scanner_failure_tags('pickle_fast_escalation_prefilter.read', exc, ['pickle_fast_read_error'])
        info['hits'] = ['pickle_fast_read_error']
        info['tags'] = sorted(set(scanner_failure_evidence_tags('pickle', 'pickle_fast_read', exc, read_tags, input_path=path)))
        info['force_full'] = True
        info['meta'] = {'pickle_fast_ext': ext, 'pickle_fast_read_error': type(exc).__name__}
        return PICKLE_FAST_READ_FAILURE


def _pickle_fast_text_from_data(data: object, path: object, info: object) -> object:
    try:
        return bytes(data or b'').decode('latin1', errors='ignore')
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        info['tags'] = sorted(set(list(info.get('tags') or []) + scanner_failure_evidence_tags(
            'pickle', 'pickle_fast_text_decode', exc, ['pickle_fast_text_decode_error'],
            input_path=path, state='degraded', error_category='pickle_text_decode_failure')))
        info['force_full'] = True
        info.setdefault('meta', {})['pickle_fast_text_decode_error'] = type(exc).__name__
        return 'pickle_fast_text_decode_error'


def _pickle_fast_apply_outcome(info: object, ext: object, data: object, hits: object, tags: object) -> object:
    if hits:
        info['hits'] = sorted(set(hits))
        info['tags'] = sorted(set(tags))
        info['force_full'] = True
        info['meta'] = {'pickle_fast_ext': ext, 'pickle_fast_sample_bytes': len(data)}
    return info


def _pickle_fast_prefilter_error(info: object, path: object, error: object) -> object:
    info['hits'] = sorted(set([*list(info.get('hits') or []), 'pickle_fast_prefilter_error']))
    info['tags'] = sorted(set(list(info.get('tags') or []) + scanner_failure_evidence_tags(
        'pickle', 'pickle_fast_escalation_prefilter', error,
        scanner_failure_tags('pickle_fast_escalation_prefilter', error, ['pickle_fast_prefilter_error']),
        input_path=path)))
    info['force_full'] = True
    info['meta'] = {'pickle_fast_error': type(error).__name__}
    try:
        log_error(scanner_contract_join(
            'pickle_fast_escalation_prefilter failed for ',
            path_identity(path).raw,
            ': ',
            scanner_contract_error_message(error),
        ))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
            _ = reporting_exc
    return info


__all__ = ('PICKLE_FAST_READ_FAILURE', '_pickle_fast_apply_outcome', '_pickle_fast_empty_info', '_pickle_fast_path_info', '_pickle_fast_prefilter_error', '_pickle_fast_read_sample', '_pickle_fast_text_from_data')
