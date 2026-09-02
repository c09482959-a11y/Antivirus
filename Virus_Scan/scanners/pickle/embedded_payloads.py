"""Scanner-owned pickle embedded payload extraction helpers."""
from __future__ import annotations

from Virus_Scan.runtime.api import log_error
from Virus_Scan.contracts.path_identity import get_scan_extension, path_identity
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join
from Virus_Scan.scanners.pickle.embedded_projection import project_embedded_payload_records
from Virus_Scan.scanners.pickle.embedded_streams import collect_embedded_payload_records
from Virus_Scan.scanners.pickle.graph_tags import unify_pickle_detection_tags
from Virus_Scan.scanners.pickle.payload_records import (
    iter_pickle_payload_records,
    _iter_pickle_payload_records,
    _iter_raw_compressed_payload_records,
    _try_decode_pickle_literal,
)
from Virus_Scan.scanners.pickle.payload_tags import _pickle_decoded_payload_tags
from Virus_Scan.scanners.pickle.rpyc_views import _pickle_container_magic_present
from Virus_Scan.scanners.contracts.scanner_evidence import scanner_failure_evidence_tags

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_FILE_BYTES = _PICKLE_POLICY.decode_max_file_bytes
pickle_container_extensions = frozenset(('.rpa', '.rpy', '.rpyc', '.rpyb', '.rpym', '.rpymc', '.pickle', '.pkl', '.save', '.sav'))


def _embedded_sample_bytes(data: object) -> object:
    if data is None:
        return b''
    if type(data) is bytes:
        return data[:PICKLE_DECODE_MAX_FILE_BYTES]
    if type(data) is bytearray:
        return bytes(data[:PICKLE_DECODE_MAX_FILE_BYTES])
    if type(data) is memoryview:
        return data.tobytes()[:PICKLE_DECODE_MAX_FILE_BYTES]
    raise ValueError('unsafe_pickle_embedded_payload_input_rejected')


def _embedded_payload_scan_scope(data: object, path: object = None) -> object:
    ext = get_scan_extension(path) if path is not None else ''
    name = path_identity(path).name.lower() if path is not None else ''
    blob = _embedded_sample_bytes(data)
    if not blob:
        return ext, blob, False, False
    has_pickle_container_magic = _pickle_container_magic_present(blob)
    in_scope = ext in pickle_container_extensions or 'pickle' in name or has_pickle_container_magic
    return ext, blob, has_pickle_container_magic, in_scope


def pickle_embedded_payload_tags(data: object = None, path: object = None) -> object:
    """Safely inspect RPA/RPYC/pickle/save containers for embedded decoded payloads.

    Recoverable decode/byte-view failures must not collapse to an empty tag list:
    callers such as the RPA scanner use these tags to publish downstream JSON
    evidence for degraded pickle/payload analysis.
    """
    tags = []
    try:
        ext, blob, has_pickle_container_magic, in_scope = _embedded_payload_scan_scope(data, path=path)
        if not in_scope:
            return []
        records = collect_embedded_payload_records(blob, path, ext, has_pickle_container_magic, tags)
        tags.extend(project_embedded_payload_records(records, path=path))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        log_error(scanner_contract_join('pickle_embedded_payload_tags failed: ', scanner_contract_error_message(exc)))
        tags.extend(scanner_failure_evidence_tags(
            'pickle',
            'embedded_payload_decode',
            exc,
            ['pickle_embedded_payload_scan_error', 'pickle_payload_decode_failure'],
            input_path=path,
            state='degraded',
            error_category='pickle_embedded_payload_failure',
            error_source='pickle.embedded_payloads.pickle_embedded_payload_tags',
            file_type='pickle_container',
        ))
        tags.extend(['pickle_failure_evidence_recorded', 'pickle_final_json_must_record'])
    return unify_pickle_detection_tags(tags, path=path)


__all__ = (
    '_iter_pickle_payload_records',
    '_iter_raw_compressed_payload_records',
    '_pickle_decoded_payload_tags',
    '_try_decode_pickle_literal',
    'iter_pickle_payload_records',
    'pickle_embedded_payload_tags',
)
