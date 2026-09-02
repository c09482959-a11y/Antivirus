"""Decoded pickle-fragment tag projection."""
from __future__ import annotations

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scanners.contracts import scanner_contract_join
from Virus_Scan.scanners.text_contextual_tags import contextual_tag_scan
from Virus_Scan.scanners.payload_decode import decoded_payload_tags
from Virus_Scan.scanners.pickle.payload_tags import _decoded_payload_exec_tags

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
exec_file_needles = ('.exe', '.dll', 'createprocess', 'shellexecute', 'startfile', 'subprocess', 'popen(', 'cmd.exe', 'powershell')
script_file_needles = ('.py', '.pyw', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', 'exec(', 'eval(', 'compile(')


def _fragment_record_value(rec: object, key: object, default: object = None) -> object:
    items = no_hook_mapping_items(rec, allow_dict_subclass=True)
    if items is None:
        return default
    values = {item_key: item_value for item_key, item_value in items if type(item_key) is str}
    return values.get(key, default)


def _fragment_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_pickle_fragment_text',
        unsupported_reason='unsafe_pickle_fragment_text_rejected',
    )
    return '' if reason else text


def contextual_fragment_tags(text: object, path: object = None) -> object:
    dtags = []
    try:
        dtags.extend(contextual_tag_scan(text, path=path, source='pickle_fragment_decoded_payload', finalize=False))
    except TypeError:
        try:
            dtags.extend(contextual_tag_scan(text, path=path, source='pickle_fragment_decoded_payload'))
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
            _record_fragment_failure(exc)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        _record_fragment_failure(exc)
    return dtags


def _record_fragment_failure(exc: object) -> object:
    try:
        record_suppressed_failure('suppressed_exception', exc, domain='runtime')
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
        _ = reporting_exc


def _decoded_fragment_scanner_tags(text: object, path: object = None) -> object:
    dtags = contextual_fragment_tags(text, path=path)
    scanners = (lambda: decoded_payload_tags(text, path=path, finalize=False),)
    for scan in scanners:
        try:
            dtags.extend(scan())
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
            _record_fragment_failure(exc)
    return dtags


def pickle_fragment_tags(rec: object, path: object = None) -> object:
    failure_tags = _fragment_record_value(rec, 'failure_tags', ())
    if type(failure_tags) in (list, tuple) and failure_tags:
        return list(failure_tags)
    tags = [
        'pickle_fragmented_payload', 'pickle_fragmented_base64_payload',
        'payload_decode_candidate', 'decoded_payload_rescanned',
        'payload_decode_candidate', 'encoded_payload_candidate',
    ]
    binary_magic = _fragment_text(_fragment_record_value(rec, 'binary_magic', ''))
    if binary_magic:
        tags.extend(['decoded_binary_payload', scanner_contract_join('decoded_', binary_magic, '_payload')])
    text = _fragment_text(_fragment_record_value(rec, 'text', ''))
    low_text = text.lower()
    if any(x in low_text for x in exec_file_needles):
        tags.extend(['pickle_external_file_reference', 'pickle_external_executable_reference', 'pickle_file_load_context'])
    if any(x in low_text for x in script_file_needles):
        tags.extend(['pickle_external_file_reference', 'pickle_external_script_reference', 'pickle_file_load_context', 'python_bytecode_or_script'])
    dtags = _decoded_fragment_scanner_tags(text, path=path)
    if dtags:
        tags.extend(dtags)
        tags.extend(_decoded_payload_exec_tags(dtags, text, path=path))
    return tags


__all__ = ('contextual_fragment_tags', 'pickle_fragment_tags')
