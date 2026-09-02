from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
import re
from Virus_Scan.runtime.api import log_error, read_file_bytes, record_detector_error, record_suppressed_failure
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join, scanner_contract_text
from Virus_Scan.utils.tagging import normalize_tags, ordered_unique_tags
from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.heuristics import evaluate_game_engine_threats
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot
from Virus_Scan.scanners.pickle.rpyc_views import _iter_rpyc_pickle_byte_views
from Virus_Scan.scanners.pickle.source_detection import renpy_source_pickle_injection_tags
from Virus_Scan.scanners.pickle.embedded_payloads import pickle_embedded_payload_tags
from Virus_Scan.scanners.pickle.graph_tags import (
    detect_python_pickle_opcode_exec,
)
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.archives.rpa_member_behavior import rpa_decoded_member_behavior_tags as _archive_rpa_decoded_member_behavior_tags

_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_FILE_BYTES = _PICKLE_POLICY.decode_max_file_bytes
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets
_ARCHIVE_POLICY = load_archive_policy_snapshot()

def _renpy_text(value: object, *, replacement: object = '') -> object:
    return scanner_contract_text(
        value,
        replacement=replacement,
        missing_reason='missing_renpy_text',
        unsupported_reason='unsafe_renpy_text_rejected',
    )


def _global_raw_renpy_header(path: object) -> object:
    ext = get_scan_extension(path)
    tags = ['renpy']
    if ext in {'.rpyc', '.rpyb'}:
        tags.append('renpy_bytecode')
        try:
            data = read_file_bytes(path, max_size=PICKLE_DECODE_MAX_FILE_BYTES)
            tags.extend(pickle_embedded_payload_tags(data, path=path) or [])
        except SCAN_CONTENT_ERRORS as e:
            try:
                log_error(scanner_contract_join('_global_raw_renpy_header pickle scan failed for ', _renpy_text(path), ': ', scanner_contract_error_message(e)))
            except SCAN_CONTENT_ERRORS as _umige_suppressed_exc:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
    return {'tags': tags}

def _is_valid_renpy_bytecode_header(ext: object, header: object) -> object:
    """Recognize legitimate Ren'Py compiled script containers.

    .rpyc/.rpyb files are expected to be opaque and compressed/pickled.  The
    identity layer should call them Ren'Py bytecode instead of unknown binary,
    while still allowing true PE/ELF/ZIP spoofing to be caught by earlier magic
    checks.
    """
    ext = _renpy_text(ext).lower()
    if ext not in {'.rpyc', '.rpyb', '.rpymc'}:
        return False
    h = bytes(header or b'')
    return h.startswith((b'RENPY RPC', b'RENPY RPC2', b'RENPY RPC3'))

def _rpa_archive_scan_caps() -> object:
    """Return bounded archive scan caps for .rpa containers.

    RPA files are containers. They should keep the fast metadata/triage path,
    then escalate through a capped container scanner. They must not dump all
    members into the generic raw queue in one burst.
    """
    try:
        return {'max_depth': max(0, int(_ARCHIVE_POLICY.rpa_zip_max_depth)), 'max_members': max(1, int(_ARCHIVE_POLICY.rpa_zip_max_members)), 'max_member_size': max(1024, int(_ARCHIVE_POLICY.rpa_zip_max_member_size))}
    except SCAN_CONTENT_ERRORS:
        return {'max_depth': _ARCHIVE_POLICY.rpa_zip_max_depth, 'max_members': _ARCHIVE_POLICY.rpa_zip_max_members, 'max_member_size': _ARCHIVE_POLICY.rpa_zip_max_member_size}

def rpa_decoded_member_behavior_tags(data: object = None, path: object = None) -> object:
    """Public RPA member behavior scanner using canonical archive-owned RPA boundary."""
    return _archive_rpa_decoded_member_behavior_tags(data=data, path=path)


def scan_renpy_file(path: object, *, read_bytes: object = read_file_bytes, engine_threat_evaluator: object = evaluate_game_engine_threats) -> object:
    tags = ['renpy']
    try:
        data = read_bytes(path)
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        log_error(scanner_contract_join('scan_renpy_file input read failed for ', _renpy_text(path), ': ', scanner_contract_error_message(exc)))
        return ordered_unique_tags(scanner_failure_tags('scan_renpy_file.read', exc, tags))
    if get_scan_extension(path) in {'.rpyc', '.rpyb'}:
        tags.append('renpy_bytecode')
    text = data.decode('latin1', errors='ignore').lower()
    try:
        tags.extend(pickle_embedded_payload_tags(data, path=path))
        if get_scan_extension(path) in {'.rpyc', '.rpyb'}:
            for enc_kind, payload_blob in list(_iter_rpyc_pickle_byte_views(data, path=path))[1:PICKLE_DECODE_MAX_OFFSETS]:
                try:
                    view_text = payload_blob.decode('latin1', errors='ignore').lower()
                    tags.extend(['rpyc_decoded_stream_inspected', scanner_contract_join(_renpy_text(enc_kind, replacement='rpyc'), '_analyzed')])
                    tags.extend(renpy_source_pickle_injection_tags(view_text, path=path))
                    tags.extend(detect_python_pickle_opcode_exec(view_text, get_scan_extension(path)))
                except SCAN_CONTENT_ERRORS as exc:
                    if is_programmer_error(exc):
                        raise
                    tags.extend(scanner_failure_tags('scan_renpy_file.decoded_pickle_view', exc, tags))
                    continue
        tags.extend(renpy_source_pickle_injection_tags(text, path=path))
    except SCAN_CONTENT_ERRORS as e:
        if is_programmer_error(e):
            raise
        log_error(scanner_contract_join('renpy pickle graph scan failed for ', _renpy_text(path), ': ', scanner_contract_error_message(e)))
        tags.extend(scanner_failure_tags('scan_renpy_file.pickle_graph', e, tags))
    if re.search('\\b(?:exec|eval)\\s*\\(', text):
        tags.append('code_execution')
    pickle_context = any((x in text for x in ('pickle.loads', 'pickle.load(', 'pickletools', '__reduce__', '__reduce_ex__', 'stack_global', 'opcode: global', 'opcode: reduce', 'cos\nsystem', 'posix\nsystem', 'nt\nsystem', 'builtins\neval', 'builtins\nexec')))
    if 'pickle' in text or pickle_context:
        tags.append('pickle_usage')
    if pickle_context and any((x in text for x in ('os.system', 'subprocess', 'popen(', 'eval(', 'exec(', 'cmd.exe', 'powershell'))):
        tags.extend(['renpy', 'renpy_script', 'pickle_callable_reference', 'pickle_dangerous_global', 'script_execution', 'process_exec'])
    try:
        verdict = engine_threat_evaluator(text, path=_renpy_text(path), engine='renpy')
        tags.extend(verdict.get('tags') or [])
    except SCAN_CONTENT_ERRORS as exc:
        record_detector_error('renpy_game_engine_threats', exc, path=path)
    return ordered_unique_tags(tags)

def global_raw_renpy_header(path: object) -> object:
    """Public Ren'Py-scanner contract for raw Ren'Py header extraction."""
    return _global_raw_renpy_header(path)
