"""Scanner-owned raw text chunk scanning contracts.

Raw queue chunk helpers live here instead of the high-level text scanner module
so read failures, contextual scan failures, and raw engine chunk ownership stay
explicit and evidence-producing.
"""

from pathlib import Path
import re

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join, scanner_contract_nonnegative_int, scanner_failure_evidence_record, scanner_failure_evidence_tags
from Virus_Scan.scanners.raw_chunk_core import should_context_scan as _raw_should_context_scan
from Virus_Scan.scanners.pickle.source_detection import renpy_source_pickle_injection_tags
from Virus_Scan.scanners.text_contextual_tags import contextual_tag_scan


PLR2004N2 = 2


def _global_raw_read_range_text_result(path: object, *, start: object = 0, size: object = None, default_size: object = 65536, open_reader: object = open) -> object:
    """Read a bounded text chunk and carry explicit failure evidence."""
    try:
        start_i = scanner_contract_nonnegative_int(start, replacement=0)
        size_i = int(size if size is not None else default_size)
        size_i = max(0, min(size_i, 2_000_000))
        with open_reader(path, 'rb') as fh:
            fh.seek(start_i)
            data = fh.read(size_i)
        return {'text': data.decode('latin1', errors='ignore'), 'failure_tags': [], 'failure_evidence': []}
    except SCAN_CONTENT_ERRORS as exc:
        record_suppressed_failure('global_raw_read_range_text', exc, domain='scanner')
        return {
            'text': '',
            'failure_tags': scanner_failure_evidence_tags(
                'text',
                'global_raw_read_range_text',
                exc,
                ['global_raw_read_range_text_error'],
                input_path=path,
            ),
            'failure_evidence': [
                scanner_failure_evidence_record(
                    'text',
                    'global_raw_read_range_text',
                    exc,
                    input_path=path,
                    error_source='text._global_raw_read_range_text',
                )
            ],
        }


def _global_raw_read_range_text(path: object, *, start: object = 0, size: object = None, default_size: object = 65536, open_reader: object = open) -> object:
    """Read a bounded text chunk for raw scanner tasks."""
    return str(_global_raw_read_range_text_result(path, start=start, size=size, default_size=default_size, open_reader=open_reader).get('text') or '')


def _global_raw_should_context_scan(text: object) -> object:
    return bool(_raw_should_context_scan(text, report=lambda label, exc: record_suppressed_failure(label, exc, domain='scanner')))


def _global_raw_pe_api_header(path: object) -> object:
    """Cheap PE API header marker. Full API strings are handled by pe_api_chunk."""
    tags = []
    try:
        with Path(path).open('rb') as fh:
            data = fh.read(4096)
        if data.startswith(b'MZ'):
            tags.append('pe_file')
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    return {'tags': tags}


def _global_raw_renpy_chunk(path: object, start: object = 0, size: object = None, *, open_reader: object = open, context_scanner: object = contextual_tag_scan) -> object:
    read_result = _global_raw_read_range_text_result(path, start=start, size=size, open_reader=open_reader)
    text = str(read_result.get('text') or '')
    low = text.lower()
    tags = list(read_result.get('failure_tags') or [])
    if re.search('\\b(?:exec|eval)\\s*\\(', low):
        tags.append('code_execution')
    pickle_context = any((x in low for x in ('pickle.loads', 'pickle.load(', 'pickletools', '__reduce__', '__reduce_ex__', 'stack_global', 'opcode: global', 'opcode: reduce', 'cos\nsystem', 'posix\nsystem', 'nt\nsystem', 'builtins\neval', 'builtins\nexec')))
    if 'pickle' in low or pickle_context:
        tags.append('pickle_usage')
    try:
        tags.extend(renpy_source_pickle_injection_tags(low, path=path))
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    if pickle_context and any((x in low for x in ('os.system', 'subprocess', 'popen(', 'eval(', 'exec(', 'cmd.exe', 'powershell'))):
        tags.extend(['renpy', 'renpy_script', 'pickle_callable_reference', 'pickle_dangerous_global', 'script_execution', 'process_exec'])
    if _global_raw_should_context_scan(low):
        try:
            tags.extend(context_scanner(low, path=path, source='global_raw_chunk', finalize=False) or [])
        except TypeError:
            tags.extend(context_scanner(low, path=path, source='global_raw_chunk') or [])
    result = {'tags': tags, 'strings_blob': text[:65536]}
    if read_result.get('failure_evidence'):
        result['failure_evidence'] = list(read_result.get('failure_evidence') or [])
    return result


def _global_raw_rpgm_js_ast_chunk(path: object, start: object = 0, size: object = None) -> object:
    read_result = _global_raw_read_range_text_result(path, start=start, size=size)
    text = str(read_result.get('text') or '')
    low = text.lower()
    tags = list(read_result.get('failure_tags') or [])
    if any((x in low for x in ['rpg_core', 'rpg_managers', 'rpgmaker', 'window.rpgmaker'])):
        tags += ['rpgm_javascript', 'rpgm_core_reference']
    call_patterns = [('eval_usage', '\\beval\\s*\\('), ('dynamic_function', '\\bfunction\\s*\\('), ('dynamic_code_generation', '\\bnew\\s+function\\s*\\('), ('node_require', '\\brequire\\s*\\('), ('child_process_reference', 'child_process'), ('process_exec', '\\.(exec|execfile|spawn|fork)\\s*\\('), ('filesystem_access', '\\bfs\\s*=\\s*require\\s*\\(|require\\s*\\(\\s*[\'\\"]fs[\'\\"]'), ('network_activity', '\\bhttps?\\s*=\\s*require\\s*\\(|xmlhttprequest|fetch\\s*\\('), ('websocket_activity', 'websocket\\s*\\('), ('delayed_execution', 'settimeout\\s*\\(|setinterval\\s*\\('), ('base64_decode', 'atob\\s*\\(|buffer\\.from\\s*\\([^\\)]*base64'), ('encoded_payload_candidate', 'fromcharcode\\s*\\(|charcodeat\\s*\\('), ('browser_storage_access', 'localstorage|sessionstorage|indexeddb'), ('external_script_load', 'createscript|createelement\\s*\\(\\s*[\'\\"]script')]
    for tag, pat in call_patterns:
        try:
            if re.search(pat, low):
                tags.append(tag)
        except SCAN_CONTENT_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except SCAN_CONTENT_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    if 'require(' in low and any((x in low for x in ['child_process', 'powershell', 'cmd.exe', 'wscript', 'cscript'])):
        tags.extend(('nodejs_native_bridge', 'script_execution', 'process_exec'))
    if 'eval' in low and any((x in low for x in ['atob', 'fromcharcode', 'base64', 'unescape'])):
        tags += ['js_encoded_eval_chain', 'obfuscated_javascript']
    if any((x in low for x in ['savefileinfo', 'datamanager', 'storagemanager'])):
        tags.append('rpgm_storage_reference')
    if len(re.findall('[A-Za-z0-9+/]{120,}={0,2}', text)) >= PLR2004N2:
        tags += ['embedded_base64_payload', 'encoded_payload_candidate']
    if _global_raw_should_context_scan(low):
        try:
            tags.extend(contextual_tag_scan(low, path=path, source='global_raw_chunk', finalize=False) or [])
        except TypeError:
            tags.extend(contextual_tag_scan(low, path=path, source='global_raw_chunk') or [])
    result = {'tags': tags, 'strings_blob': text[:65536]}
    if read_result.get('failure_evidence'):
        result['failure_evidence'] = list(read_result.get('failure_evidence') or [])
    return result


def _intrastage_contextual_chunk_raw(chunk: object, path: object = None, source: object = 'strings', offset: object = 0) -> object:
    """Raw contextual tag scan for one text chunk."""
    del offset
    if not _global_raw_should_context_scan(chunk):
        return []
    try:
        return list(contextual_tag_scan(chunk, path=path, source=source, finalize=False) or [])
    except TypeError:
        return list(contextual_tag_scan(chunk, path=path, source=source) or [])
    except SCAN_CONTENT_ERRORS as e:
        try:
            log_error(scanner_contract_join(
                'intrastage contextual chunk failed: ',
                scanner_contract_error_message(e),
            ))
        except SCAN_CONTENT_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except SCAN_CONTENT_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
        return scanner_failure_evidence_tags(
            'text',
            'intrastage_contextual_chunk',
            e,
            ['text_context_chunk_error'],
            input_path=path,
        )


def global_raw_pe_api_header(path: object) -> object:
    """Public text-scanner contract for raw PE API header extraction."""
    return _global_raw_pe_api_header(path)


def global_raw_renpy_chunk(path: object, start: object = 0, size: object = None) -> object:
    """Public text-scanner contract for raw Ren'Py chunk extraction."""
    return _global_raw_renpy_chunk(path, start=start, size=size)


def global_raw_rpgm_js_ast_chunk(path: object, start: object = 0, size: object = None) -> object:
    """Public text-scanner contract for raw RPGM JavaScript AST chunk extraction."""
    return _global_raw_rpgm_js_ast_chunk(path, start=start, size=size)


__all__ = (
    '_global_raw_pe_api_header',
    '_global_raw_read_range_text',
    '_global_raw_read_range_text_result',
    '_global_raw_renpy_chunk',
    '_global_raw_rpgm_js_ast_chunk',
    '_global_raw_should_context_scan',
    '_intrastage_contextual_chunk_raw',
    'global_raw_pe_api_header',
    'global_raw_renpy_chunk',
    'global_raw_rpgm_js_ast_chunk',
)
