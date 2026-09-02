"""Scanner-owned Ren'Py source-pattern pickle detection."""
from __future__ import annotations

from pathlib import PurePath

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.scanners.contracts import scanner_contract_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError,
    EOFError,
    ValueError,
    TypeError,
    RuntimeError,
    KeyError,
    AttributeError,
    UnicodeError,
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
RENPY_PICKLE_EXTENSIONS = frozenset(_PICKLE_POLICY.renpy_extensions)


def _renpy_path_text_status(path: object) -> object:
    if path is None:
        return '', ''
    if isinstance(path, PurePath):
        return PurePath.__str__(path), ''
    text, reason = no_hook_text(
        path,
        missing_reason='missing_renpy_pickle_path',
        unsupported_reason='unsafe_renpy_pickle_path_rejected',
    )
    return text, reason


def renpy_pickle_path_status(path: object = None) -> object:
    """Return explicit Ren'Py pickle path-scope status without fail-open defaults."""
    try:
        low, path_reason = _renpy_path_text_status(path)
        if path_reason:
            return 'probe_error'
        ext = get_scan_extension(path) if path is not None else ''
        low = low.lower()
        if ext in RENPY_PICKLE_EXTENSIONS or 'renpy' in low or 'game/' in low.replace('\\', '/'):
            return 'present'
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return 'probe_error'
    else:
        return 'absent'


def _is_renpy_pickle_path(path: object = None) -> object:
    """True when a pickle signal came from a Ren'Py/RPA/RPYC/RPY context."""
    return renpy_pickle_path_status(path) == 'present'


def _source_context_flags(low: object) -> object:
    pickle_load = any((x in low for x in ('pickle.loads', 'pickle.load(', 'cpickle.loads', 'cpickle.load(', 'persistent_load', 'find_class')))
    reduce_ctx = any((x in low for x in ('__reduce__', '__reduce_ex__', 'copyreg', 'pickletools', 'stack_global', 'global opcode', 'reduce opcode')))
    decode_ctx = any((x in low for x in ('base64.b64decode', 'zlib.decompress', 'gzip.decompress', 'marshal.loads', 'frombase64string')))
    exec_ctx = any((x in low for x in ('exec(', 'eval(', 'compile(', 'os.system', 'subprocess', 'popen(', 'cmd.exe', 'powershell', 'createprocess')))
    net_or_file_ctx = any((x in low for x in ('urlopen', 'urlretrieve', 'requests.get', 'requests.post', 'http://', 'https://', 'open(', 'appdata', '%temp%', 'renpy.loader')))
    external_exe_ctx = any((x in low for x in ('.exe', '.dll', 'createprocess', 'shellexecute', 'startfile', 'subprocess', 'popen(', 'cmd.exe', 'powershell')))
    external_script_ctx = any((x in low for x in ('.py', '.pyw', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', 'exec(', 'eval(', 'compile(')))
    return pickle_load, reduce_ctx, decode_ctx, exec_ctx, net_or_file_ctx, external_exe_ctx, external_script_ctx


def _append_renpy_source_pickle_tags(tags: list[str], low: str) -> None:
    (
        pickle_load,
        reduce_ctx,
        decode_ctx,
        exec_ctx,
        net_or_file_ctx,
        external_exe_ctx,
        external_script_ctx,
    ) = _source_context_flags(low)
    has_pickle_context = pickle_load or reduce_ctx
    if has_pickle_context:
        tags.extend(['pickle_usage', 'pickle_deserialization_context'])
    if has_pickle_context and net_or_file_ctx:
        tags.extend(['pickle_file_load_context', 'pickle_external_file_reference'])
    if has_pickle_context and external_exe_ctx:
        tags.extend(['pickle_external_executable_reference', 'process_exec'])
    if has_pickle_context and external_script_ctx:
        tags.extend(['pickle_external_script_reference', 'python_bytecode_or_script', 'script_execution'])
    if has_pickle_context and decode_ctx:
        tags.extend(['payload_decode_candidate', 'encoded_payload_candidate'])
    if has_pickle_context and exec_ctx:
        tags.extend([
            'pickle_source_injection_candidate',
            'pickle_callable_reference',
            'pickle_dangerous_global',
            'script_execution',
            'process_exec',
            'renpy',
            'renpy_script',
        ])
        if external_exe_ctx:
            tags.extend(['pickle_external_executable_reference', 'pickle_file_load_context', 'process_exec'])
        if external_script_ctx:
            tags.extend(['pickle_external_script_reference', 'python_bytecode_or_script', 'script_execution'])
    elif has_pickle_context and decode_ctx and net_or_file_ctx:
        tags.extend([
            'pickle_source_injection_candidate',
            'pickle_embedded_payload_candidate',
            'payload_decode_candidate',
            'encoded_payload_candidate',
        ])


def renpy_source_pickle_injection_tags(text: object, path: object = None) -> object:
    """Detect unsafe pickle injection patterns in Ren'Py source text."""
    tags: list[str] = []
    try:
        low = scanner_contract_text(text, replacement='').lower()
        ext = get_scan_extension(path) if path is not None else ''
        in_scope = (
            ext in {'.rpy', '.rpyc', '.rpyb', '.rpymc', '.py', '.rpym'}
            or renpy_pickle_path_status(path) == 'present'
        )
        if in_scope:
            _append_renpy_source_pickle_tags(tags, low)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return sorted(set(tags))


__all__ = ('RENPY_PICKLE_EXTENSIONS', '_is_renpy_pickle_path', 'renpy_pickle_path_status', 'renpy_source_pickle_injection_tags')
