from pathlib import Path
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_mapping_items, no_hook_text, no_hook_type_name
import hashlib
import os
from Virus_Scan.runtime.api import (
    FAST_FINGERPRINT_SAMPLE,
    log_error,
    record_detector_error,
    record_suppressed_failure,
)
from Virus_Scan.scheduler.api.runtime import note_identity_for_queue as _queue_identity_note_owned
from Virus_Scan.utils.stages import get_scan_extension
from Virus_Scan.utils.pathing import normalize_scan_path, scan_path_text as _scan_path_text_contract
from Virus_Scan.contracts.path_identity import should_include_scan_path as _should_include_scan_path_contract, DEFAULT_EXCLUDED_DIRS, DEFAULT_EXCLUDED_FILES, DEFAULT_EXCLUDED_SUFFIXES



def _routing_bool_unavailable() -> object:
    # Explicit degraded routing boolean used after recording the concrete failure path.
    return False


def _routing_digest_unavailable() -> object:
    # Explicit degraded routing digest used after recording the concrete failure path.
    return ''


def _routing_text(value: object, *, default: object='') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='routing_text_missing',
        unsupported_reason='routing_text_rejected',
    )
    return default if reason else text


def _routing_int(value: object, *, default: object) -> object:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason='routing_integer_rejected',
        non_finite_reason='routing_integer_rejected',
    )
    return default if reason else parsed


def _routing_mapping(value: object) -> object:
    items = no_hook_mapping_items(value)
    return {} if items is None else dict(items)



def fast_file_fingerprint(path: object, sample_size: object=FAST_FINGERPRINT_SAMPLE) -> object:
    """Cheap identity key used before full SHA-256 cache lookup.

    This avoids hashing multi-GB media/assets when size/mtime/head/tail already
    prove the file is unchanged. Full SHA-256 is still computed on cache miss or
    when a result is stored, so detection integrity is preserved.
    """
    try:
        p = normalize_scan_path(path, require_exists=True)
        p = str(Path(str(p)).resolve())
        st = os.stat(p)
        size = st.st_size if type(st.st_size) is int else _routing_int(st.st_size, default=0)
        mtime_raw = getattr(st, 'st_mtime_ns', None)
        if type(mtime_raw) is int:
            mtime_ns = mtime_raw
        elif type(st.st_mtime) is float:
            mtime_ns = int(st.st_mtime * 1000000000)
        else:
            mtime_ns = 0
        sample_size = max(4096, _routing_int(sample_size, default=FAST_FINGERPRINT_SAMPLE))
        with Path(p).open('rb') as f:
            head = f.read(min(sample_size, size))
            if size > sample_size:
                f.seek(max(0, size - sample_size))
                tail = f.read(sample_size)
            else:
                tail = b''
        h = hashlib.sha256()
        h.update(int.__str__(size).encode('ascii'))
        h.update(b'|')
        h.update(int.__str__(mtime_ns).encode('ascii'))
        h.update(b'|')
        h.update(head)
        h.update(b'|')
        h.update(tail)
        return (h.hexdigest(), {'size': size, 'mtime_ns': mtime_ns, 'extension': get_scan_extension(p)})
    except RECOVERABLE_RUNTIME_ERRORS as e:
        record_detector_error(
            'fast_file_fingerprint',
            e,
            context={'path_type': no_hook_type_name(path), 'error_type': no_hook_type_name(e)},
        )
        log_error('fast fingerprint failed: ' + no_hook_type_name(e))
        return ('', {})

def _global_raw_bytecode_header(path: object) -> object:
    """Extension-only bytecode/script tags; content scanning is chunked."""
    ext = get_scan_extension(path)
    tags = []
    if ext in {'.py', '.pyc', '.pyo'}:
        tags.append('python_bytecode_or_script')
    if ext in {'.js', '.jse'}:
        tags += ['jscript_execution', 'script_execution']
    if ext in {'.vbs', '.vbe'}:
        tags += ['vbs_execution', 'script_execution']
    if ext in {'.ps1', '.psm1'}:
        tags += ['powershell_exec', 'script_execution']
    if ext in {'.bat', '.cmd'}:
        tags += ['cmd_exec', 'script_execution']
    if ext in {'.jar', '.class'}:
        tags.append('java_bytecode')
    return {'tags': tags}

def _image_is_jpeg(data: object=None, path: object=None) -> object:
    try:
        data_bytes = data if type(data) is bytes else (bytes(data) if type(data) is bytearray else b'')
        if data_bytes.startswith(b'\xff\xd8'):
            return True
        ext = get_scan_extension('' if path is None else path)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_detector_error('_image_is_jpeg', exc, context={'path_type': no_hook_type_name(path)})
        return _routing_bool_unavailable()
    else:
        return ext in {'.jpg', '.jpeg'}

def _is_rpa_path(path: object) -> object:
    try:
        return get_scan_extension(path) == '.rpa'
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_detector_error('_is_rpa_path', exc, context={'path_type': no_hook_type_name(path)})
        return _routing_bool_unavailable()

def _queue_identity_index_note(queue_dir: object, identity: object) -> None:
    """Incrementally add a known-published identity to the owned queue index."""
    if not identity:
        return
    try:
        _queue_identity_note_owned(queue_dir, identity)
    except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc

def _raw_stage_cache_allowed(job: object) -> object:
    try:
        job_fields = _routing_mapping(job)
        file_value = dict.get(job_fields, 'file')
        ext = get_scan_extension('' if file_value is None else file_value)
        collector = _routing_text(dict.get(job_fields, 'collector', ''))
        base = Path(_scan_path_text_contract(file_value)).name.lower()
        if ext in {'.dll', '.exe', '.pyd'} and collector in {'identity', 'pe_api', 'pure_pe', 'dotnet', 'unity_dotnet', 'il2cpp', 'pe_api_chunk', 'pure_pe_chunk', 'dotnet_chunk', 'unity_dotnet_chunk', 'il2cpp_chunk'}:
            return True
        return base in {'libpython3.9.dll', 'd3dcompiler_47.dll', 'libglesv2.dll', 'librenpython.dll'}
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_detector_error('_raw_stage_cache_allowed', exc, context={'job_type': no_hook_type_name(job)})
        return _routing_bool_unavailable()

def sha256_file(path: object, limit: object=None) -> object:
    h = hashlib.sha256()
    resolved = normalize_scan_path(path, require_exists=True)
    try:
        with Path(resolved).open('rb') as f:
            remaining = limit
            while True:
                if remaining is not None and remaining <= 0:
                    break
                chunk_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
                data = f.read(chunk_size)
                if not data:
                    break
                h.update(data)
                if remaining is not None:
                    remaining -= len(data)
        return h.hexdigest()
    except RECOVERABLE_RUNTIME_ERRORS as e:
        record_detector_error(
            'sha256_file',
            e,
            context={'path': _scan_path_text_contract(path), 'resolved': _scan_path_text_contract(resolved)},
        )
        log_error('sha256 file failed: ' + no_hook_type_name(e))
        return _routing_digest_unavailable()





def scan_path_text(*args: object, **kwargs: object) -> object:
    """Routing mapping for canonical path text normalization."""
    return _scan_path_text_contract(*args, **kwargs)

def should_scan_path(path: object, *, scan_root: object=None) -> object:
    """Return False for scanner outputs, caches, profiles, rule archives, and the running script.

    Routing wraps the import-light contract predicate instead of owning a second
    path exclusion policy.  This removes the core<->routing<->reporting cycle
    while preserving the v27 behavior surface.
    """
    try:
        return _should_include_scan_path_contract(path, scan_root=scan_root, excluded_dirs=DEFAULT_EXCLUDED_DIRS, excluded_files=DEFAULT_EXCLUDED_FILES, excluded_suffixes=DEFAULT_EXCLUDED_SUFFIXES)
    except RECOVERABLE_RUNTIME_ERRORS as e:
        record_detector_error('should_scan_path', e, context={'path_type': no_hook_type_name(path)})
        log_error('extension routing analysis failed without synthetic substitute: ' + no_hook_type_name(e))
        return _routing_bool_unavailable()
def raw_stage_cache_allowed(job: object) -> object:
    """Public routing contract for scheduler raw-stage cache eligibility."""
    return _raw_stage_cache_allowed(job)


def global_raw_bytecode_header(path: object) -> object:
    """Public routing contract for raw bytecode header extraction."""
    return _global_raw_bytecode_header(path)
