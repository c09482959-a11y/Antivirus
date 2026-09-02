"""Raw chunk scanner collectors for bytecode, .NET, and PE markers."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scanners.raw_chunk_core import _SCANNER_LIMITS_POLICY, _contextual_chunk_tags


@dataclass(frozen=True, slots=True)
class BytecodeChunkRequest:
    path: object
    start: object
    size: object
    read_range_text_func: object
    get_scan_extension: object
    detect_pickle_exec: object
    should_context_scan_func: object
    contextual_scan: object
    context_failure: object
    report: object
    recoverable_exceptions: object


@dataclass(frozen=True, slots=True)
class ContextualRawChunkRequest:
    path: object
    start: object
    size: object
    read_range_text_func: object
    should_context_scan_func: object
    contextual_scan: object
    context_failure: object


def bytecode_chunk(request: BytecodeChunkRequest) -> object:
    """Scanner-owned chunk-level bytecode/script behavioral collector."""
    text = request.read_range_text_func(request.path, start=request.start, size=request.size)
    low = text.lower()
    ext = request.get_scan_extension(request.path)
    tags = []
    if 'eval(' in low or 'exec(' in low:
        tags += ['bytecode_eval', 'bytecode_exec']
    if 'subprocess' in low or 'os.system' in low or 'popen(' in low:
        tags += ['bytecode_subprocess', 'process_exec']
    if 'socket' in low and 'connect' in low:
        tags += ['bytecode_socket', 'network_activity']
    if 'pickle.loads' in low or 'marshal.loads' in low:
        tags.append('bytecode_deserialization')
    try:
        tags.extend(request.detect_pickle_exec(low, ext) or [])
    except request.recoverable_exceptions as exc:
        try:
            request.report('raw_bytecode_pickle_detection_failed', exc)
        except request.recoverable_exceptions as report_exc:
            _ = report_exc
    tags.extend(_contextual_chunk_tags(
        low, path=request.path, source='global_raw_chunk', collector='bytecode_chunk', start=request.start,
        should_context_scan_func=request.should_context_scan_func,
        contextual_scan=request.contextual_scan,
        context_failure=lambda _current, collector, exc, *, path=None, start=0: request.context_failure(tags, collector, exc, path=path, start=start),
    ))
    return {'tags': tags, 'strings_blob': text[:_SCANNER_LIMITS_POLICY.raw_chunk_strings_blob_max_chars]}



def dotnet_chunk(request: ContextualRawChunkRequest) -> object:
    """Scanner-owned raw chunk-level .NET/string collector."""
    text = request.read_range_text_func(request.path, start=request.start, size=request.size)
    low = text.lower()
    tags = []
    dotnet_markers = [
        'mscoree.dll', '_cor_exe_main', '_cor_dll_main', 'system.reflection',
        'system.runtime', 'clr', '#strings', '#us', '#blob',
    ]
    if any(marker in low for marker in dotnet_markers):
        tags += ['dotnet', 'dotnet_pe', 'clr_runtime_present']
    if '#strings' in low and '#us' in low and '#blob' in low:
        tags += ['dotnet', 'dotnet_metadata']
    if 'confuser' in low or 'dnspy' in low or 'costura' in low:
        tags += ['dotnet_obfuscated_or_packed', 'packed_or_obfuscated']
    tags.extend(_contextual_chunk_tags(
        low, path=request.path, source='global_raw_chunk', collector='dotnet_chunk', start=request.start,
        should_context_scan_func=request.should_context_scan_func,
        contextual_scan=request.contextual_scan,
        context_failure=lambda _current, collector, exc, *, path=None, start=0: request.context_failure(tags, collector, exc, path=path, start=start),
    ))
    return {'tags': tags, 'strings_blob': text[:_SCANNER_LIMITS_POLICY.raw_chunk_strings_blob_max_chars]}



def pe_api_chunk(path: object, *, start: object = 0, size: object = None, read_range_text_func: object) -> object:
    """Scanner-owned chunk-level PE API/import marker collector."""
    text = read_range_text_func(path, start=start, size=size)
    low = text.lower()
    tags = []
    api_map = [
        ('writeprocessmemory', 'memory_write'),
        ('ntwritevirtualmemory', 'memory_write'),
        ('virtualprotect', 'memory_protect'),
        ('virtualallocex', 'memory_allocate'),
        ('virtualalloc', 'memory_allocate'),
        ('createremotethread', 'thread_execution'),
        ('ntcreatethreadex', 'thread_execution'),
        ('queueuserapc', 'apc_injection'),
        ('setwindowshookex', 'hooking_api'),
        ('getprocaddress', 'dynamic_api_resolution'),
        ('loadlibrary', 'dynamic_library_load'),
        ('urldownloadtofile', 'network_download'),
        ('winhttpopen', 'network_activity'),
        ('internetopen', 'network_activity'),
        ('cryptunprotectdata', 'credential_access'),
        ('lsass', 'credential_access'),
    ]
    for needle, tag in api_map:
        if needle in low:
            tags.append(tag)
    tag_set = set(tags)
    if 'memory_write' in tag_set and ('thread_execution' in tag_set or 'apc_injection' in tag_set):
        tags.append('process_injection')
    if 'memory_allocate' in tag_set and 'memory_protect' in tag_set and 'memory_write' in tag_set:
        tags.append('shellcode_staging')
    return {'tags': tags, 'strings_blob': text[:_SCANNER_LIMITS_POLICY.raw_chunk_strings_blob_max_chars]}


def pure_pe_chunk(request: ContextualRawChunkRequest) -> object:
    """Scanner-owned chunk-level raw PE/string evidence collector."""
    text = request.read_range_text_func(request.path, start=request.start, size=request.size)
    low = text.lower()
    tags = []
    if 'this program cannot be run in dos mode' in low:
        tags.append('pe_file')
    if 'mscoree.dll' in low or '_cor_exe_main' in low or '_cor_dll_main' in low:
        tags += ['dotnet', 'dotnet_pe']
    if 'assembly-csharp' in low:
        tags += ['unity_managed', 'assembly_csharp']
    if 'package.json' in low and ('www/js' in low or 'rpg' in low):
        tags += ['rpgm_package_reference', 'rpgm_game_exe']
    tags.extend(_contextual_chunk_tags(
        low, path=request.path, source='global_raw_chunk', collector='pe_api_chunk', start=request.start,
        should_context_scan_func=request.should_context_scan_func,
        contextual_scan=request.contextual_scan,
        context_failure=lambda _current, collector, exc, *, path=None, start=0: request.context_failure(tags, collector, exc, path=path, start=start),
    ))
    return {'tags': tags, 'strings_blob': text[:_SCANNER_LIMITS_POLICY.raw_chunk_strings_blob_max_chars]}



__all__ = (
    'BytecodeChunkRequest',
    'ContextualRawChunkRequest',
    'bytecode_chunk',
    'dotnet_chunk',
    'pe_api_chunk',
    'pure_pe_chunk',
)
