"""Raw chunk scanner header collectors."""
from __future__ import annotations

from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.scanners.raw_chunk_core import _SCANNER_LIMITS_POLICY

def unity_dotnet_header(path: object, *, scan_unity_dotnet_layered_file: object) -> object:
    """Scanner-owned Unity/.NET header collector for raw queue execution."""
    try:
        tags, meta = scan_unity_dotnet_layered_file(path, base_tags=[], finalize=False, include_dotnet_strings=False)
        return {'tags': list(tags or []), 'meta': meta or {}}
    except TypeError:
        value = scan_unity_dotnet_layered_file(path, base_tags=[], finalize=False)
        if isinstance(value, tuple):
            return {'tags': list(value[0] or []), 'meta': value[1] if len(value) > 1 and isinstance(value[1], dict) else {}}
        return {'tags': list(value or []), 'meta': {}}

def dotnet_header(path: object, *, scan_dotnet_file: object) -> object:
    """Scanner-owned .NET header/metadata collector for raw queue execution."""
    try:
        tags, meta = scan_dotnet_file(path, finalize=False, include_strings=False)
        return {'tags': list(tags or []), 'meta': meta or {}}
    except TypeError:
        value = scan_dotnet_file(path, finalize=False)
        if isinstance(value, tuple):
            return {'tags': list(value[0] or []), 'meta': value[1] if len(value) > 1 and isinstance(value[1], dict) else {}}
        return {'tags': list(value or []), 'meta': {}}

def il2cpp_header(path: object, *, read_file_bytes: object) -> object:
    """Scanner-owned cheap IL2CPP header marker collector."""
    tags = []
    try:
        data = read_file_bytes(path, max_size=_SCANNER_LIMITS_POLICY.raw_chunk_text_probe_bytes)
    except (OSError, RuntimeError) as exc:
        tags.extend(scanner_failure_evidence_tags(
            'binary',
            'il2cpp_header_read',
            exc,
            ['raw_il2cpp_header_read_failed'],
            input_path=path,
            state='degraded',
            error_category='file_read_failure',
            file_type='il2cpp_header',
        ))
        return {'tags': tags}
    low = data.lower()
    if b'global-metadata.dat' in low:
        tags.append('il2cpp_metadata_ref')
    if b'il2cpp' in low:
        tags.append('il2cpp_binary')
    if b'assembly-csharp' in low:
        tags.append('il2cpp_strings')
    if b'MZ' in data[:_SCANNER_LIMITS_POLICY.raw_chunk_mz_probe_bytes]:
        tags.append('pe_file')
    return {'tags': tags}

__all__ = (
    "unity_dotnet_header",
    "dotnet_header",
    "il2cpp_header",
)
