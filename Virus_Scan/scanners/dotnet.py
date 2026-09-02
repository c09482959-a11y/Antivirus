from __future__ import annotations


from Virus_Scan.scanners.config.loader import load_binary_policy_snapshot

_BINARY_POLICY = load_binary_policy_snapshot()
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import log_error, read_file_bytes
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.contracts.result_record import degraded_scan_integrity, scanner_degraded_tags
from Virus_Scan.scanners.il_pipeline import analyze_il_pipeline, extract_il_patterns
from Virus_Scan.scanners.ilspy import scan_unity_ilspy_file, unity_ilspy_should_run
from Virus_Scan.scanners.binary_path_identity import binary_path_text
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join, scanner_contract_lower_token
from Virus_Scan.scanners.dotnet_identity import (
    DOTNET_EXTENSIONS,
    dotnet_metadata_present,
    dotnet_behavior_tags,
    dotnet_extension_tags,
)

def scan_unity_dotnet_layered_file(path: object, base_tags: object = None, finalize: object = True, include_dotnet_strings: object = True, *, read_bytes: object = read_file_bytes, get_extension: object = get_scan_extension, logger: object = log_error, ilspy_scanner: object = scan_unity_ilspy_file) -> object:
    """Canonical .NET/Unity managed binary scanner.

    The scanner is driven by CLR metadata, not by declared extension alone, so
    renamed Unity/.NET artifacts such as .bytes, .dat, .bin, and .asset enter
    the same owned analysis path as .dll/.exe files.  Failures are reported as
    degraded scanner evidence rather than converted to clean results.
    """
    del include_dotnet_strings  # Explicitly unused contract parameters.
    tags: list[str] = []
    meta: dict[str, object] = {'is_dotnet': False, 'ilspy_used': False, 'dncil_used': False}
    try:
        ext = get_extension(path)
        if ext not in DOTNET_EXTENSIONS:
            meta['reason'] = 'extension_not_dotnet_candidate'
            return ([], meta)
        raw = read_bytes(path, max_size=_BINARY_POLICY.dotnet_read_max_bytes)
        strings_blob = raw.decode('latin1', errors='ignore')
        meta['is_dotnet'] = dotnet_metadata_present(strings_blob)
        if not meta['is_dotnet']:
            meta['reason'] = 'clr_metadata_not_found'
            return ([], meta)

        tags += ['dotnet', 'dotnet_pe', 'unity_dotnet_candidate']
        tags += dotnet_extension_tags(ext)
        tags += dotnet_behavior_tags(strings_blob)
        if 'assembly-csharp' in strings_blob.lower() or 'unityengine' in strings_blob.lower():
            tags += ['unity_managed', 'assembly_csharp']

        ilspy_gate_tags = set(normalize_tags(list(base_tags or []) + tags))
        ilspy_trigger_tags = {
            'packed_or_obfuscated', 'high_entropy_section', 'very_high_entropy',
            'process_exec', 'network_download', 'memory_write', 'thread_execution',
            'powershell_exec', 'cmd_exec', 'script_execution', 'extension_mismatch',
            'unity_managed', 'unity_dotnet_candidate', 'assembly_csharp',
        }
        should_ilspy = bool(ilspy_gate_tags & ilspy_trigger_tags)
        meta['ilspy_gate'] = 'enabled' if should_ilspy else 'skipped_fast_metadata_sufficient'
        if should_ilspy:
            ilspy_tags, ilspy_meta = ilspy_scanner(path, base_tags=base_tags or tags)
            meta.update(ilspy_meta or {})
            tags.extend(ilspy_tags or [])
            if ilspy_tags:
                meta['ilspy_used'] = True

        il_ops = extract_il_patterns(strings_blob)
        if il_ops:
            meta['dncil_used'] = True
            meta['dncil_ops'] = il_ops[:_BINARY_POLICY.dotnet_il_op_limit]
            tags.append('pseudo_dncil_il_scan')
            for op in il_ops[:_BINARY_POLICY.dotnet_il_op_limit]:
                tags.append(scanner_contract_join('il_op_', scanner_contract_lower_token(op, replacement='unknown')))
            path_text = binary_path_text(path)
            il_result = analyze_il_pipeline(path_text, tags, strings_blob=strings_blob, file_structure=path_text)
            meta['dncil_result'] = il_result
            if il_result.get('obfuscation_score', 0) > _BINARY_POLICY.dotnet_il_obfuscation_threshold:
                tags += ['dotnet_obfuscated_or_packed', 'packed_or_obfuscated']
            if il_result.get('il_score', 0) > _BINARY_POLICY.dotnet_il_behavior_threshold:
                tags.append('il_behavior_signal')
    except SCAN_CONTENT_ERRORS as e:
        logger(scanner_contract_join('scan_unity_dotnet_layered_file failed path=', binary_path_text(path), ' error=', scanner_contract_error_message(e)))
        tags = scanner_degraded_tags([*tags, 'unity_dotnet_layered_scan_error'])
        meta['scan_integrity'] = degraded_scan_integrity(e, scanner='dotnet_layered')
    if finalize:
        return (normalize_tags(tags), meta)
    return (list(tags or []), meta)



__all__ = (
    'scan_unity_dotnet_layered_file',
    'scan_unity_ilspy_file',
    'unity_ilspy_should_run',
)
