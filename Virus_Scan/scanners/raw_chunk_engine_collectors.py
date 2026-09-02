"""Raw chunk scanner collectors for Unity/.NET and IL2CPP evidence."""
from __future__ import annotations

from pathlib import PurePath

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scanners.contracts import scanner_contract_nonnegative_int, scanner_contract_text, scanner_failure_evidence_tags
from Virus_Scan.scanners.raw_chunk_core import _SCANNER_LIMITS_POLICY, _contextual_chunk_tags


PLR2004N0_2 = 0.2
PLR2004N0_3 = 0.3
PLR2004N7_5 = 7.5


def _raw_chunk_path_text(path: object) -> object:
    if path is None:
        return ''
    if isinstance(path, PurePath):
        return PurePath.__str__(path)
    text, reason = no_hook_text(
        path,
        missing_reason='missing_raw_chunk_path',
        unsupported_reason='unsafe_raw_chunk_path_rejected',
    )
    if reason:
        return 'raw_chunk_path_probe_error'
    return text


def _raw_chunk_start(value: object) -> object:
    return scanner_contract_nonnegative_int(value, replacement=0)

def il2cpp_chunk(path: object, *, start: object = 0, size: object = None, read_range_text_func: object, runtime_value: object, detect_unity_runtime_behavior: object, byte_entropy: object, report: object, recoverable_exceptions: object) -> object:
    """Scanner-owned chunk-level IL2CPP / IL signature collector."""
    text = read_range_text_func(path, start=start, size=size)
    low_text = text.lower()
    low = low_text.encode('latin1', errors='ignore')
    tags = []
    if 'global-metadata.dat' in low_text:
        tags.append('il2cpp_metadata_ref')
    if 'il2cpp' in low_text:
        tags.append('il2cpp_binary')
    if 'assembly-csharp' in low_text:
        tags.append('il2cpp_strings')
    il_sigs = runtime_value('IL_SIGNATURES', {
        'IL_REFLECTION': b'GetMethod', 'IL_INVOKE': b'Invoke', 'IL_BASE64': b'FromBase64String',
        'IL_PROCESS': b'Process.Start', 'IL_ASSEMBLY': b'Assembly.Load',
    })
    for key, sig in no_hook_mapping_items(il_sigs, allow_dict_subclass=True) or ():
        try:
            if sig.lower() in low:
                tags.append(scanner_contract_text(key, replacement='IL_SIGNATURE'))
        except (AttributeError, TypeError) as exc:
            report('raw_il2cpp_signature_probe_failed', exc)
    try:
        tags.extend(detect_unity_runtime_behavior(text) or [])
    except recoverable_exceptions as exc:
        report('monitor_loop_suppressed', exc)
    try:
        if byte_entropy(low) > PLR2004N7_5 and any(tag in tags for tag in ('IL_REFLECTION', 'IL_INVOKE', 'IL_ASSEMBLY')):
            tags.append('likely_packed')
    except (TypeError, ValueError) as exc:
        report('raw_il2cpp_entropy_probe_failed', exc)
    return {'tags': tags, 'strings_blob': text[:_SCANNER_LIMITS_POLICY.raw_chunk_strings_blob_max_chars]}

def unity_dotnet_chunk(path: object, *, start: object = 0, size: object = None, read_range_text_func: object, extract_il_patterns: object, analyze_il_pipeline: object, should_context_scan_func: object, contextual_scan: object, context_failure: object, report_issue: object) -> object:
    """Scanner-owned raw chunk-level Unity/.NET IL-pattern collector."""
    text = read_range_text_func(path, start=start, size=size)
    low = text.lower()
    tags = []
    if any(marker in low for marker in ('assembly-csharp', 'unityengine', 'unityscript', 'monobehaviour')):
        tags += ['unity_managed', 'unity_dotnet_candidate']
    if extract_il_patterns is not None:
        try:
            il_ops = extract_il_patterns(text) or []
        except (OSError, RuntimeError, TypeError, ValueError, UnicodeError) as exc:
            report_issue(
                'raw_unity_dotnet_il_extract_failed',
                exc,
                fatal=False,
                extra={'path': _raw_chunk_path_text(path), 'start': _raw_chunk_start(start), 'collector': 'unity_dotnet_chunk'},
            )
            tags.extend(scanner_failure_evidence_tags(
                'binary',
                'unity_dotnet_il_extract',
                exc,
                ['raw_unity_dotnet_il_extract_failed'],
                input_path=path,
                state='degraded',
                error_category='il_pattern_extract_failure',
                file_type='unity_dotnet_chunk',
            ))
            il_ops = list()
        if il_ops:
            tags.append('pseudo_dncil_il_scan')
            for op in il_ops[:64]:
                tags.append('il_op_' + str(op).lower())
            if analyze_il_pipeline is not None:
                try:
                    il_result = analyze_il_pipeline(str(path), tags, strings_blob=text, file_structure=None) or {}
                    if il_result.get('obfuscation_score', 0) > PLR2004N0_3:
                        tags += ['dotnet_obfuscated_or_packed', 'packed_or_obfuscated']
                    if il_result.get('il_score', 0) > PLR2004N0_2:
                        tags.append('il_behavior_signal')
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    report_issue(
                        'raw_unity_dotnet_il_pipeline_failed',
                        exc,
                        fatal=False,
                        extra={'path': _raw_chunk_path_text(path), 'start': _raw_chunk_start(start), 'collector': 'unity_dotnet_chunk'},
                    )
                    tags.extend(scanner_failure_evidence_tags(
                        'binary',
                        'unity_dotnet_il_pipeline',
                        exc,
                        ['raw_unity_dotnet_il_pipeline_failed'],
                        input_path=path,
                        state='degraded',
                        error_category='il_pipeline_failure',
                        file_type='unity_dotnet_chunk',
                    ))
    tags.extend(_contextual_chunk_tags(
        low, path=path, source='global_raw_chunk', collector='unity_dotnet_chunk', start=start,
        should_context_scan_func=should_context_scan_func,
        contextual_scan=contextual_scan,
        context_failure=lambda _current, collector, exc, *, path=None, start=0: context_failure(tags, collector, exc, path=path, start=start),
    ))
    return {'tags': tags, 'strings_blob': text[:_SCANNER_LIMITS_POLICY.raw_chunk_strings_blob_max_chars]}

__all__ = (
    "il2cpp_chunk",
    "unity_dotnet_chunk",
)
