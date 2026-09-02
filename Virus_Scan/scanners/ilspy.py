from __future__ import annotations


from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.contracts.result_record import degraded_scan_integrity, scanner_degraded_tags
from Virus_Scan.scanners.engine_context import infer_engine_context
from Virus_Scan.runtime.api import read_file_bytes
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.scanners.dotnet_identity import DOTNET_EXTENSIONS, dotnet_metadata_present
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scanners.contracts import scanner_contract_bool, scanner_failure_evidence_record
from Virus_Scan.scanners.config.loader import load_engine_policy_snapshot

_ENGINE_POLICY = load_engine_policy_snapshot()
USE_ILSPY = _ENGINE_POLICY.use_ilspy

def scan_unity_ilspy_file(path: object, base_tags: object = None, *, read_bytes: object = read_file_bytes, get_extension: object = get_scan_extension, metadata_detector: object = dotnet_metadata_present, engine_context_inferer: object = infer_engine_context, use_ilspy: bool | None = None) -> object:
    """Canonical ILSpy diagnostic gate for CLR candidates.

    External ILSpy execution is only allowed after explicit CLR metadata proof.
    Missing or disabled ILSpy is returned as diagnostic metadata, never as a clean
    scanner result.
    """
    try:
        raw = read_bytes(path, max_size=512000)
        blob = raw.decode('latin1', errors='ignore')
    except SCAN_CONTENT_ERRORS as e:
        return (
            scanner_degraded_tags(['ilspy_preread_error']),
            {'ilspy_used': False, 'reason': 'preread_failed', 'scan_integrity': degraded_scan_integrity(e, scanner='ilspy')},
        )
    safe_base_tags = base_tags if type(base_tags) is list else []
    should, ctx = unity_ilspy_should_run(path, tags=safe_base_tags, strings_blob=blob, read_bytes=read_bytes, get_extension=get_extension, metadata_detector=metadata_detector, engine_context_inferer=engine_context_inferer, use_ilspy=use_ilspy)
    if not should:
        return [], {'ilspy_used': False, 'reason': 'not_dotnet_or_not_enabled', 'engine_context': ctx, 'diagnostic_reason': ctx.get('reason', 'not_dotnet_or_not_enabled')}
    return ([], {'ilspy_used': False, 'engine_context': ctx, 'reason': 'external_ilspy_runner_not_configured'})

def unity_ilspy_should_run(path: object, tags: object = None, strings_blob: object = '', *, read_bytes: object = read_file_bytes, get_extension: object = get_scan_extension, metadata_detector: object = dotnet_metadata_present, engine_context_inferer: object = infer_engine_context, use_ilspy: bool | None = None) -> object:
    """Return True only for proved .NET candidates when ILSpy execution is enabled."""
    ext = get_extension(path)
    if ext not in DOTNET_EXTENSIONS:
        return (False, {'reason': 'not_dotnet_candidate_extension'})
    try:
        raw = read_bytes(path, max_size=512000)
    except SCAN_CONTENT_ERRORS as e:
        return (False, {'is_dotnet': False, 'reason': 'preread_failed', 'scan_integrity': degraded_scan_integrity(e, scanner='ilspy_gate')})
    blob = strings_blob if type(strings_blob) is str and strings_blob else raw.decode('latin1', errors='ignore')
    is_dotnet = metadata_detector(blob)
    if not is_dotnet:
        return (False, {'is_dotnet': False, 'reason': 'clr_metadata_not_found'})
    try:
        safe_tags = tags if type(tags) is list else []
        ctx = engine_context_inferer(safe_tags, file_structure=path, strings_blob=blob)
    except SCAN_CONTENT_ERRORS as e:
        evidence = scanner_failure_evidence_record(
            'ilspy',
            'engine_context',
            e,
            input_path=path,
            state='degraded',
            error_category='engine_context_failure',
            error_source='ilspy.unity_ilspy_should_run',
            file_type='dotnet',
        )
        failed_ctx: dict[str, object] = {
            'reason': 'engine_context_failed',
            'scan_integrity': degraded_scan_integrity(
                e,
                scanner='ilspy_gate',
                scanner_stage='engine_context',
                scanner_failure_evidence=evidence,
                final_json_must_record=True,
            ),
            'scanner_failure_evidence': evidence,
        }
        ctx = failed_ctx
    ctx_items = no_hook_mapping_items(ctx)
    if ctx_items is None:
        ctx_map: dict[str, object] = {'reason': 'engine_context_unsupported'}
    else:
        ctx_map = {key: value for key, value in ctx_items if type(key) is str}
    ctx_map['is_dotnet'] = True
    enabled = USE_ILSPY if use_ilspy is None else scanner_contract_bool(use_ilspy, replacement=False)
    if not enabled:
        ctx_map['reason'] = 'ilspy_disabled'
        return (False, ctx_map)
    return (True, ctx_map)

__all__ = ('USE_ILSPY', 'scan_unity_ilspy_file', 'unity_ilspy_should_run')
