from Virus_Scan.runtime.api import (
    deep_scan_auto_enabled,
    deep_scan_thorough_enabled,
)
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.utils.stages import MEDIA_ASSET_EXTENSIONS, FONT_ASSET_EXTENSIONS
from Virus_Scan.utils.text_validation import text_boundary_value
from Virus_Scan.contracts.result_record import is_passive_fast_asset_result

def _deep_scan_asset_enrichment_limit(*, escalated: object=False) -> object:
    if deep_scan_thorough_enabled():
        return 8000000
    if deep_scan_auto_enabled() and escalated:
        return 5000000
    return 1000000

def _passive_asset_extension_text(ext: object) -> object:
    text = text_boundary_value(ext, unsupported=None)
    if type(text) is not str:
        return ''
    return str.__str__(text).strip().lower()


def _is_font_asset_extension(ext: object) -> object:
    return _passive_asset_extension_text(ext) in FONT_ASSET_EXTENSIONS


def _is_media_asset_extension(ext: object) -> object:
    return _passive_asset_extension_text(ext) in MEDIA_ASSET_EXTENSIONS

def _is_terminal_clean_asset_triage(tags: object, *, suspicious: object=False) -> object:
    """True when passive media/Unity asset validation found no reason to escalate."""
    t = set(normalize_tags(tags or []))
    if suspicious:
        return False
    blocking = {'asset_deep_scan_escalated', 'extension_mismatch', 'extension_magic_type_mismatch', 'embedded_script_marker', 'embedded_executable_marker', 'embedded_archive_marker', 'asset_embedded_script_marker', 'asset_embedded_executable_marker', 'asset_embedded_archive_marker', 'suspicious_media_asset', 'scan_router_error', 'binary_failover_scan', 'packed_or_obfuscated', 'high_entropy_packed', 'very_high_entropy', 'network_download', 'process_exec', 'powershell_exec', 'cmd_exec', 'script_execution', 'process_injection', 'credential_access'}
    if t & blocking:
        return False
    return bool(t & {'asset_fast_triage', 'unity_container_fast_triage_clean', 'media_asset', 'image_fast_triage_clean', 'font_fast_triage_clean', 'passive_asset_fast_triage_clean'})

def _umige_result_is_passive_fast_asset_result(res: object) -> object:
    """Return whether result is a passive fast asset result using the canonical result contract."""
    return is_passive_fast_asset_result(res)
