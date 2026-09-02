"""Canonical RPGM JavaScript pseudo-AST token scanner ownership."""

import re
from pathlib import Path

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.enrichment.strings.contextual import js_execution_model
from Virus_Scan.detection.enrichment.strings.boundaries import enrichment_sequence
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import scan_strings
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags


PLR2004N2 = 2


def scan_rpgm_js_pseudo_ast(path: object, *, finalize: object=True) -> object:
    """Pure-Python RPG Maker MV/MZ JS pseudo-AST/token scanner for www/js and plugins."""
    tags = []
    try:
        p = Path(path)
        if p.suffix.lower() != '.js':
            return []
        text = p.read_text(encoding='utf-8', errors='ignore')
        low = text.lower()
        norm_path = str(p).replace('\\', '/').lower()
        if '/www/js/' in norm_path or '/js/plugins/' in norm_path or p.name.lower().endswith('.js'):
            tags.append('javascript_file')
        if '/www/js/plugins/' in norm_path or '/plugins/' in norm_path:
            tags.extend(['rpgm_plugin_js', 'rpgm_javascript'])
        if any((x in low for x in ['rpg_core', 'rpg_managers', 'rpgmaker', 'window.rpgmaker'])):
            tags.extend(['rpgm_javascript', 'rpgm_core_reference'])
        for tag, pat in _RPGM_JS_CALL_PATTERNS:
            if re.search(pat, low):
                tags.append(tag)
        if 'require(' in low and any((x in low for x in ['child_process', 'powershell', 'cmd.exe', 'wscript', 'cscript'])):
            tags.extend(['nodejs_native_bridge', 'process_exec', 'script_execution'])
        if 'eval' in low and any((x in low for x in ['atob', 'fromcharcode', 'base64', 'unescape'])):
            tags.extend(['payload_decode_candidate', 'script_execution', 'dynamic_execution', 'obfuscated_javascript'])
        if any((x in low for x in ['savefileinfo', 'datamanager', 'storagemanager'])):
            tags.append('rpgm_storage_reference')
        if len(re.findall('[A-Za-z0-9+/]{120,}={0,2}', text)) >= PLR2004N2:
            tags.extend(['embedded_base64_payload', 'encoded_payload_candidate'])
        tags.extend(_scan_embedded_string_tags(low, path))
        tags.extend(_scan_embedded_js_model_tags(text, path))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        tags.extend(['rpgm_js_pseudo_ast_error', 'rpgm_js_failure_evidence', 'detection_stage_degraded'])
    if finalize:
        return normalize_tags(tags)
    return list(tags)


def _scan_embedded_string_tags(low: object, path: object) -> object:
    try:
        return list(enrichment_sequence(scan_strings(low, path=path, finalize=False)))
    except TypeError:
        return list(enrichment_sequence(scan_strings(low, path=path)))


def _scan_embedded_js_model_tags(text: object, path: object) -> object:
    try:
        return list(enrichment_sequence(js_execution_model.umige_js_execution_model_tags(text, path=path, finalize=False)))
    except TypeError:
        return list(enrichment_sequence(js_execution_model.umige_js_execution_model_tags(text, path=path)))


_RPGM_JS_CALL_PATTERNS = (
    ('eval_usage', '\\beval\\s*\\('),
    ('dynamic_function', '\\bfunction\\s*\\('),
    ('dynamic_code_generation', '\\bnew\\s+function\\s*\\('),
    ('node_require', '\\brequire\\s*\\('),
    ('child_process_reference', 'child_process'),
    ('process_exec', '\\.(exec|execfile|spawn|fork)\\s*\\('),
    ('filesystem_access', '\\bfs\\s*=\\s*require\\s*\\(|require\\s*\\(\\s*[\'\\"]fs[\'\\"]'),
    ('network_activity', '\\bhttps?\\s*=\\s*require\\s*\\(|xmlhttprequest|fetch\\s*\\('),
    ('websocket_activity', 'websocket\\s*\\('),
    ('delayed_execution', 'settimeout\\s*\\(|setinterval\\s*\\('),
    ('base64_decode', 'atob\\s*\\(|buffer\\.from\\s*\\([^\\)]*base64'),
    ('encoded_payload_candidate', 'fromcharcode\\s*\\(|charcodeat\\s*\\('),
    ('browser_storage_access', 'localstorage|sessionstorage|indexeddb'),
    ('external_script_load', 'createscript|createelement\\s*\\(\\s*[\'\\"]script'),
)
