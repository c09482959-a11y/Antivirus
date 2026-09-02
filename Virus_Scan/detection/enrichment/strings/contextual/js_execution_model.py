"""Canonical RPGM/JavaScript execution-model contextual enrichment ownership."""

import re

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.contracts.string_predicates import normalize_obfuscated_text
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty


def umige_js_execution_model_tags(strings_blob: object, path: object=None, *, finalize: object=True) -> object:
    """RPGM/JS static execution model: pattern + decode, not a JS interpreter."""
    del finalize  # Explicitly unused contract parameters.
    tags = []
    try:
        blob = normalize_obfuscated_text(strings_blob)
        path_text = detection_enrichment_text_or_empty(path).lower()
        js_like = path_text.endswith('.js') or any((x in blob for x in ['rpgmaker', 'window.rpgmaker', 'plugins.js', 'nw.js', 'require(', 'eval(', 'function(']))
        if not js_like:
            return []
        if re.search('\\beval\\s*\\(', blob) and any((x in blob for x in ['atob', 'buffer.from', 'fromcharcode', 'unescape', 'base64'])):
            tags.extend(['payload_decode_candidate', 'script_execution', 'dynamic_execution', 'payload_execution'])
        if re.search('\\b(?:new\\s+)?function\\s*\\(', blob) and any((x in blob for x in ['atob', 'base64', 'fromcharcode', 'child_process', 'require('])):
            tags.extend(['js_dynamic_function_execution', 'dynamic_execution'])
        if 'require(' in blob and 'child_process' in blob and re.search('\\.(?:exec|spawn|execfile|fork)\\s*\\(', blob):
            tags.extend(['nodejs_native_bridge', 'process_exec', 'script_execution'])
        if any((x in blob for x in ['xmlhttprequest', 'fetch(', 'https.request', 'http.request', 'websocket('])) and any((x in blob for x in ['eval(', 'function(', 'child_process', 'atob'])):
            tags.extend(['network_activity', 'network_download', 'remote_payload_download', 'rpgm_js_network_exec_candidate', 'script_execution', 'payload_execution'])
        if any((x in blob for x in ['payload_decode_candidate', 'decoded_payload_rescanned', 'decoded_payload_observed', 'base64', 'atob', 'buffer.from', 'frombase64string'])):
            if any((x in blob for x in ['powershell', 'cmd.exe', 'child_process', 'socket', 'http://', 'https://'])):
                tags.extend(['decoded_payload_observed', 'js_decoded_payload_rescanned', 'evidence_link:decoded_payload_to_js_behavior', 'js_decoded_payload_execution_candidate', 'payload_decode_confirmed'])
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        tags.extend(failure_tags_for_stage('js_execution_model', e, context=path))
    return ordered_unique_tags(tags)
