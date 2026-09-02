"""Scanner-owned contextual text tag extraction.

This module owns lightweight contextual tag projection for scanner text, raw
chunk, string, and pickle-fragment paths. It intentionally avoids importing
private detection enrichment modules so scanner contextual evidence is bounded
inside scanner ownership.
"""

import re

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.contracts import scanner_contract_join
from Virus_Scan.utils.tagging import normalize_tags


def _contextual_reason(prefix: object, field: object) -> object:
    field_text, field_reason = no_hook_text(
        field,
        missing_reason='missing_contextual_reason_field',
        unsupported_reason='unsafe_contextual_reason_field_rejected',
    )
    return scanner_contract_join(prefix, '' if field_reason else field_text)


def _contextual_exact_text(value: object, *, field: object) -> object:
    if value is None:
        return '', ''
    text, reason = no_hook_text(
        value,
        missing_reason=_contextual_reason('missing_', field),
        unsupported_reason=_contextual_reason('unsafe_', _contextual_reason('', field) + '_rejected'),
    )
    return text, reason


def _contextual_failure_tags(*reasons: object) -> object:
    tags = ['scanner_failure_evidence_recorded', 'scanner_failure_evidence:text:contextual_tag_scan']
    tags.extend(str.__str__(reason) for reason in reasons if type(reason) is str and reason)
    return normalize_tags(tags)


def _has(text: object, *needles: object) -> object:
    text_value, text_reason = _contextual_exact_text(text, field='contextual_probe_text')
    if text_reason:
        return False
    low = text_value.lower()
    for needle in needles:
        if type(needle) is not str:
            continue
        if str.__str__(needle).lower() in low:
            return True
    return False


def _rx(text: object, pattern: object) -> object:
    text_value, text_reason = _contextual_exact_text(text, field='contextual_regex_text')
    if text_reason or type(pattern) is not str:
        return False
    return re.search(pattern, text_value, re.IGNORECASE) is not None


def _add_command_execution(tags: object, text: object) -> object:
    if _has(text, 'powershell'):
        tags.extend(['powershell_exec', 'script_execution'])
        if _has(text, '-enc', 'encodedcommand'):
            tags.append('encoded_powershell')
    if _has(text, 'cmd.exe'):
        tags.extend(['cmd_exec', 'script_execution'])
    if _has(text, 'regsvr32'):
        tags.extend(['regsvr32_exec', 'script_execution'])
    if _has(text, 'rundll32'):
        tags.extend(['rundll32_exec', 'script_execution'])
    if _has(text, 'mshta'):
        tags.extend(['mshta_exec', 'script_execution'])
    if _rx(text, r'\bos\.system\s*\(') or _has(text, 'subprocess.', 'popen(', 'createprocess', 'shellexecute', 'winexec'):
        tags.extend(['process_exec', 'script_execution'])
    if 'process_exec' in tags and _has(text, 'powershell', 'cmd.exe', 'curl', 'wget', 'http://', 'https://', 'discord', 'telegram', 'token', 'appdata', 'startup'):
        tags.extend(['script_execution', 'process_exec'])


def _add_javascript_chains(tags: object, text: object, path_text: object) -> object:
    is_rpgm = _has(path_text, 'www/js/plugins', 'rpgm') or _has(text, 'rpg_core', 'rpg_managers', 'rpgmaker')
    if _has(text, 'atob(') and _rx(text, r'\beval\s*\('):
        tags.extend(['payload_decode_candidate', 'script_execution', 'dynamic_execution', 'payload_execution', 'obfuscated_javascript'])
    if _has(text, 'xmlhttprequest', 'xhr.open', 'fetch(') and _has(text, 'http://', 'https://') and _rx(text, r'\beval\s*\('):
        tags.extend(['network_download', 'remote_payload_download', 'script_execution', 'payload_execution'])
        if is_rpgm:
            tags.append('rpgm_js_network_exec_candidate')
    if is_rpgm and _has(text, "require('fs')", 'require("fs")', 'fs.readfilesync') and _has(text, 'login data', 'local state', 'discord'):
        tags.extend(['rpgm_nwjs_credential_stealer', 'browser_credential_access'])
    if is_rpgm and _has(text, 'localstorage', 'sessionstorage', 'document.cookie') and _has(text, 'fetch(', 'xmlhttprequest', 'requests.post', 'webhook'):
        tags.extend(['rpgm_browser_storage_exfil', 'browser_storage_access'])


def _add_native_api_chains(tags: object, text: object, path_text: object) -> object:
    has_alloc = _has(text, 'virtualalloc', 'virtualallocex')
    has_thread = _has(text, 'createremotethread', 'ntcreatethreadex', 'queueuserapc')
    has_write = _has(text, 'writeprocessmemory', 'ntwritevirtualmemory')
    if has_alloc and has_thread:
        tags.extend(['memory_allocate', 'memory_write', 'thread_execution', 'process_injection'])
    if has_write:
        tags.append('memory_write')
    if _has(path_text, 'assets/scripts', 'unity') and has_alloc and has_thread:
        tags.append('unity_process_injection')


def _add_credential_exfil(tags: object, text: object, path_text: object) -> object:
    has_secret = _has(text, 'discord token', 'authorization', 'access_token', 'refresh_token', 'login data', 'cookies.sqlite', 'local state', 'document.cookie', 'token')
    has_upload = _has(text, 'webhook', 'discord.com/api/webhooks', 'api.telegram.org', 'requests.post', 'fetch(', 'xmlhttprequest', 'socket.send', '/upload')
    if has_secret:
        tags.extend(['credential_access', 'token_secret_access'])
    if has_secret and has_upload:
        tags.extend(['token_exfiltration', 'network_exfiltration', 'high_confidence_credential_theft'])
    if _has(path_text, 'assets/scripts', 'unity') and has_secret and has_upload:
        tags.append('unity_token_stealer')


def _add_engine_specific(tags: object, text: object, path_text: object) -> object:
    if _has(path_text, 'game/') or _has(path_text, '.rpy'):
        if _has(text, 'persistent.') and _has(text, 'startup', 'autostart', 'run.ps1') and _has(text, 'powershell', 'os.system'):
            tags.extend(['persistence', 'dropper_behavior', 'startup_persistence', 'process_exec', 'script_execution'])
        if _has(text, 'socket.socket', '.connect(', 's.recv', 'os.system', 's.send'):
            tags.extend(['network_activity', 'remote_command_channel', 'network_c2', 'process_exec', 'script_execution'])


def contextual_tag_scan(text: object, path: object = None, source: object = 'strings', *, finalize: object = True) -> object:
    """Return deterministic scanner-owned contextual tags for text-like input."""
    del finalize, source  # Explicitly unused contract parameters.
    blob, blob_reason = _contextual_exact_text(text, field='contextual_text')
    path_text, path_reason = _contextual_exact_text(path, field='contextual_path')
    if blob_reason:
        return _contextual_failure_tags(blob_reason)
    tags = []
    if path_reason:
        tags.extend(_contextual_failure_tags(path_reason))
    _add_command_execution(tags, blob)
    _add_javascript_chains(tags, blob, path_text)
    _add_native_api_chains(tags, blob, path_text)
    _add_credential_exfil(tags, blob, path_text)
    _add_engine_specific(tags, blob, path_text)
    if _has(blob, 'http://', 'https://'):
        tags.append('url_present')
    if _has(blob, 'downloadstring', 'downloadfile', 'urldownloadtofile', 'invoke-webrequest'):
        tags.append('network_download')
    if _has(blob, 'base64', 'frombase64string', 'atob('):
        tags.append('encoded_payload_candidate')
    return normalize_tags(tags)


__all__ = ('contextual_tag_scan',)
