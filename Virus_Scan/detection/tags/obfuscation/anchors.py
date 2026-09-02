import re

from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.contracts.string_predicates import context_any as _ctx_any
from Virus_Scan.detection.contracts.string_predicates import context_regex as _ctx_re
from Virus_Scan.detection.contracts.string_predicates import normalize_obfuscated_text as _umige_normalize_obfuscated_text
from Virus_Scan.detection.enrichment.strings.patterns import UMIGE_B64_LONG_RE
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage


def _append_obfuscated_execution_tags(text: object, tags: list[str]) -> None:
    if _ctx_re('\\b(?:powershell|pwsh)(?:\\.exe)?\\b', text) and _ctx_re('(?:^|[\\s\'\"`])-(?:e|enc|encodedcommand)\\b|\\bencodedcommand\\b', text):
        tags.extend(['powershell_exec', 'encoded_powershell', 'encoded_powershell', 'powershell_encoded', 'process_exec', 'shell_exec_abuse'])
    if _ctx_re('(?:subprocess\\s*\\.\\s*(?:popen|run|call)|getattr\\s*\\(\\s*subprocess\\s*,\\s*[\'\"](?:popen|run|call)[\'\"]|os\\s*\\.\\s*system|__import__\\s*\\(\\s*[\'\"]os[\'\"]\\s*\\)\\s*\\.\\s*system)', text):
        tags.extend(['process_exec', 'python_process_exec'])
    if _ctx_re('(?:eval|exec)\\s*\\(', text) and _ctx_any(text, ['base64', 'b64decode', 'zlib.decompress', 'marshal.loads', 'compile(', 'frombase64string']):
        tags.extend(['bytecode_eval', 'bytecode_exec', 'dynamic_execution', 'payload_execution'])


def _append_network_anchor_tags(text: object, tags: list[str]) -> None:
    public_ipish = bool(re.search('\\b(?!(?:10|127)\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[0-1])\\.|0\\.|255\\.)\\d{1,3}(?:\\.\\d{1,3}){3}\\b', text))
    network_socket_indicator = _ctx_any(
        text,
        ['socket.create_connection', 'socket.socket', 'connect_ex', 'urllib.request.urlopen', 'requests.post'],
    ) and (
        public_ipish
        or _ctx_any(text, ['cmd', 'command', 'task', 'shell', 'beacon', 'implant', 'token', 'credential'])
    )
    public_ip_beacon_indicator = public_ipish and _ctx_any(
        text,
        ['beacon', 'tasking', 'cmd=', 'reverse shell', 'implant'],
    )
    if network_socket_indicator or public_ip_beacon_indicator:
        tags.extend(['network_activity', 'c2_connection', 'c2_beacon'])


def _append_encoded_payload_tags(text: object, tags: list[str]) -> None:
    if 'tvqq' in text or re.search('(?:^|[^a-z0-9])t\\s*v\\s*q\\s*q(?:[^a-z0-9]|$)', text):
        tags.extend(['base64_detected', 'payload_decode_candidate', 'embedded_base64_payload', 'embedded_pe_payload', 'confirmed_embedded_pe_payload', 'payload_decode_confirmed'])
    if UMIGE_B64_LONG_RE.search(text):
        tags.extend(['base64_blob_detected', 'base64_detected', 'encoded_data_context', 'decoded_base64_blob'])
        if _ctx_any(text, ['base64.b64decode', 'frombase64string', 'zlib.decompress', 'marshal.loads']):
            tags.extend(['payload_decode_candidate'])
        if _ctx_any(text, ['exec(', 'eval(', 'subprocess', 'powershell', 'cmd.exe', 'assembly.load', 'virtualalloc']):
            tags.extend(['decoded_base64_script', 'payload_decode_candidate'])


def _append_endpoint_and_persistence_tags(text: object, tags: list[str]) -> None:
    if _ctx_any(text, ['discord.com/api/webhooks', 'discordapp.com/api/webhooks', 'api.telegram.org/bot', 'pastebin.com/raw', 'raw.githubusercontent.com']):
        tags.extend(['network_activity', 'suspicious_url_endpoint'])
        if _ctx_any(text, ['webhook', 'sendmessage', 'requests.post', 'token', 'credential', 'upload']):
            tags.extend(['http_upload', 'network_exfiltration'])
    if _ctx_re('\\bschtasks(?:\\.exe)?\\b', text) and _ctx_re('/(?:create|tn|tr|sc)\\b', text):
        tags.extend(['schtasks_create', 'scheduled_task_create', 'persistence'])
    if _ctx_any(text, ['currentversion\\run', 'software\\microsoft\\windows\\currentversion\\run', 'startup\\programs\\startup']):
        tags.extend(['run_key_mod', 'registry_persistence', 'persistence'])


def obfuscated_anchor_tags(blob: object, path: object=None) -> object:
    """Narrow canonical anchors for obfuscated updater/library malware."""
    text = _umige_normalize_obfuscated_text(blob)
    tags: list[str] = []
    try:
        _append_obfuscated_execution_tags(text, tags)
        _append_network_anchor_tags(text, tags)
        _append_encoded_payload_tags(text, tags)
        _append_endpoint_and_persistence_tags(text, tags)
    except RECOVERABLE_RUNTIME_ERRORS as error:
        tags.extend(failure_tags_for_stage('obfuscated_anchor_extraction', error, context=path))
    return sorted(set(tags))


__all__ = ('obfuscated_anchor_tags',)
