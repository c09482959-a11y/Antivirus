"""Canonical contextual command, LOLBin, and download rule ownership."""

from Virus_Scan.detection.contracts.string_predicates import context_any, context_regex
from Virus_Scan.detection.tags.heuristics.network_intent import classify_network_intent_tags


def _append_process_shell_tags(
    blob: object,
    tags: list[str],
    *,
    has_cmd: object,
    has_ps_encoded: object,
    has_ps_exec_context: object,
) -> None:
    if has_ps_exec_context or has_ps_encoded:
        tags.extend(['powershell_exec', 'process_exec'])
    if has_ps_encoded:
        tags.extend(['encoded_powershell', 'encoded_powershell'])
    if has_cmd and context_regex('\\bcmd(?:\\.exe)?\\s*(?:/c|/k)\\b', blob):
        tags.extend(['cmd_exec', 'process_exec'])
    if context_regex('\\b(?:createprocess|shellexecute|winexec)\\b', blob):
        tags.append('process_exec')


def _append_script_lolbin_execution_tags(blob: object, tags: list[str]) -> None:
    if context_regex('\\bcscript(?:\\.exe)?\\b', blob) and context_regex('\\.(?:vbs|vbe|js|jse|wsf)\\b|//e:', blob):
        tags.extend(['cscript_exec', 'script_execution'])
    if context_regex('\\bmshta(?:\\.exe)?\\b', blob) and context_regex('https?://|javascript:|vbscript:|\\.hta\\b', blob):
        tags.extend(['mshta_exec', 'script_execution', 'fileless_execution'])
    if context_regex('\\brundll32(?:\\.exe)?\\b', blob) and context_regex('javascript:|mshtml|url\\.dll,fileprotocolhandler|comsvcs\\.dll|\\bminidump\\b|https?://', blob):
        tags.append('rundll32_exec')
    if context_regex('\\bregsvr32(?:\\.exe)?\\b', blob) and context_regex('scrobj\\.dll|/i:https?://|https?://', blob):
        tags.extend(['regsvr32_exec', 'script_execution', 'fileless_execution'])


def _append_certutil_tags(blob: object, tags: list[str], *, has_url: object) -> None:
    if not context_regex('\\bcertutil(?:\\.exe)?\\b', blob):
        return
    tags.append('certutil_exec')
    if has_url and context_regex('(?:-|/)urlcache|(?:-|/)split|(?:\\s|^)(?:-|/)f(?:\\s|$)', blob):
        tags.extend(['network_download', 'lolbin_download', 'payload_decode_candidate', 'process_exec'])
    if context_regex('(?:-|/)decode(?:hex)?\\b|frombase64string', blob):
        tags.extend(['payload_decode_candidate', 'certutil_decode', 'payload_decode'])


def _append_transfer_lolbin_tags(blob: object, tags: list[str], *, has_url: object) -> None:
    if context_regex('\\bbitsadmin(?:\\.exe)?\\b', blob) and (context_regex('/(?:transfer|create|addfile|resume)\\b', blob) or has_url):
        tags.extend(['bitsadmin_exec', 'background_transfer', 'network_download', 'lolbin_download'])
    if context_regex('\\b(?:curl|wget)(?:\\.exe)?\\b', blob) and has_url and context_regex('\\.(?:exe|dll|ps1|bat|cmd|hta|vbs|js)\\b|\\|\\s*(?:sh|bash|powershell)', blob):
        tags.extend(['network_download', 'process_exec', 'lolbin_download'])


def _append_network_activity_tags(
    blob: object,
    tags: list[str],
    *,
    existing_tags: object,
    has_url: object,
) -> None:
    tags.extend(classify_network_intent_tags(blob, has_url=has_url))
    if has_url and context_any(blob, ['downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr ', 'urlopen', 'internetopenurl', 'winhttpopenrequest', 'urldownloadtofile']):
        if context_any(blob, ['powershell', 'invoke-webrequest', 'iwr ', 'curl', 'wget', 'certutil', 'bitsadmin', 'start-process', 'subprocess', 'os.system', 'createprocess', 'shellexecute']) or context_regex('\\.(?:exe|dll|ps1|bat|cmd|hta|vbs|js|scr|msi|jar)\\b', blob):
            tags.extend(['network_activity', 'remote_payload_download', 'network_download'])
        else:
            tags.append('network_activity')
    elif has_url and 'asset_resource_fetch' not in {str(t).lower() for t in existing_tags} and context_any(blob, ['webhook', 'upload', 'post ', 'put ', 'telegram', 'discord']):
        tags.append('network_activity')


def _append_powershell_download_chain_tags(
    blob: object,
    tags: list[str],
    *,
    has_powershell: object,
) -> None:
    if has_powershell and context_any(blob, ['downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr ', 'webclient']) and context_any(blob, ['iex', 'invoke-expression', 'frombase64string', '-enc', 'encodedcommand']):
        tags.extend(['powershell_exec', 'network_download', 'fileless_execution', 'process_exec'])
        if context_any(blob, ['-enc', 'encodedcommand', 'frombase64string']):
            tags.extend(['encoded_powershell', 'encoded_powershell', 'payload_decode_candidate'])


def collect_command_execution_tags(blob: object, *, existing_tags: object=()) -> object:
    """Return process, script, LOLBin, and network-download tags from contextual anchors."""
    tags: list[str] = []
    has_powershell = context_regex('\\b(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b', blob)
    has_cmd = context_regex('\\bcmd(?:\\.exe)?\\b', blob)
    has_url = context_regex('\\b(?:https?|ftp)://', blob)
    has_ps_encoded = has_powershell and context_regex('(?:^|[\\s\'\"`])-(?:e|enc|encodedcommand)\\b|\\bencodedcommand\\b', blob)
    has_ps_exec_context = has_powershell and context_any(blob, [' -command', ' -c ', ' -nop', ' -noprofile', ' -w hidden', 'iex', 'invoke-expression', 'downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr ', 'start-process', 'frombase64string'])
    _append_process_shell_tags(
        blob,
        tags,
        has_cmd=has_cmd,
        has_ps_encoded=has_ps_encoded,
        has_ps_exec_context=has_ps_exec_context,
    )
    _append_script_lolbin_execution_tags(blob, tags)
    _append_certutil_tags(blob, tags, has_url=has_url)
    _append_transfer_lolbin_tags(blob, tags, has_url=has_url)
    _append_network_activity_tags(blob, tags, existing_tags=existing_tags, has_url=has_url)
    _append_powershell_download_chain_tags(blob, tags, has_powershell=has_powershell)
    return tags


def command_context_flags(blob: object) -> object:
    """Return contextual command booleans shared by neighboring rule owners."""
    return {
        'has_powershell': context_regex('\\b(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b', blob),
        'has_url': context_regex('\\b(?:https?|ftp)://', blob),
    }
