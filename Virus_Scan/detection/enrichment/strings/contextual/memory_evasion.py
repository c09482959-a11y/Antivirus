"""Canonical contextual memory, fileless execution, and evasion rule ownership."""

from Virus_Scan.detection.contracts.string_predicates import context_any, context_regex


def _append_memory_manipulation_tags(blob: object, tags: list[str]) -> None:
    has_alloc = context_any(blob, ['virtualalloc', 'virtualallocex', 'ntallocatevirtualmemory'])
    has_write_mem = context_any(blob, ['writeprocessmemory', 'rtlmovememory', 'copymemory', 'memcpy', 'marshal.copy'])
    has_thread = context_any(blob, ['createremotethread', 'ntcreatethreadex', 'createthread', 'queueuserapc', 'setthreadcontext'])
    if 'readprocessmemory' in blob:
        tags.append('memory_read')
    if has_alloc:
        tags.append('memory_allocate')
    if has_write_mem:
        tags.append('memory_write')
    if context_any(blob, ['virtualprotect', 'virtualprotectex']):
        tags.append('memory_protect')
    if has_thread:
        tags.append('thread_execution')
    if has_alloc and has_write_mem and (has_thread or 'virtualprotect' in blob):
        tags.extend(['memory_allocate', 'memory_write', 'thread_execution', 'process_injection', 'in_memory_execution', 'shellcode_exec'])


def _append_fileless_decode_tags(blob: object, tags: list[str]) -> None:
    if context_any(blob, ['assembly.load', 'invoke-reflectivepeinjection', 'reflectivepe', 'shellcode']) and context_any(blob, ['frombase64string', 'virtualalloc', 'virtualprotect', 'getprocaddress', 'delegate']):
        tags.extend(['assembly_load', 'reflection', 'in_memory_execution', 'fileless_execution'])
    if context_any(blob, ['frombase64string', 'convert.frombase64string']):
        tags.append('payload_decode_candidate')
    if context_any(blob, ['fromcharcode', 'string.fromcharcode', 'gzipstream', 'xor']) and context_any(blob, ['eval', 'iex', 'invoke-expression', 'assembly.load', 'virtualalloc']):
        tags.extend(['obfuscated_script', 'encoded_payload_candidate'])


def _append_patch_bypass_tags(blob: object, tags: list[str]) -> None:
    amsi_patch_ctx = context_any(blob, ['virtualprotect', 'virtualprotectex', 'patch', 'amsiinitfailed', 'amsiutils', 'setvalue', 'marshal.copy', 'writeprocessmemory', '0xb8', '0x57', '0x00', '0xc3'])
    if context_any(blob, ['amsiscanbuffer', 'amsiscanstring', 'amsi.dll', 'amsiutils', 'amsicontext']) and amsi_patch_ctx:
        tags.extend(['amsi_scanbuffer_patch', 'amsi_bypass_attempt', 'defense_evasion'])
    etw_patch_ctx = context_any(blob, ['patch', 'virtualprotect', 'virtualprotectex', 'ntdll', 'writeprocessmemory', 'marshal.copy', '0xc3', 'ret', 'xor eax', 'return 0'])
    if context_any(blob, ['etweventwrite', 'nttraceevent', 'eventwrite', 'eventregister']) and etw_patch_ctx:
        tags.extend(['etw_eventwrite_patch', 'etw_bypass_attempt', 'defense_evasion'])


def _append_platform_defense_evasion_tags(blob: object, tags: list[str]) -> None:
    if context_any(blob, ['set-mppreference', 'add-mppreference', 'disablerealtimemonitoring', 'disableantispyware', 'exclusionpath']):
        tags.extend(['defender_disable', 'defense_evasion'])
    if context_any(blob, ['wevtutil cl', 'wevtutil.exe cl', 'clear-eventlog']):
        tags.extend(['log_clearing', 'defense_evasion'])
    if context_any(blob, ['vssadmin delete shadows', 'wmic shadowcopy delete', 'delete shadows', 'wbadmin delete catalog', 'resize shadowstorage']):
        tags.extend(['shadowcopy_delete', 'recovery_disable', 'ransomware_behavior', 'defense_evasion'])
    if 'bcdedit' in blob and context_any(blob, ['recoveryenabled no', 'bootstatuspolicy', 'ignoreallfailures']):
        tags.extend(['recovery_disable', 'defense_evasion'])
    if context_regex('\\b(?:taskkill|sc stop|net stop|stop-service|sc config)\\b', blob) and context_any(blob, ['msmpeng', 'windefend', 'avp', 'avg', 'sophos', 'sentinel', 'crowdstrike', 'carbonblack']):
        tags.extend(['security_process_kill', 'security_service_disable', 'defense_evasion'])


def collect_memory_and_evasion_tags(blob: object) -> object:
    """Return memory manipulation, injection, and defense-evasion tags."""
    tags: list[str] = []
    _append_memory_manipulation_tags(blob, tags)
    _append_fileless_decode_tags(blob, tags)
    _append_patch_bypass_tags(blob, tags)
    _append_platform_defense_evasion_tags(blob, tags)
    return tags
