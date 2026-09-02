"""Canonical API-behavior contract tables shared across scanner, detection, and models."""
from __future__ import annotations

import re
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_optional_sequence_items, no_hook_text

API_GROUPS = MappingProxyType({
    'process_execution': ('CreateProcessA', 'CreateProcessW', 'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW'),
    'process_access': ('OpenProcess', 'OpenThread', 'OpenProcessToken', 'DuplicateToken', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser', 'SetThreadToken', 'AdjustTokenPrivileges'),
    'memory': ('VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 'ReadProcessMemory', 'NtWriteVirtualMemory', 'NtReadVirtualMemory', 'MapViewOfFile', 'MapViewOfFileEx'),
    'threading': ('CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx', 'QueueUserAPC', 'SetThreadContext', 'ResumeThread'),
    'dll': ('LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'LdrLoadDll'),
    'credentials': ('MiniDumpWriteDump', 'LsaEnumerateLogonSessions', 'LsaGetLogonSessionData', 'CredEnumerate', 'CredRead', 'CredWrite'),
    'registry': ('RegOpenKeyEx', 'RegCreateKey', 'RegSetValueEx', 'RegQueryValueEx', 'NtSetValueKey'),
    'filesystem': ('CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'FindFirstFile', 'FindNextFile'),
    'network': ('socket', 'connect', 'send', 'recv', 'InternetOpen', 'InternetOpenUrl', 'URLDownloadToFile', 'WinHttpSendRequest', 'WinHttpOpen'),
    'services': ('CreateService', 'OpenSCManager', 'StartService', 'ControlService'),
    'evasion': ('AmsiScanBuffer', 'EtwEventWrite', 'NtSetInformationThread', 'NtQueryInformationProcess'),
    'collection': ('BitBlt', 'PrintWindow', 'GetAsyncKeyState', 'GetForegroundWindow', 'GetDC'),
})


API_NAME_TEXT_UNAVAILABLE = 'api_name_text_unavailable'


def _owned_sequence(value: object) -> tuple[object, ...]:
    return no_hook_optional_sequence_items(
        value,
        unsupported=(API_NAME_TEXT_UNAVAILABLE,),
    )


def _owned_mapping_values(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return ()
    return tuple(item for _key, item in items)


def canonical_api_text(value: object) -> str:
    """Project API names without invoking caller-owned arbitrary hooks."""
    if value is None:
        return ''
    text, reason = no_hook_text(
        value,
        missing_reason="missing_api_name_text",
        unsupported_reason="api_name_text_unavailable",
    )
    if reason == "" and text:
        return text
    return API_NAME_TEXT_UNAVAILABLE


def _api_text(value: object) -> str:
    return canonical_api_text(value)


def map_api_to_group(api: object) -> str:
    """Return the canonical API behavior group for an API name."""
    api_name = _api_text(api)
    api_name_l = api_name.lower()
    for group, apis in (no_hook_mapping_items(API_GROUPS) or ()):
        if api_name in apis or api_name_l in {canonical_api_text(item).lower() for item in apis}:
            return group
    return 'unknown'


def api_to_timeline_tag(api: object) -> str:
    """Convert an API name into the closest concrete detection tag."""
    api_name = _api_text(api)
    api_lower = api_name.lower()
    group = map_api_to_group(api_name)
    specific = {
        'virtualalloc': 'memory_allocate', 'virtualallocex': 'memory_allocate',
        'virtualprotect': 'memory_protect', 'virtualprotectex': 'memory_protect',
        'writeprocessmemory': 'memory_write', 'readprocessmemory': 'memory_read',
        'openprocess': 'process_access', 'createremotethread': 'thread_execution',
        'createthread': 'thread_execution', 'ntcreatethreadex': 'thread_execution',
        'loadlibrarya': 'dll_load', 'loadlibraryw': 'dll_load', 'getprocaddress': 'dynamic_api_resolution',
        'urldownloadtofilea': 'network_download', 'urldownloadtofilew': 'network_download',
        'internetopenurl': 'network_download', 'winhttpopenrequest': 'network_activity',
        'winhttpsendrequest': 'network_activity', 'socket': 'network_activity',
        'connect': 'network_activity', 'send': 'network_activity', 'recv': 'network_activity',
        'regsetvalueexa': 'registry_mod', 'regsetvalueexw': 'registry_mod',
        'createservicea': 'service_create', 'createservicew': 'service_create',
        'createprocessa': 'process_exec', 'createprocessw': 'process_exec',
        'shellexecutea': 'shell_execute', 'shellexecutew': 'shell_execute',
        'credread': 'credential_api_access', 'credenumerate': 'credential_api_access',
        'minidumpwritedump': 'credential_dump_attempt', 'cryptunprotectdata': 'dpapi_access',
        'amsiscanbuffer': 'defense_evasion', 'etweventwrite': 'defense_evasion',
        'getasynckeystate': 'keylogging_behavior', 'bitblt': 'screenshot_capture',
        'printwindow': 'screenshot_capture',
    }
    if api_lower in specific:
        return specific[api_lower]
    group_map = {
        'process_execution': 'process_exec', 'process_access': 'process_access',
        'memory': 'memory_access', 'threading': 'thread_execution', 'dll': 'dll_load',
        'credentials': 'credential_api_access', 'registry': 'registry_mod',
        'filesystem': 'file_access', 'network': 'network_activity',
        'services': 'service_create', 'evasion': 'defense_evasion', 'collection': 'collection',
    }
    return group_map.get(group, 'api_call')


def api_call_values(api_calls: object) -> list[object]:
    return list(_owned_sequence(api_calls))


def build_api_regex(api_groups: object = API_GROUPS) -> re.Pattern[str]:
    all_apis = set()
    for group in _owned_mapping_values(api_groups):
        for api in _owned_sequence(group):
            all_apis.add(canonical_api_text(api))
    pattern = r'\b(' + '|'.join(re.escape(api) for api in sorted(all_apis) if api and api != API_NAME_TEXT_UNAVAILABLE) + r')\b'
    return re.compile(pattern, re.IGNORECASE)


__all__ = ('API_GROUPS', 'API_NAME_TEXT_UNAVAILABLE', 'api_call_values', 'api_to_timeline_tag', 'build_api_regex', 'canonical_api_text', 'map_api_to_group')
