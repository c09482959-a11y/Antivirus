"""Canonical contextual lateral-movement, collection, and .NET rule ownership."""

from Virus_Scan.detection.contracts.string_predicates import context_any, context_regex


def _append_remote_execution_tags(blob: object, tags: list[str], *, has_powershell: object) -> None:
    if context_any(blob, ['new-pssession', 'enter-pssession', 'invoke-command']) and has_powershell:
        tags.extend(['remote_powershell', 'winrm_exec', 'lateral_movement', 'process_exec'])
    if context_regex('\\bwin32_process(?:\\.create)?\\b', blob) and context_any(blob, ['create', 'invoke-wmimethod', 'wmic process call create']):
        tags.extend(['win32_process_create', 'wmi_exec', 'lateral_movement', 'process_exec'])
    if context_any(blob, ['wmic process call create', 'invoke-wmimethod', 'invoke-cimmethod', 'win32_process.create']):
        tags.extend(['win32_process_create', 'wmi_exec', 'lateral_movement', 'remote_execution', 'process_exec'])


def _append_remote_service_tags(blob: object, tags: list[str]) -> None:
    if context_regex('(?:\\\\\\\\[^\\s\\\\]+\\\\(?:admin\\$|ipc\\$|c\\$)|\\badmin\\$\\b|\\bipc\\$\\b)', blob) and context_any(blob, ['copy', 'writefile', 'createfile', 'net use', 'psexec', 'smb']):
        tags.extend(['admin_share_access', 'smb_activity', 'lateral_movement'])
    if context_any(blob, ['impacket', 'smbexec', 'wmiexec', 'atexec', 'psexec.py']):
        tags.extend(['impacket_exec', 'smb_activity', 'lateral_movement', 'process_exec'])
    if context_any(blob, ['svcctl', 'openscmanager', 'openscmanagera', 'openscmanagerw', 'createservice', 'createservicea', 'createservicew', 'sc.exe create', 'sc create']):
        tags.extend(['remote_service_creation', 'service_create', 'lateral_movement', 'process_exec'])
    if context_any(blob, ['reg connect', 'remote registry']):
        tags.extend(['remote_registry', 'lateral_movement', 'registry_mod'])


def _append_collection_tags(blob: object, tags: list[str]) -> None:
    keylog_api_hits = sum((1 for x in ['getasynckeystate', 'getkeystate', 'getkeyboardstate', 'keybd_event', 'setwindowshookex', 'wh_keyboard_ll', 'getrawinputdata', 'registerrawinputdevices', 'tounicode', 'mapvirtualkey', 'vkkeyscan'] if x in blob))
    if keylog_api_hits >= 1:
        tags.extend(['keylogging_behavior', 'input_capture', 'collection'])
    if context_any(blob, ['bitblt', 'printwindow', 'copyfromscreen']):
        tags.extend(['screenshot_capture', 'screen_capture', 'collection'])
    clipboard_hits = sum((1 for x in ['getclipboarddata', 'openclipboard', 'setclipboarddata', 'emptyclipboard', 'isclipboardformatavailable', 'clipboard.gettext', 'system.windows.forms.clipboard'] if x in blob))
    if clipboard_hits >= 1:
        tags.extend(['clipboard_access', 'collection'])
    if keylog_api_hits and clipboard_hits:
        tags.extend(['input_capture', 'clipboard_access', 'file_collection'])


def _append_dll_and_msbuild_tags(blob: object, tags: list[str]) -> None:
    if context_any(blob, ['loadlibrary', 'dllimport']) or (context_regex('\\brundll32(?:\\.exe)?\\b', blob) and '.dll' in blob):
        tags.append('dll_load')
    if 'msbuild' in blob and context_any(blob, ['codetaskfactory', 'usingtask', 'taskfactory']):
        tags.extend(['msbuild_exec', 'inline_task', 'fileless_execution', 'dotnet_execution'])
    elif 'msbuild' in blob:
        tags.extend(['msbuild_exec', 'dotnet_execution'])


def _append_dotnet_registry_tags(blob: object, tags: list[str]) -> None:
    if 'installutil' in blob:
        tags.extend(['installutil_exec', 'dotnet_execution', 'process_exec'])
    if context_regex('\\breg(?:\\.exe)?\\s+(?:add|query|save|load)\\b', blob):
        tags.extend(['reg_exec', 'registry_mod'])
    if context_any(blob, ['system.reflection', 'assembly.load', 'loadfrom']) or (context_any(blob, ['getmethod', 'methodinfo.invoke']) and 'invoke' in blob):
        tags.extend(['reflection', 'assembly_load'])


def collect_lateral_collection_and_dotnet_tags(blob: object, *, has_powershell: object=False) -> object:
    """Return lateral-movement, collection, DLL, and .NET execution tags."""
    tags: list[str] = []
    _append_remote_execution_tags(blob, tags, has_powershell=has_powershell)
    _append_remote_service_tags(blob, tags)
    _append_collection_tags(blob, tags)
    _append_dll_and_msbuild_tags(blob, tags)
    _append_dotnet_registry_tags(blob, tags)
    return tags
