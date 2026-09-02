"""Behavior-intent tag filtering owned by composite chain detection."""

from dataclasses import dataclass
from types import MappingProxyType

from Virus_Scan.detection.tags.heuristics.runtime_library_policy import (
    is_known_python_runtime_library_path,
    is_runtime_or_engine_library_path,
)
from Virus_Scan.detection.contracts.path_predicates import RUNTIME_STRONG_ATTACK_CONTEXT as _RUNTIME_STRONG_ATTACK_CONTEXT
from Virus_Scan.detection.chains.composite.text_behavior import (
    has_archive_dropper_behavior as _has_archive_dropper_behavior,
    has_c2_behavior as _has_c2_behavior,
    has_payload_download_behavior as _has_payload_download_behavior,
)
from Virus_Scan.detection.registries.chain_registry import (
    BEHAVIOR_GATED_TAGS,
    MAJOR_ATTACK_ANCHOR_TAGS,
)
from Virus_Scan.detection.registries.chain_gate_registry_defaults import LOW_RISK_CONTEXT_REPLACEMENTS
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.contracts.string_predicates import has_pickle_exec_behavior as _has_pickle_exec_behavior
from Virus_Scan.detection.contracts.string_predicates import (
    behavior_text_bits as _behavior_text_bits,
    has_any_text as _has_any_text,
    has_command_exec_behavior as _has_command_exec_behavior,
    has_dll_hijack_behavior as _has_dll_hijack_behavior,
    has_input_collection_behavior as _has_input_collection_behavior,
    has_lolbin_script_behavior as _has_lolbin_script_behavior,
    has_macro_exec_behavior as _has_macro_exec_behavior,
    is_renpy_tts_wscript_context as _is_renpy_tts_wscript_context,
)
from Virus_Scan.utils.tagging import ordered_unique_tags


def _script_execution_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_command_exec_behavior(text) or _has_lolbin_script_behavior(text) or _has_pickle_exec_behavior(text)


def _process_execution_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_command_exec_behavior(text) or _has_lolbin_script_behavior(text)


def _lolbin_execution_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_lolbin_script_behavior(text)


def _javascript_execution_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_lolbin_script_behavior(text) or (
        _has_any_text(text, ['eval(', 'function(', 'new function'])
        and _has_any_text(text, ['http://', 'https://', 'document.write', 'activexobject'])
    )


def _fileless_execution_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_lolbin_script_behavior(text) or (
        _has_any_text(text, ['frombase64string', 'downloadstring', 'invoke-expression', 'reflective', 'assembly.load'])
        and _has_command_exec_behavior(text)
    )


def _payload_download_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_payload_download_behavior(text)


def _c2_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_c2_behavior(text)


def _archive_dropper_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_archive_dropper_behavior(text)


def _dropper_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_archive_dropper_behavior(text) or (
        _has_payload_download_behavior(text) and _has_command_exec_behavior(text)
    )


def _dll_hijack_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_dll_hijack_behavior(text)


def _input_collection_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_input_collection_behavior(text)


def _collection_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_input_collection_behavior(text) or (
        _has_any_text(text, ['login data', 'cookies.sqlite', 'wallet.dat', 'password', 'token'])
        and _has_any_text(text, ['upload', 'webhook', 'http post', 'ftp://'])
    )


def _exfiltration_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_any_text(
        text,
        ['uploadfile', 'uploadstring', 'multipart/form-data', 'webhook', 'discord.com/api/webhooks', 'api.telegram.org', 'ftp://', 'http post'],
    ) and _has_any_text(text, ['password', 'token', 'cookie', 'wallet', 'screenshot', 'clipboard', 'keylog'])


def _http_upload_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_any_text(
        text,
        ['uploadfile', 'uploadstring', 'multipart/form-data', 'content-disposition: form-data', 'http post', 'postasync'],
    ) and _has_any_text(text, ['password', 'token', 'cookie', 'wallet', 'screenshot', 'clipboard', 'keylog'])


def _embedded_base64_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_any_text(text, ['frombase64string', 'base64.b64decode', 'certutil -decode']) and (
        _has_command_exec_behavior(text)
        or _has_any_text(text, ['mz', 'this program cannot be run', 'assembly.load', 'virtualalloc'])
    )


def _encoded_payload_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_any_text(text, ['frombase64string', 'base64.b64decode', 'certutil -decode', 'encodedcommand']) and (
        _has_command_exec_behavior(text)
        or _has_any_text(text, ['mz', 'this program cannot be run', 'assembly.load', 'virtualalloc'])
    )


def _macro_execution_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_macro_exec_behavior(text)


def _renpy_pickle_confirmed(text: str, ext: str) -> bool:
    return _has_pickle_exec_behavior(text) and ext not in {'.py', '.pyc', '.pyo'}


def _python_pickle_confirmed(text: str, ext: str) -> bool:
    return _has_pickle_exec_behavior(text) and ext in {'.py', '.pyc', '.pyo'}


def _pickle_execution_confirmed(text: str, ext: str) -> bool:
    del ext
    return _has_pickle_exec_behavior(text)


def _rpa_pickle_confirmed(text: str, ext: str) -> bool:
    return _has_pickle_exec_behavior(text) and (ext == '.rpa' or 'rpa-3.0' in text)


@dataclass(frozen=True, slots=True)
class _BehaviorTagFilterContext:
    tags: object
    text: str
    ext: str
    has_major_anchor: bool
    runtime_gate: bool


_BEHAVIOR_PREDICATES = MappingProxyType({
    'script_execution': _script_execution_confirmed,
    'process_exec': _process_execution_confirmed,
    'wscript_exec': _lolbin_execution_confirmed,
    'cscript_exec': _lolbin_execution_confirmed,
    'vbs_execution': _lolbin_execution_confirmed,
    'jscript_execution': _lolbin_execution_confirmed,
    'javascript_execution': _javascript_execution_confirmed,
    'fileless_execution': _fileless_execution_confirmed,
    'network_download': _payload_download_confirmed,
    'remote_payload_download': _payload_download_confirmed,
    'network_c2': _c2_confirmed,
    'backdoor_or_c2': _c2_confirmed,
    'remote_command_channel': _c2_confirmed,
    'c2_beacon': _c2_confirmed,
    'c2_or_remote_command': _c2_confirmed,
    'archive_dropper': _archive_dropper_confirmed,
    'embedded_archive_payload': _archive_dropper_confirmed,
    'dropper_behavior': _dropper_confirmed,
    'dll_hijack': _dll_hijack_confirmed,
    'dll_sideload': _dll_hijack_confirmed,
    'input_capture': _input_collection_confirmed,
    'keylogging_behavior': _input_collection_confirmed,
    'collection': _collection_confirmed,
    'exfiltration': _exfiltration_confirmed,
    'network_exfiltration': _exfiltration_confirmed,
    'http_upload': _http_upload_confirmed,
    'embedded_base64_payload': _embedded_base64_confirmed,
    'encoded_payload_candidate': _encoded_payload_confirmed,
    'macro_office': _macro_execution_confirmed,
    'office_macro_execution': _macro_execution_confirmed,
})

_RUNTIME_ALLOWED_TAGS = frozenset({
    'yara_malware', 'known_bad_hash', 'malware_family', 'confirmed_embedded_pe_payload',
    'decoded_pe_payload', 'embedded_pe_payload', 'mimikatz_credential_dump', 'lsass_access',
    'credential_dump_attempt', 'amsi_scanbuffer_patch', 'etw_eventwrite_patch',
    'write_process_memory', 'create_remote_thread', 'remote_thread_create',
'process_injection', 'encoded_powershell', 'powershell_exec',
})


def _behavior_context_extras(text: str, name: str) -> list[str]:
    extras: list[str] = []
    if _is_renpy_tts_wscript_context(text, name):
        extras.extend(['renpy_tts_wscript', 'assistive_tts_script_launch'])
    if _has_any_text(text, ['zipfile', 'zipfile.zipfile', 'zf.read', 'zf.write']) and _has_any_text(
        text, ['save', 'savegame', 'slotname', 'persistent', 'renpy.loadsave']
    ):
        extras.append('save_archive_access')
    if _has_any_text(text, ['loadlibrary', 'setdlldirectory', 'adddlldirectory']) and not _has_dll_hijack_behavior(text):
        extras.append('dll_load_capability')
    if _has_any_text(text, ['getasynckeystate', 'getkeystate', 'getcursorpos', 'getlastinputinfo']) and not _has_input_collection_behavior(text):
        extras.append('input_api_capability')
    return extras


def _runtime_behavior_gate(tagset: set[str], text: str, path: object, strings_blob: object, extras: list[str]) -> bool:
    is_runtime_library = is_runtime_or_engine_library_path(path) or is_known_python_runtime_library_path(path, strings_blob)
    if not is_runtime_library:
        return False
    runtime_strong = bool(tagset & _RUNTIME_ALLOWED_TAGS) or _has_any_text(text, _RUNTIME_STRONG_ATTACK_CONTEXT)
    if runtime_strong:
        return False
    extras.append('runtime_behavior_intent_gate')
    if is_known_python_runtime_library_path(path, strings_blob):
        extras.extend([
            'python_runtime_library',
            'renpy_runtime_library',
            'library_behavior_baseline:renpy_python_runtime_source',
        ])
    return True


def _filtered_behavior_tags(context: _BehaviorTagFilterContext, extras: list[str]) -> list[object]:
    cleaned: list[object] = []
    for tag in context.tags or []:
        low = str(tag).lower()
        predicate = _BEHAVIOR_PREDICATES.get(low)
        if predicate is None:
            cleaned.append(tag)
            continue
        keep = False
        try:
            keep = False if context.runtime_gate else bool(predicate(context.text, context.ext))
        except RECOVERABLE_RUNTIME_ERRORS:
            keep = False
        if keep or context.has_major_anchor:
            cleaned.append(tag)
            continue
        replacement = LOW_RISK_CONTEXT_REPLACEMENTS.get(low)
        if replacement:
            extras.append(replacement)
    return cleaned


def behavior_intent_filter_tags(tags: object, path: object=None, strings_blob: object='', source: object='') -> object:
    """Demote keyword/capability tags unless behavior-level predicates confirm them."""
    del source
    text, _compact, name, ext = _behavior_text_bits(strings_blob, path)
    tagset = {str(tag).lower() for tag in tags or []}
    extras = _behavior_context_extras(text, name)
    runtime_gate = _runtime_behavior_gate(tagset, text, path, strings_blob, extras)
    has_major_anchor = bool(tagset & (MAJOR_ATTACK_ANCHOR_TAGS - BEHAVIOR_GATED_TAGS))
    filter_context = _BehaviorTagFilterContext(
        tags=tags,
        text=text,
        ext=ext,
        has_major_anchor=has_major_anchor,
        runtime_gate=runtime_gate,
    )
    cleaned = _filtered_behavior_tags(filter_context, extras)
    return ordered_unique_tags(list(cleaned) + extras)
