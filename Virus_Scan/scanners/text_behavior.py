"""Scanner-owned text behavior predicates and lightweight probes."""

from pathlib import Path, PurePath
import re

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join
from Virus_Scan.scanners.pipeline import _ctx_re
from Virus_Scan.scanners.text_extraction import _tag_validation_text
from Virus_Scan.utils.text_match import has_any_text as _has_any_text


PLR2004N120 = 120

DECODE_LAYER_DEBUG = False


def _scanner_path_text(path: object) -> object:
    """Return scanner-owned path text without invoking caller-owned hooks."""
    if path is None:
        return ('', '')
    if type(path) is str:
        return (str.__str__(path), '')
    if type(path) in (bytes, bytearray):
        try:
            return (bytes(path).decode('utf-8', 'replace'), '')
        except SCAN_CONTENT_ERRORS:
            return ('', 'scanner_path_decode_failed')
    if isinstance(path, PurePath):
        try:
            return (PurePath.__str__(path), '')
        except SCAN_CONTENT_ERRORS:
            return ('', 'scanner_path_text_failed')
    text, reason = no_hook_text(
        path,
        missing_reason='missing_scanner_path',
        unsupported_reason='unsafe_scanner_path_rejected',
    )
    return (text, reason)


def _renpy_bytecode_path_status(path: object) -> object:
    """Return explicit Ren'Py path-probe status without fail-open defaults or hooks."""
    p, reason = _scanner_path_text(path)
    if reason and reason != 'missing_scanner_path':
        return 'probe_error'
    p = p.lower()
    if p.endswith(('.rpyc', '.rpyb')) or '/renpy/' in p.replace('\\', '/') or '\\renpy\\' in p:
        return 'renpy_bytecode_path'
    return 'ordinary_path'


def _is_renpy_bytecode_path(path: object) -> object:
    return _renpy_bytecode_path_status(path) == 'renpy_bytecode_path'


def _behavior_text_bits(strings_blob: object = '', path: object = None) -> object:
    text = _tag_validation_text(strings_blob)
    compact = re.sub('\\s+', ' ', text)
    path_text, reason = _scanner_path_text(path)
    if reason and reason != 'missing_scanner_path':
        name, ext = ('', '')
    else:
        try:
            name = Path(path_text).name.lower()
            ext = Path(path_text).suffix.lower()
        except SCAN_CONTENT_ERRORS:
            name, ext = ('', '')
    return (text, compact, name, ext)


def _decode_debug(msg: object) -> object:
    """Quiet decode-miss hook; expected malformed candidates are not scanner errors."""
    if DECODE_LAYER_DEBUG:
        log_error(scanner_contract_join('decode debug: ', scanner_contract_error_message(msg)))


def _has_command_exec_behavior(text: object) -> object:
    return bool((_ctx_re('\\b(?:powershell|pwsh)(?:\\.exe)?\\b', text) and _ctx_re('(?:-|/)enc(?:odedcommand)?\\b|invoke-expression|\\biex\\b|downloadstring|downloadfile|start-process', text)) or _ctx_re('\\bcmd(?:\\.exe)?\\s*(?:/c|/k)\\b', text) or _ctx_re('\\b(?:createprocess|shellexecute|winexec)\\b', text) or (_ctx_re('\\b(?:subprocess\\.(?:popen|run|call)|popen\\(|os\\.system\\()', text) and _has_any_text(text, ['powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'shell=true', 'http://', 'https://'])) or (_ctx_re('\\b(?:eval|exec)\\s*\\(', text) and _has_any_text(text, ['base64', 'frombase64string', 'compile(', 'request', 'socket', 'download', 'http://', 'https://', 'pickle', 'marshal.loads'])))


def _has_confirmed_exfil_proof(text: object, tagset: object) -> object:
    if tagset & {'network_exfiltration', 'token_exfiltration', 'http_upload', 'dns_tunneling'}:
        return True
    return _has_any_text(text, ['uploadfile', 'uploadstring', 'multipart/form-data', 'webhook', 'discord.com/api/webhooks', 'api.telegram.org', 'ftp://', 'http post', 'postasync', 'requests.post', 'socket.send']) and _has_any_text(text, ['password', 'credential', 'token', 'cookie', 'wallet', 'screenshot', 'clipboard', 'keylog', 'login data', 'cookies.sqlite'])


def _has_dll_hijack_behavior(text: object) -> object:
    load_ctx = _has_any_text(text, ['loadlibrary', 'setdlldirectory', 'adddlldirectory', 'dll search order', 'side-load', 'sideload'])
    untrusted_path = _has_any_text(text, ['current directory', '%temp%', 'appdata', 'startup', 'writable', 'copyfile', 'writeallbytes', 'drop', 'plant', 'side-load', 'sideload'])
    return bool(load_ctx and untrusted_path and ('.dll' in text))


def _has_input_collection_behavior(text: object) -> object:
    """Return true only for real input/clipboard capture with theft or exfil context."""
    benign_ui_context = _has_any_text(text, ['pygame.keydown', 'pygame.keyup', 'pygame.textinput', 'pygame.mousemotion', 'pygame.mousebuttondown', 'pygame.mousebuttonup', 'displayable', 'scene_lists', 'renpy.display', 'set_mouse_pos', 'get_mouse_pos', 'screenshot_surface', 'save_screenshot', 'thumbnail_width', 'thumbnail_height'])
    strong_input_api = _has_any_text(text, ['getasynckeystate', 'setwindowshookex', 'wh_keyboard', 'wh_keyboard_ll', 'getrawinputdata', 'keyboard hook', 'keylogger', 'keylog', 'openclipboard', 'getclipboarddata', 'clipboard monitor'])
    sensitive_target = _has_any_text(text, ['password', 'credential', 'token', 'cookie', 'wallet', 'seed phrase', 'private key', 'login data', 'cookies.sqlite', 'discord token', 'telegram', 'browser profile'])
    exfil_target = _has_any_text(text, ['uploadfile', 'uploadstring', 'multipart/form-data', 'webhook', 'discord.com/api/webhooks', 'api.telegram.org', 'ftp://', 'http post', 'postasync', 'requests.post', '.send(', 'socket.send'])
    if benign_ui_context and (not (strong_input_api and (sensitive_target or exfil_target))):
        return False
    return strong_input_api and (sensitive_target or exfil_target)


def _has_lolbin_script_behavior(text: object) -> object:
    if _is_renpy_tts_wscript_context(text):
        return False
    return bool((_ctx_re('\\b(?:wscript|cscript)(?:\\.exe)?\\b', text) and _ctx_re('\\.(?:vbs|vbe|js|jse|wsf)\\b|//e:|wscript\\.shell|createobject\\(', text) and _has_any_text(text, ['http://', 'https://', 'powershell', 'cmd.exe', 'run(', 'shell', 'appdata', '%temp%', 'startup'])) or (_ctx_re('\\bmshta(?:\\.exe)?\\b', text) and _ctx_re('https?://|javascript:|vbscript:|\\.hta\\b', text)) or (_ctx_re('\\bregsvr32(?:\\.exe)?\\b', text) and _ctx_re('scrobj\\.dll|/i:https?://|\\.sct|scriptlet', text)) or (_ctx_re('\\brundll32(?:\\.exe)?\\b', text) and _ctx_re('javascript:|mshtml|comsvcs\\.dll|https?://|minidump', text)))


def _has_macro_exec_behavior(text: object) -> object:
    macro = _has_any_text(text, ['autoopen', 'document_open', 'workbook_open', 'auto_open', 'vbproject', 'vba', 'createobject('])
    exec_or_net = _has_any_text(text, ['shell(', 'run(', 'powershell', 'cmd.exe', 'wscript.shell', 'urldownloadtofile', 'downloadfile', 'downloadstring', 'winmgmts:'])
    return bool(macro and exec_or_net)


def _is_renpy_tts_wscript_context(text: object, name: object = '') -> object:
    del name  # Explicitly unused contract parameters.
    return bool('say.vbs' in text and 'wscript' in text and _has_any_text(text, ['tts_voice', 'amplitude_100', 'renpy.windows', 'fsencode(say_vbs)', 'text-to-speech', 'self voicing']))


def _looks_like_base64_payload_status(text: object) -> object:
    try:
        matches = re.findall('(?i)(?:[A-Za-z0-9+/]{80,}={0,2})', text or '')
        return 'present' if any((len(m) >= PLR2004N120 for m in matches)) else 'absent'
    except SCAN_CONTENT_ERRORS:
        return 'probe_error'


def _looks_like_base64_payload(text: object) -> object:
    return _looks_like_base64_payload_status(text) == 'present'


__all__ = (
    '_behavior_text_bits',
    '_decode_debug',
    '_has_command_exec_behavior',
    '_has_confirmed_exfil_proof',
    '_has_dll_hijack_behavior',
    '_has_input_collection_behavior',
    '_has_lolbin_script_behavior',
    '_has_macro_exec_behavior',
    '_is_renpy_bytecode_path',
    '_is_renpy_tts_wscript_context',
    '_looks_like_base64_payload',
    '_looks_like_base64_payload_status',
    '_renpy_bytecode_path_status',
    '_scanner_path_text',
)
