"""Profile-aware family tag scanning ownership.

This module owns the cross-profile explicit missed-family scan entry point.
Generic callers import this bounded profile coordinator instead of importing
engine-specific Ren'Py loader modules directly.  Engine-specific loader
evidence is selected through immutable detection profile context.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.profiles.renpy.loaders.family_scan import renpy_loader_family_tags
from Virus_Scan.detection.profiles.selection import build_detection_profile_context
from Virus_Scan.detection.profiles.renpy.updater_text import profile_text_or_empty, profile_tuple_or_empty
from Virus_Scan.detection.tags.heuristics.archive_intent import classify_archive_intent_tags
from Virus_Scan.detection.tags.heuristics.network_intent import classify_network_intent_tags
from Virus_Scan.detection.profiles.engine_context import infer_engine_context
from Virus_Scan.detection.contracts.pickle_opcode import detect_python_pickle_opcode_exec
from Virus_Scan.detection.contracts.string_predicates import context_regex
from Virus_Scan.detection.heuristics.game_engine_threats import evaluate_game_engine_threats
from Virus_Scan.utils.tagging import ordered_unique_tags


DetectionValue = object
TagList = list[str]
TextItems = Iterable[DetectionValue]
TagSequence = Sequence[str]
BinaryData = bytes | bytearray | memoryview | None
RenpyLoaderFamilyScanner = Callable[..., TagSequence]


MEDIA_EXTENSIONS = frozenset(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.wav', '.mp3', '.flac', '.ogg', '.mp4', '.avi', '.mkv'))
WALLET_EXTENSION_IDS = (
    'nkbihfbeogaeaoehlefnkodbefgpgknn',
    'bfnaelmomeimhlpmgjnjophhpkkoljpa',
    'hnfanknocfeofbddgcijnmhnfnkdnaad',
    'mcohilncbfahbmgdjkbpemcciiolgcge',
    'egjidjbpglichdcondbcbdnbeeppgdph',
    'omaabbefbmiijedngplfjmnooppbclkk',
)
ANTI_VM_TERMS = (
    'vboxservice', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'vmwareuser', 'qemu-ga',
    'xenservice', 'virtualbox', 'vmware', 'qemu', 'hyper-v', 'sandboxie', 'sbie',
    'wireshark', 'procmon', 'isdebuggerpresent', 'checkremotedebuggerpresent',
    'ntqueryinformationprocess', 'cpuid', 'rdtsc',
)


def _family_text_contains_any(text: str, items: TextItems) -> bool:
    return any(str(item).lower() in text for item in items)


def _family_context_regex(pattern: str, text: str) -> bool:
    return context_regex(pattern, text)


def _add_game_engine_threat_tags(tags: TagList, text: str, path: DetectionValue) -> None:
    try:
        result = evaluate_game_engine_threats(text, path=profile_text_or_empty(path))
        tags.extend(profile_tuple_or_empty(result.get('tags')))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        tags.extend(failure_tags_for_stage('game_engine_threat_evaluator', exc, context=path))


def _add_lolbin_macro_and_c2_tags(tags: TagList, text: str) -> None:
    def anyof(items: TextItems) -> bool:
        return _family_text_contains_any(text, items)

    if _family_context_regex('\\bregsvr32(?:\\.exe)?\\b', text) and (
        anyof(['scrobj.dll', '/i:http://', '/i:https://', 'scriptlet', '.sct', 'com scriptlet'])
        or ('http' in text and anyof(['/s', '/n', '/u', '/i:']))
    ):
        tags.extend(('regsvr32_exec', 'regsvr32_sct', 'scriptlet_execution', 'fileless_execution', 'lolbin_download'))
        if 'http://' in text or 'https://' in text:
            tags.extend(('network_download', 'remote_payload_download', 'process_exec'))
    if anyof(['autoopen', 'document_open', 'workbook_open', 'auto_open', 'vba', 'vbproject', 'wscript.shell', 'createobject(']) and anyof(['shell(', 'run(', 'powershell', 'cmd.exe', 'urlmon', 'urldownloadtofile', 'downloadfile', 'downloadstring', 'winmgmts:']):
        tags.extend(('office_macro_execution', 'macro_office', 'script_execution'))
        if anyof(['powershell', 'cmd.exe', 'wscript.shell', 'createobject(']):
            tags.append('process_exec')
        if anyof(['http://', 'https://', 'downloadfile', 'downloadstring', 'urldownloadtofile']):
            tags.extend(('network_download', 'remote_payload_download', 'process_exec'))
    tags.extend(classify_network_intent_tags(text, has_url=anyof(['http://', 'https://', 'ftp://', 'ws://', 'wss://'])))
    c2_net = anyof(['http://', 'https://', 'ws://', 'wss://', 'tcpclient', 'socket.connect', 'connect(', 'winhttpopenrequest'])
    c2_tasking = anyof(['beacon', 'checkin', 'check-in', 'command and control', 'c2', 'sleep jitter', '/api/checkin', '/gate.php', '/panel/', 'reverse shell', 'getcommand', 'tasking'])
    socket_tasking = anyof(['recv(', 'send(']) and anyof(['command', 'cmd', 'task', 'shell', 'beacon', 'implant'])
    c2_exec = anyof(['eval(', 'exec(', 'subprocess', 'os.system', 'popen(', 'powershell', 'cmd.exe', 'createprocess', 'shellexecute'])
    if c2_net and (c2_tasking or socket_tasking) and c2_exec:
        tags.extend(('c2_or_remote_command', 'c2_beacon', 'network_c2', 'backdoor_or_c2', 'network_activity', 'remote_command_channel'))


def _add_wallet_privilege_archive_and_dll_tags(
    tags: TagList, text: str, path: DetectionValue,
) -> None:
    def anyof(items: TextItems) -> bool:
        return _family_text_contains_any(text, items)

    browser_wallet_target = anyof(['local extension settings', 'chrome\\user data', 'chrome/user data', 'google\\chrome\\user data', 'brave-browser', 'edge\\user data']) and anyof(WALLET_EXTENSION_IDS)
    wallet_rpc = anyof(['jsonrpc', 'eth_call', 'ethereum', 'sepolia', 'publicnode', 'tenderly', '1rpc.io', 'drpc.org'])
    wallet_download_exec = anyof(['urlopen', 'urlretrieve', 'urllib.request', 'requests.get', 'http://', 'https://']) and anyof(['.exe', 'subprocess.popen', 'popen(', 'createprocess', 'startfile'])
    if browser_wallet_target:
        tags.extend(('browser_credential_access', 'browser_credential_path', 'browser_wallet_extension_access', 'token_secret_access', 'file_read', 'collection'))
        if wallet_rpc or wallet_download_exec:
            tags.extend(('network_activity', 'network_download', 'remote_payload_download'))
        if wallet_download_exec:
            tags.extend(('process_exec', 'network_download', 'remote_payload_download', 'probable_browser_wallet_stealer'))
        if wallet_rpc and wallet_download_exec:
            tags.extend(('confirmed_browser_wallet_stealer_download_exec', 'backdoor_or_c2'))
    if anyof(['fodhelper.exe', 'eventvwr.exe', 'computerdefaults.exe', 'sdclt.exe', 'uacme', 'cmstp.exe', 'slui.exe', 'auto elevate', 'autoelevate']) or (anyof(['delegateexecute', 'ms-settings\\shell\\open\\command', 'hkcu\\software\\classes']) and anyof(['reg.exe add', 'currentversion\\run', 'cmd.exe', 'powershell'])):
        tags.extend(('uac_bypass', 'priv_esc_uac', 'privilege_escalation', 'defense_evasion'))
        if anyof(['cmd.exe', 'powershell', 'createprocess']):
            tags.append('process_exec')
    tags.extend(classify_archive_intent_tags(text, path=path))
    if 'archive_dropper' in {str(t).lower() for t in tags} and anyof(['start-process', 'createprocess', 'shellexecute', 'cmd.exe', 'powershell', 'subprocess', 'os.system']):
        tags.extend(('process_exec', 'network_download'))
    if anyof(['loadlibrary', 'setdlldirectory', 'adddlldirectory', 'dll search order', 'known dlls', 'side-load', 'sideload']) and anyof(['current directory', 'appdata', '%temp%', 'system32', 'copyfile', 'writeallbytes', '.dll', 'rundll32']):
        tags.extend(('dll_hijack', 'dll_sideload', 'dll_load', 'persistence'))


def _add_reflection_anti_exfil_clipboard_and_packer_tags(tags: TagList, text: str) -> None:
    def anyof(items: TextItems) -> bool:
        return _family_text_contains_any(text, items)

    if anyof(['system.reflection', 'assembly.load', 'load(byte[]', 'loadfile', 'loadfrom', 'methodinfo.invoke', 'getmethod(']) and anyof(['frombase64string', 'memorystream', 'byte[]', 'invoke(', 'entrypoint.invoke', 'getdelegateforfunctionpointer', 'virtualalloc', 'amsi']):
        tags.extend(('reflection_dotnet', 'reflection', 'assembly_load', 'in_memory_execution'))
        if anyof(['frombase64string', 'memorystream', 'byte[]']):
            tags.extend(('embedded_base64_payload', 'encoded_payload_candidate'))
    anti_vm_hits = sum(1 for term in ANTI_VM_TERMS if term in text)
    if anti_vm_hits >= 2 or (anyof(['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess']) and anyof(['debug', 'sandbox', 'virtualbox', 'vmware'])):
        tags.extend(('anti_vm', 'anti_sandbox', 'defense_evasion'))
    if anyof(['login data', 'cookies.sqlite', 'desktop', 'documents', 'wallet.dat', 'clipboard', 'screenshot', 'keylog', 'password', 'token', 'secret_access_key']) and anyof(['uploadfile', 'uploadstring', 'multipart/form-data', 'content-disposition: form-data', 'webhook', 'discord.com/api/webhooks', 'api.telegram.org', 's3.amazonaws', 'azureblob', 'ftp://', 'http post', 'postasync']):
        tags.extend(('exfiltration', 'network_exfiltration', 'http_upload', 'collection'))
        if anyof(['clipboard', 'keylog', 'screenshot']):
            tags.extend(('input_capture', 'clipboard_access', 'file_collection'))
    if anyof(['getclipboarddata', 'openclipboard', 'setclipboarddata', 'clipboard.gettext', 'system.windows.forms.clipboard']) and anyof(['bitcoin', 'ethereum', 'monero', 'litecoin', 'wallet', 'address regex', 'bc1', 'xmr', 'clipboard monitor', 'replace clipboard']):
        tags.extend(('clipboard_access', 'clipboard_crypto', 'crypto_wallet_clipboard_replace', 'collection'))
    if anyof(['upx0', 'upx1', 'mpress', 'themida', 'vmprotect', 'aspack', 'pecompact', 'enigma protector', 'confuserex', 'koivm']) or (anyof(['virtualalloc', 'virtualprotect', 'getprocaddress', 'loadlibrary']) and anyof(['unpack', 'decompress', 'self-extract', 'rc4', 'xor decrypt', 'payload'])):
        tags.extend(('obfuscation_pack', 'packer_marker', 'packed_or_obfuscated', 'defense_evasion'))


def _add_media_stego_tags(
    tags: TagList, text: str, ext: str, data: BinaryData,
) -> None:
    if ext not in MEDIA_EXTENSIONS:
        return
    if _family_text_contains_any(text, ['steghide', 'outguess', 'zsteg', 'lsb', 'iendt', 'payload after iend', 'appended mz', 'appended pk', 'hidden payload']):
        tags.extend(('image_payload_candidate', 'possible_stego_payload', 'encoded_data_context'))
    if data is not None:
        low = bytes(data[:min(len(data), 4 * 1024 * 1024)]).lower()
        if low.find(b'mz') > 1024 or low.find(b'pk\x03\x04') > 1024 or low.find(b'powershell') > 1024:
            tags.extend(('image_payload_candidate', 'possible_stego_payload', 'encoded_data_context'))


def _pickle_contexts(text: str) -> tuple[bool, bool]:
    def anyof(items: TextItems) -> bool:
        return _family_text_contains_any(text, items)

    opcode_context = anyof(['cos\nsystem', 'subprocess\npopen', 'builtins\neval', 'builtins\nexec', 'posix\nsystem', 'nt\nsystem', '__reduce__', '__reduce_ex__', 'stack_global', 'opcode: global', 'opcode: reduce', 'pickletools']) or ((_family_context_regex('\\b(?:proto|global|reduce)\\b', text) and anyof(['pickle', 'pickletools', 'opcode'])) and anyof(['os.system(', 'subprocess', 'popen(', 'eval(', 'exec(', 'cmd.exe', 'powershell', 'import os']))
    exec_context = anyof(['os.system(', 'os system', 'subprocess', 'popen(', 'eval(', 'exec(', 'cmd.exe', 'powershell', 'import os'])
    return opcode_context, exec_context


def _renpy_profile_selected(*, text: str, path: DetectionValue, tags: TagSequence) -> bool:
    frozen_tags = profile_tuple_or_empty(tags)
    engine_context = infer_engine_context(frozen_tags, file_structure=profile_text_or_empty(path), strings_blob=text)
    profile_context = build_detection_profile_context(
        engine_context=engine_context,
        path=path,
        tags=frozen_tags,
        strings_blob=text,
    )
    return profile_context.active_profile == 'renpy'


def _add_pickle_and_renpy_tags(
    tags: TagList, text: str, ext: str, path: DetectionValue, data: BinaryData,
    renpy_loader_family_tags_func: RenpyLoaderFamilyScanner,
) -> None:
    pickle_opcode_context, pickle_exec_context = _pickle_contexts(text)
    if ext in {'.py', '.pyc', '.pyo'}:
        tags.extend(detect_python_pickle_opcode_exec(text, ext))
    if not _renpy_profile_selected(text=text, path=path, tags=tags):
        return
    try:
        tags.extend(renpy_loader_family_tags_func(
            text,
            path=path,
            data=data,
            pickle_opcode_context=pickle_opcode_context,
            pickle_exec_context=pickle_exec_context,
        ))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        tags.extend(failure_tags_for_stage('renpy_loader_family_scan', exc, context=path))


def _add_packed_exe_tags(tags: TagList, text: str, ext: str) -> None:
    def anyof(items: TextItems) -> bool:
        return _family_text_contains_any(text, items)

    if ext == '.exe' and (anyof(['upx0', 'upx1', 'themida', 'vmprotect', 'mpress', 'aspack', 'confuserex']) or anyof(['virtualalloc', 'virtualprotect', 'writeprocessmemory', 'getprocaddress', 'loadlibrary', 'unpack', 'payload'])):
        tags.extend(('packed_exe', 'packed_or_obfuscated'))


def explicit_missed_family_tag_scan(
    blob: DetectionValue, path: DetectionValue | None = None, data: BinaryData = None,
    *, renpy_loader_family_tags_func: RenpyLoaderFamilyScanner = renpy_loader_family_tags,
) -> list[str]:
    """Strict explicit coverage for previously missed families; requires concrete command/API context."""
    tags = []
    text = profile_text_or_empty(blob).lower()
    path_text = profile_text_or_empty(path)
    ext = get_scan_extension(path_text) if path_text else ''
    _add_game_engine_threat_tags(tags, text, path_text)
    _add_lolbin_macro_and_c2_tags(tags, text)
    _add_wallet_privilege_archive_and_dll_tags(tags, text, path_text)
    _add_reflection_anti_exfil_clipboard_and_packer_tags(tags, text)
    _add_media_stego_tags(tags, text, ext, data)
    _add_pickle_and_renpy_tags(tags, text, ext, path_text, data, renpy_loader_family_tags_func)
    _add_packed_exe_tags(tags, text, ext)
    return ordered_unique_tags(tags)
