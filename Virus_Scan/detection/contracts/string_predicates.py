"""Detection-owned string predicate helpers.

These helpers replace private scanner/core helper imports inside detection. They
are static-importable, side-effect free, and owned by detection.
"""

from __future__ import annotations

import re
from pathlib import Path

from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.contracts.string_extraction import (
    build_extraction_view,
    looks_like_base64_payload,
    normalize_obfuscated_text,
)
from Virus_Scan.utils.text_validation import tag_validation_text, text_boundary_value


PLR2004N126 = 126
PLR2004N32 = 32

PredicateValue = object


def _predicate_text(value: PredicateValue) -> str:
    text = text_boundary_value(value, unsupported="")
    if text is None:
        return ""
    return text


def _predicate_text_lower(value: PredicateValue) -> str:
    return _predicate_text(value).lower()


def _iter_predicate_needles(needles: PredicateValue) -> tuple[PredicateValue, ...]:
    if needles is None:
        return ()
    if type(needles) is tuple:
        return needles
    if type(needles) is list:
        return tuple(needles)
    if type(needles) is set:
        return tuple(sorted(set.__iter__(needles), key=_predicate_text_lower))
    if type(needles) is frozenset:
        return tuple(sorted(frozenset.__iter__(needles), key=_predicate_text_lower))
    return ()


def context_any(text: PredicateValue, needles: PredicateValue) -> bool:
    low = _predicate_text_lower(text)
    return any(_predicate_text_lower(needle) in low for needle in _iter_predicate_needles(needles))


def has_any_text(text: PredicateValue, needles: PredicateValue) -> bool:
    return context_any(text, needles)


def context_regex(pattern: str, text: PredicateValue, flags: int = 0) -> bool:
    return re.search(pattern, _predicate_text(text), flags | re.IGNORECASE) is not None


def ascii_visibility_ratio(buf: bytes | bytearray | memoryview | None) -> float:
    if buf is None:
        return 0.0
    if type(buf) is bytes:
        data = buf
    elif type(buf) is bytearray:
        data = bytes(buf)
    elif type(buf) is memoryview:
        data = buf.tobytes()
    else:
        return 0.0
    if len(data) == 0:
        return 0.0
    visible = sum(1 for byte in data if byte in (9, 10, 13) or PLR2004N32 <= byte <= PLR2004N126)
    return visible / float(len(data))


def is_renpy_bytecode_path(path: PredicateValue) -> bool:
    normalized = _predicate_text_lower(path).replace("\\", "/")
    return normalized.endswith((".rpyc", ".rpyb")) or "/renpy/" in normalized


def behavior_text_bits(strings_blob: PredicateValue = "", path: PredicateValue = None) -> tuple[str, str, str, str]:
    text = tag_validation_text(strings_blob)
    compact = re.sub(r"\s+", " ", text)
    try:
        path_text = _predicate_text(path)
        name = Path(path_text).name.lower()
        ext = Path(path_text).suffix.lower()
    except RECOVERABLE_RUNTIME_ERRORS:
        name, ext = "", ""
    return text, compact, name, ext


def has_command_exec_behavior(text: PredicateValue) -> bool:
    text_value = _predicate_text(text)
    return (
        (
            context_regex(r"\b(?:powershell|pwsh)(?:\.exe)?\b", text_value)
            and context_regex(r"(?:-|/)enc(?:odedcommand)?\b|invoke-expression|\biex\b|downloadstring|downloadfile|start-process", text_value)
        )
        or context_regex(r"\bcmd(?:\.exe)?\s*(?:/c|/k)\b", text_value)
        or context_regex(r"\b(?:createprocess|shellexecute|winexec)\b", text_value)
        or (
            context_regex(r"\b(?:subprocess\.(?:popen|run|call)|popen\(|os\.system\()", text_value)
            and has_any_text(text_value, ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "shell=true", "http://", "https://"])
        )
        or (
            context_regex(r"\b(?:eval|exec)\s*\(", text_value)
            and has_any_text(text_value, ["base64", "frombase64string", "compile(", "request", "socket", "download", "http://", "https://", "pickle", "marshal.loads"])
        )
    )


def has_dll_hijack_behavior(text: PredicateValue) -> bool:
    text_value = _predicate_text(text)
    load_ctx = has_any_text(text_value, ["loadlibrary", "setdlldirectory", "adddlldirectory", "dll search order", "side-load", "sideload"])
    untrusted_path = has_any_text(text_value, ["current directory", "%temp%", "appdata", "startup", "writable", "copyfile", "writeallbytes", "drop", "plant", "side-load", "sideload"])
    return load_ctx and untrusted_path and ".dll" in text_value.lower()


def has_input_collection_behavior(text: PredicateValue) -> bool:
    text_value = _predicate_text(text)
    benign_ui_context = has_any_text(text_value, ["pygame.keydown", "pygame.keyup", "pygame.textinput", "pygame.mousemotion", "pygame.mousebuttondown", "pygame.mousebuttonup", "displayable", "scene_lists", "renpy.display", "set_mouse_pos", "get_mouse_pos", "screenshot_surface", "save_screenshot", "thumbnail_width", "thumbnail_height"])
    strong_input_api = has_any_text(text_value, ["getasynckeystate", "setwindowshookex", "wh_keyboard", "wh_keyboard_ll", "getrawinputdata", "keyboard hook", "keylogger", "keylog", "openclipboard", "getclipboarddata", "clipboard monitor"])
    sensitive_target = has_any_text(text_value, ["password", "credential", "token", "cookie", "wallet", "seed phrase", "private key", "login data", "cookies.sqlite", "discord token", "telegram", "browser profile"])
    exfil_target = has_any_text(text_value, ["uploadfile", "uploadstring", "multipart/form-data", "webhook", "discord.com/api/webhooks", "api.telegram.org", "ftp://", "http post", "postasync", "requests.post", ".send(", "socket.send"])
    if benign_ui_context and not (strong_input_api and (sensitive_target or exfil_target)):
        return False
    return strong_input_api and (sensitive_target or exfil_target)


def is_renpy_tts_wscript_context(text: PredicateValue, name: PredicateValue = "") -> bool:
    low = _predicate_text_lower(text)
    file_name = _predicate_text_lower(name)
    return (
        ("wscript" in low or "sapi.spvoice" in low or "text-to-speech" in low or "tts" in low)
        and ("renpy" in low or file_name.endswith(("tts.rpy", "self_voicing.rpy")) or "self voicing" in low)
    )


def has_lolbin_script_behavior(text: PredicateValue) -> bool:
    text_value = _predicate_text(text)
    if is_renpy_tts_wscript_context(text_value):
        return False
    return (
        (
            context_regex(r"\b(?:wscript|cscript)(?:\.exe)?\b", text_value)
            and context_regex(r"\.(?:vbs|vbe|js|jse|wsf)\b|//e:|wscript\.shell|createobject\(", text_value)
            and has_any_text(text_value, ["http://", "https://", "powershell", "cmd.exe", "run(", "shell", "appdata", "%temp%", "startup"])
        )
        or (context_regex(r"\bmshta(?:\.exe)?\b", text_value) and context_regex(r"https?://|javascript:|vbscript:|\.hta\b", text_value))
        or (context_regex(r"\bregsvr32(?:\.exe)?\b", text_value) and context_regex(r"scrobj\.dll|/i:https?://|\.sct|scriptlet", text_value))
        or (context_regex(r"\brundll32(?:\.exe)?\b", text_value) and context_regex(r"javascript:|mshtml|comsvcs\.dll|https?://|minidump", text_value))
    )


def has_macro_exec_behavior(text: PredicateValue) -> bool:
    text_value = _predicate_text(text)
    macro = has_any_text(text_value, ["autoopen", "document_open", "workbook_open", "auto_open", "vbproject", "vba", "createobject("])
    exec_or_net = has_any_text(text_value, ["shell(", "run(", "powershell", "cmd.exe", "wscript.shell", "urldownloadtofile", "downloadfile", "downloadstring", "winmgmts:"])
    return macro and exec_or_net


def has_pickle_exec_behavior(text: PredicateValue) -> bool:
    text_value = _predicate_text(text)
    pickle_terms = has_any_text(text_value, ["pickle.loads", "pickle.load(", "pickletools", "pickletools.dis", "__reduce__", "__reduce_ex__", "stack_global", "opcode: global", "opcode: reduce", "global opcode", "reduce opcode", "cos\\nsystem", "cposix\\nsystem", "cnt\\nsystem", "posix\\nsystem", "nt\\nsystem", "builtins\\neval", "builtins\\nexec", "subprocess\\npopen"])
    dangerous_callable = has_any_text(text_value, ["cos\\nsystem", "cposix\\nsystem", "cnt\\nsystem", "posix\\nsystem", "nt\\nsystem", "builtins\\neval", "builtins\\nexec", "subprocess\\npopen"])
    return pickle_terms and (has_command_exec_behavior(text_value) or dangerous_callable)


BROAD_UNVALIDATED_DETECTION_TAGS = frozenset({
    "process_exec", "script_execution", "network_activity", "persistence",
    "defense_evasion", "collection", "exfiltration", "dropper_behavior",
})


def validate_high_risk_tag(tag: PredicateValue, strings_blob: PredicateValue = "", path: PredicateValue = None) -> bool:
    """Return True only when a high-risk tag has enough concrete context."""
    t = _predicate_text(tag).strip().lower()
    text = tag_validation_text(strings_blob)
    is_rpyc = is_renpy_bytecode_path(path)
    exec_ctx = has_any_text(text, ["subprocess", "os.system", "popen(", "popen", "createprocess", "shellexecute", "winexec", "cmd.exe", "cmd /c", "powershell", "pwsh", "start-process", "exec(", "eval(", "renpy.python.py_exec_bytecode"])
    net_ctx = has_any_text(text, ["http://", "https://", "socket", "connect(", "webhook", "telegram", "discord"])
    compact = re.sub(r"[^a-z0-9_./$\\-]+", " ", text)
    if t in {"wmi_exec", "win32_process_create"}:
        strong_wmi = has_any_text(text, ["wmic process call create", "win32_process.create", "invoke-wmimethod", "get-wmiobject", "invoke-cimmethod", "wmic.exe"]) or ("wmic" in compact and "process" in compact and "call" in compact and "create" in compact) or ("win32_process" in compact and "create" in compact)
        return strong_wmi and exec_ctx
    if t in {"admin_share_access", "smb_activity", "impacket_exec"}:
        strong_smb = has_any_text(text, ["\\admin$", "\\ipc$", "\\c$", "net use", "smbexec", "wmiexec", "psexec.py", "impacket", "tree_connect"])
        return strong_smb and (exec_ctx or "net use" in text or "impacket" in text)
    if t in {"remote_service_creation", "remote_scheduled_task", "remote_registry"}:
        return exec_ctx and has_any_text(text, ["createservice", "openscmanager", "svcctl", "sc create", "schtasks /s", "reg connect", "remote registry"])
    if t in {"credential_dump_attempt", "lsass_access", "memory_dump", "credential_api_access"}:
        return has_any_text(text, ["mimikatz", "sekurlsa", "lsass", "minidumpwritedump", "comsvcs.dll", "procdump", "nanodump", "credread", "credenumerate", "cryptunprotectdata"])
    if t == "token_secret_access":
        return has_any_text(text, ["refresh_token", "access_token", "aws_access_key_id", "secret_access_key"]) and (net_ctx or not is_rpyc)
    if t in {"powershell_exec", "cmd_exec", "process_exec", "fileless_execution"}:
        return exec_ctx
    if t in {"amsi_bypass_attempt", "etw_bypass_attempt", "amsi_scanbuffer_patch", "etw_eventwrite_patch"}:
        bypass_terms = has_any_text(text, ["amsiscanbuffer", "amsi.dll", "amsiinitfailed", "amsiutils", "patch amsi", "disable amsi", "bypass amsi", "etweventwrite", "nttraceevent", "patch etw", "disable etw"])
        patch_terms = has_any_text(text, ["virtualprotect", "writeprocessmemory", "memcpy", "patch", "0x31", "0xc3"])
        return bypass_terms and (patch_terms or exec_ctx)
    if t in {"process_injection", "memory_write", "memory_protect", "thread_execution"}:
        return has_any_text(text, ["writeprocessmemory", "virtualprotect", "virtualallocex", "createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext"])
    if t in {"network_c2", "backdoor_or_c2", "remote_command_channel", "c2_beacon", "c2_or_remote_command"}:
        c2_terms = has_any_text(text, ["command and control", "c2", "beacon", "checkin", "check-in", "sleep jitter", "/api/checkin", "/gate.php", "/panel/", "reverse shell", "getcommand", "tasking", "implant", "heartbeat", "poll", "cmd=", "post /api"])
        socket_terms = ("recv(" in text or "send(" in text) and has_any_text(text, ["command", "cmd", "task", "shell", "beacon", "implant"])
        return net_ctx and (c2_terms or socket_terms) and exec_ctx
    if t in {"archive_dropper", "embedded_archive_payload", "dropper_behavior"}:
        archive_ctx = has_any_text(text, ["zipfile", "extractall", "7z.exe", "rar.exe", "tarfile", "cabinet", "expand.exe", "gzipstream", "deflatestream", "pk\x03\x04"])
        payload_ctx = has_any_text(text, [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr", ".msi", "writeallbytes", "createfile", "%temp%", "appdata", "startup", "currentversion\\run"])
        write_or_extract_ctx = has_any_text(text, ["extractall", "extract(", "writeallbytes", "createfile", "open(", "copyfile", "movefile", "safe_extract", "unpack", "decompress"])
        return archive_ctx and payload_ctx and write_or_extract_ctx and (
            exec_ctx or has_any_text(text, ["startup", "currentversion\\run", "schtasks", "service create"])
        )
    if t in {"pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode", "pickle_external_executable_reference"}:
        pickle_terms = has_any_text(text, ["pickle.loads", "pickle.load(", "pickletools", "pickletools.dis", "__reduce__", "__reduce_ex__", "stack_global", "opcode: global", "opcode: reduce", "global opcode", "reduce opcode", "cos\\nsystem", "cposix\\nsystem", "cnt\\nsystem", "posix\\nsystem", "nt\\nsystem", "builtins\\neval", "builtins\\nexec"])
        plaintext_global_reduce = (
            all(term in text for term in ("pickle", "global", "reduce"))
            and has_any_text(text, ["cmd.exe", "powershell", "os system", "os.system", "subprocess", "popen"])
        )
        return (pickle_terms or plaintext_global_reduce) and exec_ctx
    if t in {"persistence", "registry_persistence", "startup_persistence", "autorun_persistence", "run_key_mod", "registry_run_key"}:
        return has_any_text(text, ["currentversion\\run", "\\software\\microsoft\\windows\\currentversion\\run", "start menu\\programs\\startup", "startup", "appdata", "runonce", "schtasks", "createservice", "service_auto_start", "crontab", "systemctl enable"])
    if t in {"schtasks_create", "scheduled_task", "scheduled_execution"}:
        return "schtasks" in compact and (
            "/create" in compact or " /tn " in compact or " /tr " in compact
        ) and exec_ctx
    if t == "shadowcopy_delete":
        return (("shadowcopy" in compact and "delete" in compact) or "vssadmin delete shadows" in text) and exec_ctx
    return t not in BROAD_UNVALIDATED_DETECTION_TAGS

__all__ = (
    "ascii_visibility_ratio",
    "behavior_text_bits",
    "build_extraction_view",
    "context_any",
    "context_regex",
    "has_any_text",
    "has_command_exec_behavior",
    "has_dll_hijack_behavior",
    "has_input_collection_behavior",
    "has_lolbin_script_behavior",
    "has_macro_exec_behavior",
    "has_pickle_exec_behavior",
    "is_renpy_bytecode_path",
    "is_renpy_tts_wscript_context",
    "looks_like_base64_payload",
    "normalize_obfuscated_text",
    "validate_high_risk_tag",
)
