"""Detection-owned game-engine context builder using canonical contracts."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

from Virus_Scan.contracts.game_engine_threats import (
    BROWSER_STORE_TERMS,
    EXEC_TERMS,
    EXFIL_TERMS,
    GameThreatHit,
    INJECTION_TERMS,
    READ_TERMS,
    contains_any_term,
    engine_from_path,
    matches_regex,
    strip_negated_behavior_phrases,
)

AddThreat = Callable[[str, str, str], None]


def _owned_path_text(value: object) -> str:
    if value is None:
        return ""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_game_engine_path",
        unsupported_reason="unsafe_game_engine_path_rejected",
    )
    return "" if reason else text


def build_game_threat_context(low: str, path: str | None) -> dict[str, object]:
    store = contains_any_term(low, BROWSER_STORE_TERMS)
    read = contains_any_term(low, READ_TERMS)
    exfil = contains_any_term(low, EXFIL_TERMS) or (
        contains_any_term(low, ("http://", "https://"))
        and contains_any_term(low, ("post", "send", "webhook", "telegram", "discord"))
    )
    powershell_or_shell = contains_any_term(low, ("powershell", "-enc", "-encodedcommand", "cmd.exe", "/c ", "shell.execute", "winexec", "createprocess"))
    downloader = contains_any_term(low, ("webclient", "downloadstring", "downloadfile", "urllib.request", "urlopen", "fetch(", "xmlhttprequest", "http://", "https://"))
    external_exec = contains_any_term(low, ("process.start", "system.diagnostics.process", "subprocess.popen", "subprocess.call", "os.system", "child_process", ".exec(", ".spawn(", "popen("))
    encoded_payload = contains_any_term(low, ("frombase64string", "atob(", "base64.b64decode", "gzipstream", "zlib", "convert.frombase64string", " -enc", "-encodedcommand", "encodedcommand"))
    c2_socket = contains_any_term(low, ("tcpclient", "socket.socket", "socket.create_connection", ".connect(", "networkstream")) and (
        contains_any_term(low, ("recv", "send", "command", "cmd", "shell", "while(true)", "while true"))
        or matches_regex(low, r"tcpclient\s*\(\s*[\"'](?:\d{1,3}\.){3}\d{1,3}[\"']\s*,\s*\d{2,5}")
    )
    return {
        "store": store,
        "read": read,
        "exfil": exfil,
        "exec_ctx": contains_any_term(low, EXEC_TERMS),
        "powershell_or_shell": powershell_or_shell,
        "downloader": downloader,
        "external_exec": external_exec,
        "encoded_payload": encoded_payload,
        "persistence_api": contains_any_term(low, ("currentversion\\run", "runonce", "schtasks", "startup", "start menu/programs/startup", "winreg", "setvalueex", "copyfile", "writeallbytes")),
        "c2_socket": c2_socket,
        "reflection_exec": contains_any_term(low, ("assembly.load", "entrypoint.invoke", "methodinfo.invoke", "mono_runtime_invoke", "reflection")),
        "path": _owned_path_text(path),
    }


__all__ = (
    "BROWSER_STORE_TERMS",
    "EXEC_TERMS",
    "EXFIL_TERMS",
    "INJECTION_TERMS",
    "READ_TERMS",
    "AddThreat",
    "GameThreatHit",
    "build_game_threat_context",
    "contains_any_term",
    "engine_from_path",
    "matches_regex",
    "strip_negated_behavior_phrases",
)
