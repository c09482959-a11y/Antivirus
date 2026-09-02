"""Detection-owned engine-specific game-engine threat rules."""
from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.contracts.no_hook_materialization import no_hook_text

from Virus_Scan.detection.heuristics.game_engine_core import contains_any_term, matches_regex

if TYPE_CHECKING:
    from collections.abc import Callable

def _owned_rule_text(value: object) -> str:
    if value is None:
        return ""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_game_engine_rule_text",
        unsupported_reason="unsafe_game_engine_rule_text_rejected",
    )
    return "" if reason else str.lower(text)


def apply_engine_specific_game_engine_rules(low: str, eng: str, path: str | None, context: dict[str, object], add: Callable[..., None]) -> None:
    powershell_or_shell = bool(context["powershell_or_shell"])
    downloader = bool(context["downloader"])
    external_exec = bool(context["external_exec"])
    encoded_payload = bool(context["encoded_payload"])
    persistence_api = bool(context["persistence_api"])
    c2_socket = bool(context["c2_socket"])
    reflection_exec = bool(context["reflection_exec"])
    python_reverse_shell = (
        _owned_rule_text(path).endswith((".py", ".pyw"))
        and contains_any_term(low, ("socket.socket", "socket.create_connection", ".connect(", "connect_ex"))
        and contains_any_term(low, ("subprocess", "popen(", "os.system", "cmd.exe", "powershell", "shell"))
        and (matches_regex(low, r"(?:recv|send)\s*\(") or contains_any_term(low, (".recv", ".send", "command", "cmd", "shell", "task")))
    )
    if python_reverse_shell:
        add("python_reverse_shell", "Python socket C2/reverse shell reaches process execution", "python_exec", "socket_usage", "reverse_shell", "network_activity", "network_c2", "backdoor_or_c2", "remote_command_channel", "c2_or_remote_command", "process_exec", "script_execution", "payload_execution", "high_confidence_malware")
    if eng == "unity":
        if powershell_or_shell and external_exec:
            add("unity_external_process_execution", "Unity managed code starts shell/PowerShell", "unity_external_process_exec", "process_exec", "script_execution", "powershell_exec", "engine_continuity_break")
        if downloader and (external_exec or reflection_exec or encoded_payload):
            add("unity_download_execute", "Unity downloader reaches execution/reflection/encoded payload", "network_activity", "remote_payload_download", "payload_execution")
        if reflection_exec:
            add("unity_reflection_payload", "Unity managed reflection payload execution", "unity_reflection_execution", "dynamic_loader", "payload_execution")
        if persistence_api:
            add("unity_persistence", "Unity code manipulates autostart/persistence locations", "persistence", "autorun_persistence", "startup_persistence")
        if c2_socket:
            add("unity_socket_c2", "Unity socket tasking/C2 channel", "network_activity", "network_c2", "remote_command_channel", "c2_or_remote_command", "unity_socket_c2")
        if encoded_payload and (powershell_or_shell or external_exec or reflection_exec):
            add("unity_encoded_payload", "Unity encoded payload with execution context", "encoded_payload", "payload_decode_candidate", "payload_execution")
        if contains_any_term(low, ("loadlibrary", "getprocaddress", "nativeplugin", "pluginimport")) and contains_any_term(low, ("run", "entry", "invoke", "payload", "evil.dll", ".dll")):
            add("unity_native_loader", "Unity native plugin/LoadLibrary staging chain", "dynamic_loader", "dll_load", "loader_intent_suspicious", "engine_continuity_break")
    if eng == "rpgm":
        js_eval = contains_any_term(low, ("eval(", "function(", "new function", "window[atob", "pluginmanager.loadscript"))
        js_decode = contains_any_term(low, ("atob(", "fromcharcode", "unescape(", "decodeuricomponent", "base64"))
        js_remote = contains_any_term(low, ("fetch(", "xmlhttprequest", "http://", "https://", "pluginmanager.loadscript"))
        nw_exec = contains_any_term(low, ('require("child_process")', "require('child_process')", "child_process", ".exec(", ".spawn("))
        nw_fs = contains_any_term(low, ('require("fs")', "require('fs')", "readfilesync", "writefilesync"))
        if js_eval and (js_decode or js_remote or nw_exec):
            add("rpgm_dynamic_eval_loader", "RPGM dynamic eval/function loader with decode/remote/exec context", "rpgm_dynamic_eval_loader", "script_execution", "dynamic_loader", "loader_intent_suspicious")
        if js_remote and js_eval:
            add("rpgm_remote_eval", "RPGM remote script fetch reaches eval/function", "network_activity", "network_download", "remote_payload_download", "script_execution", "payload_execution")
        if nw_exec:
            add("rpgm_nwjs_process_exec", "RPGM/NW.js child_process execution", "rpgm_nwjs_process_exec", "process_exec", "script_execution")
        if nw_fs and (bool(context["exfil"]) or bool(context["store"]) or contains_any_term(low, ("localstorage", "document.cookie"))):
            add("rpgm_nwjs_file_exfil", "RPGM/NW.js filesystem access with exfil/credential context", "rpgm_nwjs_credential_stealer", "collection", "network_exfiltration")
        if contains_any_term(low, ("websocket", "new websocket", "ws://", "wss://")) and contains_any_term(low, ("onmessage", "eval(", "function(", "command", "cmd", "shell", "send(")):
            add("rpgm_websocket_c2", "RPGM WebSocket tasking/C2 channel", "rpgm_websocket_c2", "network_activity", "network_c2", "remote_command_channel", "c2_or_remote_command", "script_execution", "payload_execution")
    if eng == "renpy":
        if powershell_or_shell and (external_exec or contains_any_term(low, ("os.system", "subprocess", "popen"))):
            add("renpy_external_process_execution", "RenPy Python launches shell/PowerShell", "renpy_external_process_exec", "process_exec", "script_execution", "powershell_exec", "engine_continuity_break")
        if downloader and (external_exec or contains_any_term(low, ("open(", "write", ".exe", "exec("))):
            add("renpy_download_execute", "RenPy downloader writes/executes payload", "network_activity", "network_download", "remote_payload_download", "process_exec", "payload_execution")
        if encoded_payload and contains_any_term(low, ("exec(", "eval(", "os.system", "subprocess")):
            add("renpy_encoded_exec", "RenPy base64/encoded payload reaches exec/eval/process", "encoded_payload", "renpy_encoded_exec", "script_execution", "payload_execution")
        if contains_any_term(low, ("winreg", "currentversion\\run", "setvalueex", "startup")) and not contains_any_term(low, ("preferences", "save data only", "game saves")):
            add("renpy_registry_persistence", "RenPy registry/startup persistence", "persistence", "autorun_persistence", "startup_persistence", "renpy_registry_persistence")
        if ("cos\nsystem" in low or "posix\nsystem" in low or "nt\nsystem" in low or "reduce" in low) and ("powershell" in low or "cmd" in low or "system" in low):
            add("renpy_pickle_callable_reference", "RenPy pickle reduce/global system callable reference", "pickle_reduce_opcode", "pickle_callable_reference", "pickle_dangerous_global")


__all__ = ("apply_engine_specific_game_engine_rules",)
