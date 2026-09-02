"""Bounded game-engine threat rule groups."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from Virus_Scan.contracts.game_engine_threats import contains_any_term, matches_regex
from Virus_Scan.heuristics.no_hook import heuristic_lower

ThreatAdder = Callable[..., None]


@dataclass(frozen=True, slots=True)
class _EngineExecutionRequest:
    low: str
    path: str | None
    engine: str
    store: bool
    exfil: bool
    add: ThreatAdder


@dataclass(frozen=True, slots=True)
class _EngineExecutionSignals:
    low: str
    powershell_or_shell: bool
    downloader: bool
    external_exec: bool
    encoded_payload: bool
    persistence_api: bool
    c2_socket: bool
    reflection_exec: bool
    add: ThreatAdder


def _add_engine_execution_rules(request: _EngineExecutionRequest) -> None:
    low = request.low
    path = request.path
    eng = request.engine
    store = request.store
    exfil = request.exfil
    add = request.add
    powershell_or_shell = contains_any_term(low, ("powershell", "-enc", "-encodedcommand", "cmd.exe", "/c ", "shell.execute", "winexec", "createprocess"))
    downloader = contains_any_term(low, ("webclient", "downloadstring", "downloadfile", "urllib.request", "urlopen", "fetch(", "xmlhttprequest", "http://", "https://"))
    external_exec = contains_any_term(low, ("process.start", "system.diagnostics.process", "subprocess.popen", "subprocess.call", "os.system", "child_process", ".exec(", ".spawn(", "popen("))
    encoded_payload = contains_any_term(low, ("frombase64string", "atob(", "base64.b64decode", "gzipstream", "zlib", "convert.frombase64string", " -enc", "-encodedcommand", "encodedcommand"))
    persistence_api = contains_any_term(low, ("currentversion\\run", "runonce", "schtasks", "startup", "start menu/programs/startup", "winreg", "setvalueex", "copyfile", "writeallbytes"))
    c2_socket = contains_any_term(low, ("tcpclient", "socket.socket", "socket.create_connection", ".connect(", "networkstream")) and (
        contains_any_term(low, ("recv", "send", "command", "cmd", "shell", "while(true)", "while true"))
        or matches_regex(low, r"tcpclient\s*\(\s*[\"'](?:\d{1,3}\.){3}\d{1,3}[\"']\s*,\s*\d{2,5}")
    )
    reflection_exec = contains_any_term(low, ("assembly.load", "entrypoint.invoke", "methodinfo.invoke", "mono_runtime_invoke", "reflection"))

    python_reverse_shell = (
        heuristic_lower(path).endswith((".py", ".pyw"))
        and contains_any_term(low, ("socket.socket", "socket.create_connection", ".connect(", "connect_ex"))
        and contains_any_term(low, ("subprocess", "popen(", "os.system", "cmd.exe", "powershell", "shell"))
        and (matches_regex(low, r"(?:recv|send)\s*\(") or contains_any_term(low, (".recv", ".send", "command", "cmd", "shell", "task")))
    )
    if python_reverse_shell:
        add("python_reverse_shell", "Python socket C2/reverse shell reaches process execution",
            "python_exec", "socket_usage", "reverse_shell", "network_activity",
            "network_c2", "backdoor_or_c2", "remote_command_channel",
            "c2_or_remote_command", "process_exec", "script_execution",
            "payload_execution", "high_confidence_malware")

    signals = _EngineExecutionSignals(
        low=low,
        powershell_or_shell=powershell_or_shell,
        downloader=downloader,
        external_exec=external_exec,
        encoded_payload=encoded_payload,
        persistence_api=persistence_api,
        c2_socket=c2_socket,
        reflection_exec=reflection_exec,
        add=add,
    )
    if eng == "unity":
        _add_unity_execution_rules(signals)
    if eng == "rpgm":
        _add_rpgm_execution_rules(low, store=store, exfil=exfil, add=add)
    if eng == "renpy":
        _add_renpy_execution_rules(signals)


def _add_unity_execution_rules(signals: _EngineExecutionSignals) -> None:
    low = signals.low
    add = signals.add
    if signals.powershell_or_shell and signals.external_exec:
        add("unity_external_process_execution", "Unity managed code starts shell/PowerShell",
            "unity_external_process_exec", "process_exec", "script_execution", "powershell_exec", "engine_continuity_break")
    if signals.downloader and (signals.external_exec or signals.reflection_exec or signals.encoded_payload):
        add("unity_download_execute", "Unity downloader reaches execution/reflection/encoded payload",
            "network_activity", "network_download", "remote_payload_download", "payload_execution")
    if signals.reflection_exec:
        add("unity_reflection_payload", "Unity managed reflection payload execution",
            "unity_reflection_execution", "dynamic_loader", "payload_execution")
    if signals.persistence_api:
        add("unity_persistence", "Unity code manipulates autostart/persistence locations",
            "persistence", "autorun_persistence", "startup_persistence")
    if signals.c2_socket:
        add("unity_socket_c2", "Unity socket tasking/C2 channel",
            "network_activity", "network_c2", "remote_command_channel", "c2_or_remote_command", "unity_socket_c2")
    if signals.encoded_payload and (signals.powershell_or_shell or signals.external_exec or signals.reflection_exec):
        add("unity_encoded_payload", "Unity encoded payload with execution context",
            "encoded_payload", "payload_decode_candidate", "payload_execution")
    if contains_any_term(low, ("loadlibrary", "getprocaddress", "nativeplugin", "pluginimport")) and contains_any_term(low, ("run", "entry", "invoke", "payload", "evil.dll", ".dll")):
        add("unity_native_loader", "Unity native plugin/LoadLibrary staging chain",
            "dynamic_loader", "dll_load", "loader_intent_suspicious", "engine_continuity_break")


def _add_rpgm_execution_rules(low: str, *, store: bool, exfil: bool, add: ThreatAdder) -> None:
    js_eval = contains_any_term(low, ("eval(", "function(", "new function", "window[atob", "pluginmanager.loadscript"))
    js_decode = contains_any_term(low, ("atob(", "fromcharcode", "unescape(", "decodeuricomponent", "base64"))
    js_remote = contains_any_term(low, ("fetch(", "xmlhttprequest", "http://", "https://", "pluginmanager.loadscript"))
    nw_exec = contains_any_term(low, ("require(\"child_process\")", "require('child_process')", "child_process", ".exec(", ".spawn("))
    nw_fs = contains_any_term(low, ("require(\"fs\")", "require('fs')", "readfilesync", "writefilesync"))
    if js_eval and (js_decode or js_remote or nw_exec):
        add("rpgm_dynamic_eval_loader", "RPGM dynamic eval/function loader with decode/remote/exec context",
            "rpgm_dynamic_eval_loader", "script_execution", "dynamic_loader", "loader_intent_suspicious")
    if js_remote and js_eval:
        add("rpgm_remote_eval", "RPGM remote script fetch reaches eval/function",
            "network_activity", "network_download", "remote_payload_download", "script_execution", "payload_execution")
    if nw_exec:
        add("rpgm_nwjs_process_exec", "RPGM/NW.js child_process execution",
            "rpgm_nwjs_process_exec", "process_exec", "script_execution")
    if nw_fs and (exfil or store or contains_any_term(low, ("localstorage", "document.cookie"))):
        add("rpgm_nwjs_file_exfil", "RPGM/NW.js filesystem access with exfil/credential context",
            "rpgm_nwjs_credential_stealer", "collection", "network_exfiltration")
    if contains_any_term(low, ("websocket", "new websocket", "ws://", "wss://")) and contains_any_term(low, ("onmessage", "eval(", "function(", "command", "cmd", "shell", "send(")):
        add("rpgm_websocket_c2", "RPGM WebSocket tasking/C2 channel",
            "rpgm_websocket_c2", "network_activity", "network_c2", "remote_command_channel", "c2_or_remote_command", "script_execution", "payload_execution")


def _add_renpy_execution_rules(signals: _EngineExecutionSignals) -> None:
    low = signals.low
    add = signals.add
    if signals.powershell_or_shell and (signals.external_exec or contains_any_term(low, ("os.system", "subprocess", "popen"))):
        add("renpy_external_process_execution", "RenPy Python launches shell/PowerShell",
            "renpy_external_process_exec", "process_exec", "script_execution", "powershell_exec", "engine_continuity_break")
    if signals.downloader and (signals.external_exec or contains_any_term(low, ("open(", "write", ".exe", "exec("))):
        add("renpy_download_execute", "RenPy downloader writes/executes payload",
            "network_activity", "network_download", "remote_payload_download", "process_exec", "payload_execution")
    if signals.encoded_payload and contains_any_term(low, ("exec(", "eval(", "os.system", "subprocess")):
        add("renpy_encoded_exec", "RenPy base64/encoded payload reaches exec/eval/process",
            "encoded_payload", "renpy_encoded_exec", "script_execution", "payload_execution")
    if contains_any_term(low, ("winreg", "currentversion\\run", "setvalueex", "startup")) and not contains_any_term(low, ("preferences", "save data only", "game saves")):
        add("renpy_registry_persistence", "RenPy registry/startup persistence",
            "persistence", "autorun_persistence", "startup_persistence", "renpy_registry_persistence")
    if ("cos\nsystem" in low or "posix\nsystem" in low or "nt\nsystem" in low or "reduce" in low) and ("powershell" in low or "cmd" in low or "system" in low):
        add("renpy_pickle_callable_reference", "RenPy pickle reduce/global system callable reference",
            "pickle_reduce_opcode", "pickle_callable_reference", "pickle_dangerous_global",
            "process_exec", "script_execution", "renpy", "renpy_script")


__all__ = ()
