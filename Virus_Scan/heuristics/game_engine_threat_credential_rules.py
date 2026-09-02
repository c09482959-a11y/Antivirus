"""Credential, loader, and early cross-engine game threat rules."""
from __future__ import annotations
from typing import TYPE_CHECKING

from Virus_Scan.contracts.game_engine_threats import (
    BROWSER_STORE_TERMS,
    EXFIL_TERMS,
    EXEC_TERMS,
    INJECTION_TERMS,
    READ_TERMS,
    contains_any_term,
    matches_regex,
)

if TYPE_CHECKING:
    from Virus_Scan.heuristics.game_engine_threat_rules import ThreatAdder

def credential_context(low: str) -> tuple[bool, bool, bool, bool]:
    store = contains_any_term(low, BROWSER_STORE_TERMS)
    read = contains_any_term(low, READ_TERMS)
    exfil = contains_any_term(low, EXFIL_TERMS) or (
        contains_any_term(low, ("http://", "https://"))
        and contains_any_term(low, ("post", "send", "webhook", "telegram", "discord"))
    )
    exec_ctx = contains_any_term(low, EXEC_TERMS)
    return store, read, exfil, exec_ctx


def _add_credential_store_rules(eng: str, store: bool, read: bool, exfil: bool, add: ThreatAdder) -> None:
    if not (store and (read or exfil)):
        return
    add("credential_store_exfil", "credential store path plus read/exfil context",
        "credential_access", "browser_credential_access", "browser_profile_access",
        "token_secret_access", "collection")
    if exfil:
        add("credential_store_exfil", "credential store exfil channel",
            "network_activity", "network_exfiltration", "token_exfiltration",
            "high_confidence_credential_theft")
    if eng == "rpgm":
        add("rpgm_nwjs_stealer", "NW.js/RPGM store read/exfil", "rpgm_nwjs_credential_stealer")
    elif eng == "unity":
        add("unity_token_stealer", "Unity credential/token store read/exfil", "unity_token_stealer")
    elif eng == "renpy":
        add("renpy_token_stealer", "RenPy credential/token store read/exfil", "renpy_token_stealer")


def _add_browser_and_remote_loader_rules(low: str, exfil: bool, add: ThreatAdder) -> None:
    if contains_any_term(low, ("localstorage", "sessionstorage", "document.cookie", "indexeddb")) and exfil:
        add("browser_storage_exfil", "browser storage object sent over network",
            "browser_storage_access", "collection", "network_activity", "network_exfiltration",
            "http_upload", "token_exfiltration", "rpgm_browser_storage_exfil")
    if contains_any_term(low, ("fetch(", "xmlhttprequest", "http://", "https://", "downloadstring", "urlopen")) and contains_any_term(low, ("eval(", "function(", "new function", ".then(t=>function", ".then(t => function")):
        add("generic_remote_dynamic_script_loader", "remote script fetch reaches eval/Function dynamic execution",
            "network_activity", "remote_payload_download", "dynamic_loader", "script_execution",
            "payload_execution", "remote_eval_loader")


def _add_renpy_dropper_and_socket_rules(low: str, eng: str, exec_ctx: bool, add: ThreatAdder) -> None:
    renpy_dropper_target = contains_any_term(low, ("currentversion\\run", "runonce", "startup", "autostart", "autorun", "dropper", "writeallbytes", "write_file", "copyfile", "shutil.copy", ".ps1", ".bat", ".cmd", ".exe", ".vbs", "%appdata%", "appdata"))
    renpy_write_context = contains_any_term(low, ("open(", "write(", ".write", "writeallbytes", "copyfile", "shutil.copy"))
    if eng == "renpy" and contains_any_term(low, ("persistent.", "renpy.persistent", "init python", "config.after_load_callbacks")) and renpy_dropper_target and renpy_write_context:
        add("renpy_persistent_dropper", "RenPy persistent/autoload dropper context",
            "persistence", "dropper_behavior", "autorun_persistence", "startup_persistence")
        if exec_ctx:
            add("renpy_persistent_dropper", "RenPy persistent dropper reaches execution",
                "process_exec", "script_execution", "payload_execution")
    renpy_socket_net = contains_any_term(low, ("socket.socket", "socket.create_connection", ".connect(", "connect_ex"))
    renpy_socket_io = matches_regex(low, r"(?:recv|send)\s*\(") or contains_any_term(low, (".recv", ".send", "socket.send"))
    renpy_tasking = contains_any_term(low, ("command", "task", "tasking", "cmd", "shell", "beacon", "implant", "token", "heartbeat", "checkin"))
    if eng == "renpy" and renpy_socket_net and renpy_socket_io and renpy_tasking:
        add("renpy_socket_c2", "RenPy socket tasking/C2 behavior",
            "network_activity", "network_c2", "backdoor_or_c2", "remote_command_channel", "c2_or_remote_command")
        if exec_ctx:
            add("renpy_socket_c2", "RenPy C2 reaches command execution", "process_exec", "script_execution")


def _add_injection_and_dynamic_loader_rules(low: str, eng: str, exfil: bool, exec_ctx: bool, add: ThreatAdder) -> None:
    if eng == "unity" and contains_any_term(low, INJECTION_TERMS) and contains_any_term(low, ("virtualalloc", "virtualallocex")) and contains_any_term(low, ("createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext")):
        add("unity_native_injection", "Unity native injection API chain",
            "dll_load", "memory_allocate", "memory_write", "thread_execution",
            "process_injection", "in_memory_execution", "shellcode_exec")
        if "writeprocessmemory" in low:
            add("unity_native_injection", "Unity injection includes remote memory write", "memory_write")
    loader_terms = ("loadlibrary", "assembly.load", "importlib", "require(", "eval(", "new function", "dllimport", "addcomponent", "reflection", "deserialize")
    conceal_terms = ("frombase64string", "atob(", "xor", "decrypt", "unpack", "payload", "hidden", "temp", "appdata")
    parent_child_break = contains_any_term(low, ("cmd.exe", "powershell", "schtasks", "runonce", "currentversion\\run", ".exe", ".ps1", ".bat"))
    if contains_any_term(low, loader_terms) and (contains_any_term(low, conceal_terms) or exfil or parent_child_break):
        add("dynamic_loader_intent", "dynamic loader paired with staging/exfil/persistence context",
            "dynamic_loader", "loader_intent_suspicious", "engine_continuity_break")
        if exfil:
            add("dynamic_loader_intent", "loader chain includes outbound/exfil behavior", "network_activity", "network_exfiltration")
        if parent_child_break or exec_ctx:
            add("dynamic_loader_intent", "loader chain reaches external execution", "process_exec", "script_execution")


def _add_engine_storage_rules(low: str, eng: str, store: bool, exfil: bool, add: ThreatAdder) -> None:
    if eng == "rpgm" and contains_any_term(low, ("localstorage", "sessionstorage", "indexeddb", "document.cookie", "nw.gui", "nwjs", "require('fs'", 'require("fs"')) and contains_any_term(low, ("webhook", "telegram", "discord", "upload", "send", "post", "fetch", "xmlhttprequest", "https.request")):
        add("rpgm_nwjs_storage_exfil", "RPGM/NW.js storage or cookie exfiltration",
            "rpgm_nwjs_credential_stealer", "browser_storage_access", "network_activity", "network_exfiltration", "token_exfiltration")
    if eng == "renpy" and contains_any_term(low, ("persistent", "renpy.store", "store.")) and contains_any_term(low, ("open(", "write", "copyfile", "shutil", "dump", "save")) and contains_any_term(low, (".exe", ".ps1", ".bat", ".cmd", ".vbs", "appdata", "startup")):
        add("renpy_persistent_dropper", "RenPy persistent write-to-executable/script target",
            "persistence", "dropper_behavior")
    if eng == "unity" and store and (contains_any_term(low, ("environment.getfolderpath", "specialfolder", "application.persistentdatapath", "directory.getfiles", "file.readall")) or exfil):
        add("unity_token_stealer", "Unity token/browser store discovery with read/exfil",
            "unity_token_stealer", "credential_access", "browser_profile_access", "token_secret_access")
        if exfil:
            add("unity_token_stealer", "Unity credential exfil channel", "network_activity", "network_exfiltration", "high_confidence_credential_theft")


def add_credential_and_loader_rules(low: str, eng: str, add: ThreatAdder) -> tuple[bool, bool, bool, bool]:
    """Apply credential, loader, and early cross-engine threat rules."""
    store, read, exfil, exec_ctx = credential_context(low)
    _add_credential_store_rules(eng, store, read, exfil, add)
    _add_browser_and_remote_loader_rules(low, exfil, add)
    _add_renpy_dropper_and_socket_rules(low, eng, exec_ctx, add)
    _add_injection_and_dynamic_loader_rules(low, eng, exfil, exec_ctx, add)
    _add_engine_storage_rules(low, eng, store, exfil, add)
    return store, read, exfil, exec_ctx


__all__ = ("add_credential_and_loader_rules", "credential_context")
