"""MalwareBazaar and behavior-description game-engine threat rules."""
from __future__ import annotations

from collections.abc import Callable

from Virus_Scan.contracts.game_engine_threats import (
    BROWSER_STORE_TERMS,
    EXFIL_TERMS,
    INJECTION_TERMS,
    contains_any_term,
    is_malwarebazaar_malicious_metadata,
    malwarebazaar_metadata_family,
    matches_regex,
)

ThreatAdder = Callable[..., None]


def _add_collection_rule(low: str, add: ThreatAdder) -> None:
    keylogger = contains_any_term(
        low,
        ("keylogger", "keyboard hook", "hooks keyboard", "keystroke", "screenshots"),
    )
    store = contains_any_term(low, BROWSER_STORE_TERMS)
    exfil = contains_any_term(low, EXFIL_TERMS) or (
        contains_any_term(low, ("http://", "https://"))
        and contains_any_term(low, ("post", "send", "webhook", "telegram", "discord"))
    )
    mail_exfil = contains_any_term(
        low,
        ("smtp", "mail exfil", "sends stolen", "stolen data"),
    ) and contains_any_term(low, ("http post", "post", "upload", "command server", "c2"))
    if keylogger and (mail_exfil or store or exfil):
        add(
            "keylogger_exfil",
            "keylogger/screenshot collection with exfiltration context",
            "collection",
            "credential_access",
            "keylogging",
            "screen_capture",
            "network_activity",
            "network_exfiltration",
        )


def _add_c2_rule(low: str, add: ThreatAdder) -> None:
    c2_socket = contains_any_term(
        low,
        ("tcpclient", "socket.socket", "socket.create_connection", ".connect(", "networkstream"),
    ) and (
        contains_any_term(low, ("recv", "send", "command", "cmd", "shell", "while(true)", "while true"))
        or matches_regex(low, r"tcpclient\s*\(\s*[\"'](?:\d{1,3}\.){3}\d{1,3}[\"']\s*,\s*\d{2,5}")
    )
    generic_tasking = contains_any_term(
        low,
        ("beacon", "checkin", "heartbeat", "receive task", "task command", "command tasking", "c2", "cnc", "command server"),
    )
    task_action = contains_any_term(
        low,
        ("download payload", "execute", "process start", "shell command", "cmd.exe", "powershell", "ddos"),
    )
    if generic_tasking and (task_action or c2_socket):
        add(
            "generic_botnet_or_rat_c2",
            "botnet/RAT C2 tasking with execution or attack behavior",
            "network_activity",
            "network_c2",
            "backdoor_or_c2",
            "remote_command_channel",
            "c2_or_remote_command",
            "payload_execution",
        )


def _add_collection_and_c2_rules(low: str, add: ThreatAdder) -> None:
    _add_collection_rule(low, add)
    _add_c2_rule(low, add)


def _add_named_behavior_rules(low: str, add: ThreatAdder) -> None:
    if contains_any_term(low, ("ransomware", "ransom note", "aes/rsa")) and contains_any_term(low, ("encrypts documents", "encrypts files", "encrypt files", "file encryption", "deletes shadow copies", "delete shadow copies", "vssadmin", "stops services", "ransom note")):
        add("ransomware_behavior", "file encryption/ransomware behavior description", "ransomware_behavior", "destructive_behavior", "file_encryption", "shadow_copy_deletion", "high_confidence_malware")
    if contains_any_term(low, ("xmrig", "cryptominer", "crypto miner", "mining pool", "stratum+tcp", "high cpu")):
        add("cryptominer_behavior", "cryptomining behavior description", "cryptominer", "resource_hijacking", "network_activity", "mining_pool_connection")
    if contains_any_term(low, ("wiper", "overwrites mbr", "delete backups", "destroys backups", "destructive deletes", "disk wipe", "data destruction")):
        add("wiper_behavior", "destructive wiper behavior description", "destructive_behavior", "wiper_behavior", "file_deletion", "backup_deletion", "high_confidence_malware")
    if contains_any_term(low, ("rootkit", "kernel driver", "hide process", "hides process", "hide file", "kernel persistence", "ssdt", "driver hides")):
        add("rootkit_behavior", "rootkit/kernel hiding behavior description", "rootkit_behavior", "stealth_behavior", "kernel_driver", "persistence", "high_confidence_malware")
    if contains_any_term(low, ("adware", "browser injection", "unwanted browser", "injects ads", "browser hijack", "downloads payload")) and contains_any_term(low, ("download", "payload", "inject", "browser", "unwanted")):
        add("adware_payload_behavior", "adware/browser injection with download or payload behavior", "adware_behavior", "browser_injection", "remote_payload_download", "high_confidence_malware")
    if contains_any_term(low, ("mirai", "gafgyt", "iot bot", "telnet brute", "scans ports", "ddos", "cnc")) and contains_any_term(low, ("command", "connect", "attack", "scan", "brute")):
        add("iot_botnet_behavior", "IoT botnet scan/CNC/DDoS behavior description", "botnet_behavior", "network_c2", "remote_command_channel", "network_scanning", "ddos_capability")


def _add_download_and_persistence_rules(low: str, add: ThreatAdder) -> None:
    powershell_or_shell = contains_any_term(low, ("powershell", "-enc", "-encodedcommand", "cmd.exe", "/c ", "shell.execute", "winexec", "createprocess"))
    downloader = contains_any_term(low, ("webclient", "downloadstring", "downloadfile", "urllib.request", "urlopen", "fetch(", "xmlhttprequest", "http://", "https://"))
    external_exec = contains_any_term(low, ("process.start", "system.diagnostics.process", "subprocess.popen", "subprocess.call", "os.system", "child_process", ".exec(", ".spawn(", "popen("))
    encoded_payload = contains_any_term(low, ("frombase64string", "atob(", "base64.b64decode", "gzipstream", "zlib", "convert.frombase64string", " -enc", "-encodedcommand", "encodedcommand"))
    persistence_api = contains_any_term(low, ("currentversion\\run", "runonce", "schtasks", "startup", "start menu/programs/startup", "winreg", "setvalueex", "copyfile", "writeallbytes"))
    generic_download_exec = downloader and (
        external_exec
        or encoded_payload
        or contains_any_term(low, ("execute payload", "process start", "write temp exe", "write temp", "download execute", "downloaded payload"))
    )
    if generic_download_exec:
        add("generic_download_execute", "downloaded/decoded payload reaches execution", "network_activity", "remote_payload_download", "payload_execution")
    if powershell_or_shell and encoded_payload:
        add("generic_encoded_powershell_loader", "encoded PowerShell/shell loader behavior", "powershell_exec", "encoded_payload", "payload_decode_candidate", "script_execution", "payload_execution")
    if persistence_api and not contains_any_term(low, ("preferences", "save data only", "game saves", "local save data")):
        add("generic_persistence", "autostart/run-key/startup persistence behavior", "persistence", "autorun_persistence", "startup_persistence")


def _add_injection_and_macro_rules(low: str, add: ThreatAdder) -> None:
    powershell_or_shell = contains_any_term(low, ("powershell", "-enc", "-encodedcommand", "cmd.exe", "/c ", "shell.execute", "winexec", "createprocess"))
    downloader = contains_any_term(low, ("webclient", "downloadstring", "downloadfile", "urllib.request", "urlopen", "fetch(", "xmlhttprequest", "http://", "https://"))
    encoded_payload = contains_any_term(low, ("frombase64string", "atob(", "base64.b64decode", "gzipstream", "zlib", "convert.frombase64string", " -enc", "-encodedcommand", "encodedcommand"))
    injection_chain = (
        contains_any_term(low, INJECTION_TERMS)
        and contains_any_term(low, ("virtualalloc", "virtualallocex"))
        and contains_any_term(low, ("createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext"))
    )
    if injection_chain:
        add("generic_native_injection", "native injection API chain behavior", "dll_load", "memory_allocate", "thread_execution", "process_injection", "shellcode_exec")
    office_macro = contains_any_term(low, ("vba", "autoopen", "macro dropper", "office macro"))
    if office_macro and (powershell_or_shell or downloader or encoded_payload):
        add("office_macro_dropper", "Office macro dropper behavior embedded in metadata/description", "macro_dropper", "powershell_exec", "remote_payload_download", "payload_execution")


def _add_metadata_family_rules(low: str, add: ThreatAdder) -> None:
    if is_malwarebazaar_malicious_metadata(low):
        add("malware_metadata_category", "MalwareBazaar signature/tags/vendor metadata identifies malicious behavior category", "malware_metadata_category", "high_confidence_malware")
    family = malwarebazaar_metadata_family(low)
    if family:
        add("malwarebazaar_confirmed_family", "MalwareBazaar signature/tag metadata identifies confirmed malware family", "malwarebazaar_known_family", "known_malware_family", "high_confidence_malware")


def add_behavior_metadata_rules(low: str, add: ThreatAdder) -> None:
    _add_collection_and_c2_rules(low, add)
    _add_named_behavior_rules(low, add)
    _add_download_and_persistence_rules(low, add)
    _add_injection_and_macro_rules(low, add)
    _add_metadata_family_rules(low, add)


__all__ = ("add_behavior_metadata_rules",)
