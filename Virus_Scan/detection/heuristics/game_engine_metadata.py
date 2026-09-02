"""Detection-owned MalwareBazaar and generic behavior metadata rules."""
from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.detection.heuristics.game_engine_core import INJECTION_TERMS, contains_any_term
from Virus_Scan.contracts.game_engine_threats import (
    is_malwarebazaar_malicious_metadata,
    malwarebazaar_metadata_family,
)

if TYPE_CHECKING:
    from collections.abc import Callable

def apply_metadata_game_engine_rules(low: str, context: dict[str, object], add: Callable[..., None]) -> None:
    store = bool(context["store"])
    exfil = bool(context["exfil"])
    downloader = bool(context["downloader"])
    external_exec = bool(context["external_exec"])
    encoded_payload = bool(context["encoded_payload"])
    powershell_or_shell = bool(context["powershell_or_shell"])
    persistence_api = bool(context["persistence_api"])
    c2_socket = bool(context["c2_socket"])
    keylogger = contains_any_term(low, ("keylogger", "keyboard hook", "hooks keyboard", "keystroke", "screenshots"))
    mail_exfil = contains_any_term(low, ("smtp", "mail exfil", "sends stolen", "stolen data")) and contains_any_term(low, ("http post", "post", "upload", "command server", "c2"))
    if keylogger and (mail_exfil or store or exfil):
        add("keylogger_exfil", "keylogger/screenshot collection with exfiltration context", "collection", "credential_access", "keylogging", "screen_capture", "network_activity", "network_exfiltration")
    generic_tasking = contains_any_term(low, ("beacon", "checkin", "heartbeat", "receive task", "task command", "command tasking", "c2", "cnc", "command server"))
    if generic_tasking and (contains_any_term(low, ("download payload", "execute", "process start", "shell command", "cmd.exe", "powershell", "ddos")) or c2_socket):
        add("generic_botnet_or_rat_c2", "botnet/RAT C2 tasking with execution or attack behavior", "network_activity", "network_c2", "backdoor_or_c2", "remote_command_channel", "c2_or_remote_command", "payload_execution")
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
    if downloader and (external_exec or encoded_payload or contains_any_term(low, ("execute payload", "process start", "write temp exe", "write temp", "download execute", "downloaded payload"))):
        add("generic_download_execute", "downloaded/decoded payload reaches execution", "network_activity", "remote_payload_download", "payload_execution")
    if powershell_or_shell and encoded_payload:
        add("generic_encoded_powershell_loader", "encoded PowerShell/shell loader behavior", "powershell_exec", "encoded_payload", "payload_decode_candidate", "script_execution", "payload_execution")
    if persistence_api and not contains_any_term(low, ("preferences", "save data only", "game saves", "local save data")):
        add("generic_persistence", "autostart/run-key/startup persistence behavior", "persistence", "autorun_persistence", "startup_persistence")
    if contains_any_term(low, INJECTION_TERMS) and contains_any_term(low, ("virtualalloc", "virtualallocex")) and contains_any_term(low, ("createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext")):
        add("generic_native_injection", "native injection API chain behavior", "dll_load", "memory_allocate", "thread_execution", "process_injection", "shellcode_exec")
    if contains_any_term(low, ("vba", "autoopen", "macro dropper", "office macro")) and (powershell_or_shell or downloader or encoded_payload):
        add("office_macro_dropper", "Office macro dropper behavior embedded in metadata/description", "macro_dropper", "powershell_exec", "remote_payload_download", "payload_execution")
    if is_malwarebazaar_malicious_metadata(low):
        add("malware_metadata_category", "MalwareBazaar signature/tags/vendor metadata identifies malicious behavior category", "malware_metadata_category", "high_confidence_malware")
    family = malwarebazaar_metadata_family(low)
    if family:
        add("malwarebazaar_confirmed_family", "MalwareBazaar signature/tag metadata identifies confirmed malware family", "malwarebazaar_known_family", "known_malware_family", "high_confidence_malware")


__all__ = ("apply_metadata_game_engine_rules",)
