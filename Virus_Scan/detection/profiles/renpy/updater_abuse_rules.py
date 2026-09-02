"""Ren'Py updater abuse text rules."""

from __future__ import annotations

import re

from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.contracts.string_predicates import context_regex
from Virus_Scan.detection.profiles.renpy.updater_text import has_any_text

FETCH_APIS = (
    "requests.get", "requests.post", "urlopen(", "urlretrieve(",
    "urllib.request", "downloadfile", "downloadstring", "http://", "https://",
)
SUBPROCESS_APIS = ("subprocess", "popen(", "os.system", "spawn", "createprocess", "shellexecute")
NORMAL_ZSYNC_TERMS = ("zsync", "zsyncmake", "zsync_path", "zsync_update", "zsyncmake.exe")
SHELL_ABUSE_TERMS = (
    "powershell -enc", "-encodedcommand", "encodedcommand", "invoke-expression", "iex(",
    "cmd.exe /c", "cmd /c", "mshta.exe", "regsvr32.exe", "rundll32.exe", "wscript.shell",
    "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe",
)
STAGING_AREA_TERMS = (
    "appdata", "%temp%", "tempfile", "mkdtemp", r"currentversion\run",
    r"start menu\programs\startup", "programdata",
)
PAYLOAD_WRITE_TERMS = ("open(", "write(", "write_bytes", "shutil.copy", "copyfile")
PERSISTENCE_TERMS = (
    r"currentversion\run", "schtasks /create", "schtasks.exe /create",
    r"start menu\programs\startup", "startup_persistence", "createservice", "sc create",
)
SUSPICIOUS_ENDPOINT_TERMS = (
    "discord.com/api/webhooks", "api.telegram.org", "pastebin.com/raw", "raw.githubusercontent.com",
    ".onion", "ngrok", "duckdns", "no-ip", "webhook.site",
)
C2_TERMS = ("socket.connect", "reverse shell", "meterpreter", "c2", "beacon", "command channel")
BENIGN_UPDATE_TOOLS = frozenset({"zsync.exe", "zsyncmake.exe", "zsync", "zsyncmake"})
EXECUTABLE_REFERENCE_PATTERN = re.compile(r'[^\s\'"]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|jse|hta|scr|msi|jar)\b')


def updater_behavior_context(text: str) -> dict[str, bool]:
    return {
        "has_fetch": has_any_text(text, FETCH_APIS),
        "has_subprocess": has_any_text(text, SUBPROCESS_APIS),
        "normal_zsync": has_any_text(text, NORMAL_ZSYNC_TERMS),
        "shell_abuse": has_any_text(text, SHELL_ABUSE_TERMS),
    }


def suspicious_executable_refs(text: str) -> tuple[str, ...]:
    try:
        refs = tuple(match.group(0).lower() for match in EXECUTABLE_REFERENCE_PATTERN.finditer(text))
    except RECOVERABLE_RUNTIME_ERRORS:
        refs = ()
    return tuple(ref for ref in refs if not any(tool in ref for tool in BENIGN_UPDATE_TOOLS))


def has_suspicious_endpoint(text: str) -> bool:
    return has_any_text(text, SUSPICIOUS_ENDPOINT_TERMS) or bool(context_regex(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", text))


__all__ = (
    "C2_TERMS",
    "PAYLOAD_WRITE_TERMS",
    "PERSISTENCE_TERMS",
    "STAGING_AREA_TERMS",
    "has_suspicious_endpoint",
    "suspicious_executable_refs",
    "updater_behavior_context",
)
