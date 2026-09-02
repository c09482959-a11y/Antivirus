"""Detection-owned path predicates used by scoring/correlation."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.utils.text_validation import text_boundary_value

RUNTIME_STRONG_ATTACK_CONTEXT = (
    "powershell -enc", "encodedcommand", "invoke-expression", "iex(", "cmd.exe /c",
    "wscript.shell", "mshta.exe", "rundll32.exe", "regsvr32.exe", "schtasks /create",
    "wmic process call create", "createprocessw(", "createprocessa(", "writeprocessmemory",
    "createremotethread", "ntcreatethreadex", "queueuserapc", "mimikatz", "sekurlsa",
    "minidumpwritedump", "lsass.exe", "amsiscanbuffer", "discord.com/api/webhooks",
    "api.telegram.org", "/gate.php", "/panel/", "reverse shell",
)


def binary_ext_for_attack_cap(path: object) -> bool:
    path_text = text_boundary_value(path, unsupported="") or ""
    return Path(path_text).suffix.lower() in {".exe", ".dll", ".sys", ".ocx", ".scr"}


__all__ = ("RUNTIME_STRONG_ATTACK_CONTEXT", "binary_ext_for_attack_cap")
