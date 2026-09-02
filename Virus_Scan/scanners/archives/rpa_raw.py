"""Raw/custom RPA text behavior boundary."""

from __future__ import annotations

from Virus_Scan.runtime.api import scan_strings
from Virus_Scan.scanners.archives.rpa_evidence import append_archive_rpa_finding_publication_evidence
from Virus_Scan.utils.tagging import normalize_tags

_RPA_RAW_SUSPICIOUS_TAGS = frozenset({
    "process_exec",
    "bytecode_exec",
    "bytecode_eval",
    "network_activity",
    "reverse_shell",
    "remote_payload_download",
    "network_download_execute",
    "encoded_payload",
    "powershell_encoded",
    "encoded_powershell",
    "encoded_script_execution",
    "powershell_exec",
    "script_execution",
})


def _rpa_raw_tags_are_suspicious(values: list[str]) -> bool:
    lowered = {tag.lower() for tag in normalize_tags(values)}
    return bool(lowered & _RPA_RAW_SUSPICIOUS_TAGS)


def _append_rpa_finding_publication_tags(tags: list[str], path: str, finding_tag: str) -> None:
    tags[:] = append_archive_rpa_finding_publication_evidence(tags, path=path, finding_tag=finding_tag)


def scan_raw_rpa_text(path: str, data: bytes, text: str, tags: list[str]) -> bool:
    """Scan raw/custom RPA text views and publish archive-owned findings."""
    suspicious = False
    if data[:3].lower() == b"rpa" or "renpy" in text:
        tags.append("rpa_custom_container")
    if ".rpy" in text or ".rpyc" in text or ".rpyb" in text:
        tags.append("renpy_script_reference")
    if "python" in text or "pickle" in text or "marshal" in text:
        tags.append("renpy_python_payload_reference")
    string_tags = list(scan_strings(text, path=path) or [])
    tags.extend(string_tags)
    if _rpa_raw_tags_are_suspicious(string_tags):
        suspicious = True
        _append_rpa_finding_publication_tags(tags, path, "rpa_raw_string_finding")
    if "exec(" in text or "eval(" in text or "subprocess" in text:
        tags += ["bytecode_exec", "bytecode_eval", "process_exec"]
        suspicious = True
        _append_rpa_finding_publication_tags(tags, path, "rpa_raw_execution_finding")
    if "socket" in text and "connect" in text:
        tags += ["network_activity", "reverse_shell"]
        suspicious = True
        _append_rpa_finding_publication_tags(tags, path, "rpa_raw_network_finding")
    return suspicious


__all__ = ("scan_raw_rpa_text",)
