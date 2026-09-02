"""ILSpy output enrichment scanner owner."""
from __future__ import annotations

import os
from pathlib import Path

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags

_ILSPY_PATTERNS = (
    ("memory_protect", ("virtualprotect", "virtualprotectex")),
    ("memory_write", ("writeprocessmemory",)),
    ("memory_read", ("readprocessmemory",)),
    ("thread_execution", ("createremotethread", "ntcreatethreadex")),
    ("process_exec", ("process.start", "createprocess")),
    ("cmd_exec", ("cmd.exe",)),
    ("powershell_exec", ("powershell", "pwsh")),
    ("encoded_powershell", ("encodedcommand", " -enc ", "-encodedcommand")),
    ("schtasks_create", ("schtasks",)),
    ("registry_mod", ("registry.currentuser", "registry.localmachine", "microsoft.win32.registry")),
    ("network_download", ("downloadstring", "downloadfile", "webclient", "httpclient", "httpwebrequest")),
    ("http_upload", ("uploadstring", "uploadfile", "postasync")),
    ("reflection", ("assembly.load", "getmethod", "invoke(", "reflection")),
    ("defender_disable", ("set-mppreference", "disablerealtimemonitoring", "disableantispyware")),
    ("shadowcopy_delete", ("vssadmin delete shadows", "shadowcopy delete", "delete shadows")),
    ("lsass_access", ("lsass",)),
    ("credential_dump_attempt", ("mimikatz", "minidumpwritedump", "sekurlsa")),
)


def scan_ilspy_output(out_dir: object) -> object:
    """Extract UMIGE tags from decompiled C# without runtime helper imports."""
    tags: set[str] = set()
    if not out_dir or not Path(out_dir).is_dir():
        return []
    try:
        for root, _, files in os.walk(out_dir):
            for filename in files:
                if not filename.lower().endswith((".cs", ".il", ".txt")):
                    continue
                path = Path(root, filename)
                try:
                    data = path.read_text(encoding="utf-8", errors="ignore").lower()
                except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
                    tags.update(failure_tags_for_stage("ilspy_output_file_read", exc, context=path))
                    continue
                for tag, needles in _ILSPY_PATTERNS:
                    if any(needle in data for needle in needles):
                        tags.add(tag)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        tags.update(failure_tags_for_stage("ilspy_output_scan", exc, context=out_dir))
    if tags:
        tags.add("ilspy_decompiled")
        tags.add("dotnet_ilspy_scan")
    return normalize_tags(sorted(tags))
