"""Bytecode file enrichment scanner owner."""
from __future__ import annotations

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.contracts.pickle_opcode import detect_python_pickle_opcode_exec
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import scan_strings
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.evidence.static_bytes import stage_read_bytes
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags

_ALLOWED_BYTECODE_EXTS = frozenset({
    ".py", ".pyc", ".pyo", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1",
    ".bat", ".cmd", ".jar", ".class", ".rpy", ".rpyc", ".rpyb",
})


def _scan_string_tags(text: str, path: object, *, finalize: bool) -> list[str]:
    del finalize  # Explicitly unused contract parameters.
    try:
        return list(scan_strings(text, path=path, finalize=False))
    except TypeError:
        return list(scan_strings(text, path=path))


def scan_bytecode_file(path: object, *, finalize: object=True) -> object:
    """Scan bytecode/script files without runtime-owned helper imports."""
    tags: list[str] = []
    try:
        ext = get_scan_extension(path)
        if ext not in _ALLOWED_BYTECODE_EXTS:
            return []
        data = stage_read_bytes(path, max_size=2 * 1024 * 1024)
        text = data.decode("latin1", errors="ignore").lower()
        if ext in {".py", ".pyc", ".pyo"}:
            tags.append("python_bytecode_or_script")
        if ext in {".js", ".jse"}:
            tags += ["jscript_execution", "script_execution"]
        if ext in {".vbs", ".vbe"}:
            tags += ["vbs_execution", "script_execution"]
        if ext in {".ps1", ".psm1"}:
            tags += ["powershell_exec", "script_execution"]
        if ext in {".bat", ".cmd"}:
            tags += ["cmd_exec", "script_execution"]
        if ext in {".jar", ".class"}:
            tags.append("java_bytecode")
        if "eval(" in text or "exec(" in text:
            tags += ["bytecode_eval", "bytecode_exec"]
        if "subprocess" in text or "os.system" in text or "popen(" in text:
            tags += ["bytecode_subprocess", "process_exec"]
        if "socket" in text and "connect" in text:
            tags += ["bytecode_socket", "network_activity"]
        if "pickle.loads" in text or "marshal.loads" in text:
            tags.append("bytecode_deserialization")
        tags.extend(detect_python_pickle_opcode_exec(text, ext))
        tags.extend(_scan_string_tags(text, path, finalize=bool(finalize)))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        tags.extend(failure_tags_for_stage("bytecode_file_scan", exc, context=path))
    if finalize:
        return normalize_tags(tags)
    return list(tags or [])
