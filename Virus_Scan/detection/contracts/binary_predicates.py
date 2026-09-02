"""Detection-owned binary predicate helpers."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.contracts.string_predicates import ascii_visibility_ratio, has_any_text
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value
from Virus_Scan.utils.entropy import strict_fast_entropy

STRICT_TEXT_EXTENSIONS = frozenset({".txt", ".log", ".ini", ".cfg", ".json", ".xml", ".csv", ".rpy", ".py", ".js", ".html", ".css"})
STRICT_BINARY_MAGIC = (b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b\x08", b"Rar!\x1a\x07", b"7z\xbc\xaf'\x1c")

def strict_fast_file_is_boring_text(path: object) -> tuple[bool, dict[str, object]]:
    path_text = text_boundary_value(path, unsupported="") or ""
    p = Path(path_text)
    meta: dict[str, object] = {"extension": p.suffix.lower()}
    if meta["extension"] not in STRICT_TEXT_EXTENSIONS:
        return False, meta
    try:
        data = p.read_bytes()[:262_145]
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        meta["read_error"] = str(exc)
        return False, meta
    if not data or any(data.startswith(magic) for magic in STRICT_BINARY_MAGIC):
        return False, meta
    nul_ratio = data.count(b"\x00") / max(1, len(data))
    printable_ratio = ascii_visibility_ratio(data)
    entropy = strict_fast_entropy(data)
    text = data.decode("latin1", errors="ignore").lower()
    meta.update({"nul_ratio": round(nul_ratio, 5), "printable_ratio": round(printable_ratio, 5), "entropy": round(entropy, 4)})
    suspicious = has_any_text(text, ["powershell", "cmd.exe", "subprocess", "eval(", "exec(", "frombase64string", "writeprocessmemory", "createremotethread", "http://", "https://"])
    return bool(nul_ratio == 0.0 and printable_ratio >= 0.97 and entropy < 5.2 and not suspicious), meta


def xor_blob_signal(data: bytes | bytearray | memoryview | None) -> bool:
    sample = bytes(data or b"")[:65536]
    if len(sample) < 512:
        return False
    entropy = strict_fast_entropy(sample)
    visible = ascii_visibility_ratio(sample)
    return bool(5.8 <= entropy <= 7.9 and visible < 0.72)


__all__ = ("strict_fast_file_is_boring_text", "xor_blob_signal")
