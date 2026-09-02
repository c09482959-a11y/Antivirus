"""Scanner-owned .NET PE metadata parsing."""
from __future__ import annotations

from pathlib import Path
import hashlib
import struct

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.binary_io import binary_log_message
from Virus_Scan.scanners.binary_exception_policy import is_binary_programmer_error
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.scanners.contracts.binary_result import (
    BinaryAnalysisResult,
    BinaryMalformedRequest,
)
from Virus_Scan.scanners.entropy import entropy_bytes


PLR2004N267 = 267
PLR2004N523 = 523
PLR2004N64 = 64


def _malformed_binary_result(
    stage: str, error: BaseException | str, *, input_path: object
) -> BinaryAnalysisResult:
    return BinaryAnalysisResult.malformed(
        BinaryMalformedRequest(
            scanner_name="binary",
            stage=stage,
            error=error,
            input_path=input_path,
        )
    )


def dotnet_pe_result(data: bytes | bytearray | memoryview, *, input_path: str = "") -> BinaryAnalysisResult:
    """Return an immutable .NET PE parse result without hiding malformed PE data."""
    if data is None:
        return _malformed_binary_result("dotnet_pe_header", "missing binary data", input_path=input_path)
    try:
        view = bytes(data)
    except SCAN_CONTENT_ERRORS as exc:
        return _malformed_binary_result("dotnet_pe_header", exc, input_path=input_path)
    header = _pe_header_offsets(view, input_path=input_path)
    if isinstance(header, BinaryAnalysisResult):
        return header
    clr_dir_offset = header["opt_header_offset"] + (128 if header["magic"] == PLR2004N267 else 144)
    if clr_dir_offset + 8 > len(view):
        return _malformed_binary_result("dotnet_clr_directory", "truncated CLR directory", input_path=input_path)
    clr_rva, clr_size = struct.unpack("<II", view[clr_dir_offset:clr_dir_offset + 8])
    if clr_rva and clr_size:
        return BinaryAnalysisResult.detected_result("binary", "dotnet_clr_directory")
    return BinaryAnalysisResult.unsupported_result("binary", "dotnet_clr_directory")


def is_dotnet_pe(data: bytes) -> bool:
    """Detect a CLR header in a PE using the canonical immutable parse result."""
    return bool(dotnet_pe_result(data).detected)


def extract_dotnet_metadata(path: str) -> dict:
    """Fast .NET PE metadata extractor; no decompilation or execution."""
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(5000000)
        dotnet_result = dotnet_pe_result(data, input_path=path)
        if not dotnet_result.ok:
            return dotnet_result.to_metadata()
        if not dotnet_result.detected:
            return {"is_dotnet": False}
        return _dotnet_metadata_from_data(data)
    except SCAN_CONTENT_ERRORS as exc:
        if is_binary_programmer_error(exc):
            raise
        binary_log_message("extract_dotnet_metadata failed")
        tags = scanner_failure_evidence_tags("binary", "extract_dotnet_metadata", exc, ["dotnet_metadata_scan_error", "binary_final_json_must_record"], state="degraded", error_category="dotnet_metadata_scan_failure", file_type="binary")
        return {
            "is_dotnet": False,
            "error": True,
            "scanner_degraded": True,
            "tags": tags,
            "scan_integrity": {"file_failed": True, "had_degraded_stage": True, "allow_learning": False, "error": str(exc)[:500]},
        }


def _dotnet_metadata_from_data(data: bytes) -> dict:
    header = _pe_header_offsets(data)
    if isinstance(header, BinaryAnalysisResult):
        return header.to_metadata()
    image_base_offset = header["opt_header_offset"] + (24 if header["is_64"] else 28)
    image_base = struct.unpack("<Q" if header["is_64"] else "<I", data[image_base_offset:image_base_offset + (8 if header["is_64"] else 4)])[0]
    clr_dir_offset = header["opt_header_offset"] + (128 if not header["is_64"] else 144)
    clr_rva, clr_size = struct.unpack("<II", data[clr_dir_offset:clr_dir_offset + 8])
    return {
        "is_dotnet": True,
        "arch": "x64" if header["is_64"] else "x86",
        "image_base": image_base,
        "clr_rva": clr_rva,
        "clr_size": clr_size,
        "fingerprint": hashlib.sha256(data[:4096]).hexdigest(),
        "entropy_head": entropy_bytes(data[:4096]),
    }


def _pe_header_offsets(view: bytes, *, input_path: str = "") -> dict | BinaryAnalysisResult:
    if len(view) < 2 or view[:2] != b"MZ":
        return BinaryAnalysisResult.unsupported_result("binary", "dotnet_pe_header")
    if len(view) < PLR2004N64:
        return _malformed_binary_result("dotnet_pe_header", "truncated DOS header", input_path=input_path)
    pe_offset = struct.unpack("<I", view[60:64])[0]
    if pe_offset <= 0 or pe_offset + 24 > len(view):
        return _malformed_binary_result("dotnet_pe_header", "invalid or truncated PE header offset", input_path=input_path)
    if view[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return _malformed_binary_result("dotnet_pe_header", "missing PE signature at header offset", input_path=input_path)
    opt_header_offset = pe_offset + 24
    if opt_header_offset + 2 > len(view):
        return _malformed_binary_result("dotnet_pe_optional_header", "truncated optional header", input_path=input_path)
    magic = struct.unpack("<H", view[opt_header_offset:opt_header_offset + 2])[0]
    if magic not in (267, 523):
        return _malformed_binary_result("dotnet_pe_optional_header", "unsupported PE optional header magic " + int.__str__(magic), input_path=input_path)
    return {"pe_offset": pe_offset, "opt_header_offset": opt_header_offset, "magic": magic, "is_64": magic == PLR2004N523}


__all__ = ("dotnet_pe_result", "extract_dotnet_metadata", "is_dotnet_pe")
