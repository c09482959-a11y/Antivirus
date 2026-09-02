"""Detection-owned static byte helpers for enrichment/correlation."""

from __future__ import annotations

import struct
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value


PLR2004N256 = 256
PLR2004N4 = 4


def find_known_eof_offset(data: bytes | bytearray | memoryview | None) -> tuple[int | None, str | None]:
    try:
        if data is None:
            buf = b""
        elif type(data) is bytes:
            buf = data
        elif type(data) is bytearray:
            buf = bytes(data)
        elif type(data) is memoryview:
            buf = data.tobytes()
        else:
            buf = b""
        if not buf:
            return None, None
        if buf.startswith(b"\x89PNG\r\n\x1a\n"):
            idx = buf.rfind(b"IEND")
            if idx >= PLR2004N4:
                return min(idx + 8, len(buf)), "png_eof"
        if buf.startswith(b"\xff\xd8"):
            idx = buf.rfind(b"\xff\xd9")
            if idx >= 0:
                return idx + 2, "jpeg_eof"
        if buf.startswith((b"GIF87a", b"GIF89a")):
            idx = buf.rfind(b";")
            if idx >= 0:
                return idx + 1, "gif_eof"
        if buf.startswith(b"BM") and len(buf) >= 6:
            declared = struct.unpack_from("<I", buf, 2)[0]
            if 0 < declared <= len(buf):
                return declared, "bmp_declared_eof"
        if buf.startswith(b"MZ") and len(buf) > PLR2004N256:
            pe_off = struct.unpack_from("<I", buf, 60)[0]
            if 0 <= pe_off + 24 < len(buf) and buf[pe_off:pe_off + 4] == b"PE\x00\x00":
                num_sections = struct.unpack_from("<H", buf, pe_off + 6)[0]
                opt_size = struct.unpack_from("<H", buf, pe_off + 20)[0]
                sec_off = pe_off + 24 + opt_size
                max_end = 0
                for index in range(min(num_sections, 96)):
                    off = sec_off + index * 40
                    if off + 40 > len(buf):
                        break
                    raw_size = struct.unpack_from("<I", buf, off + 16)[0]
                    raw_ptr = struct.unpack_from("<I", buf, off + 20)[0]
                    if raw_ptr and raw_size:
                        max_end = max(max_end, raw_ptr + raw_size)
                if 0 < max_end <= len(buf):
                    return max_end, "pe_section_eof"
    except RECOVERABLE_RUNTIME_ERRORS:
        return None, None
    return None, None


def stage_read_bytes(path: object, max_size: int = 2_000_000) -> bytes:
    """Read bytes for a detection stage; recoverable read failures propagate.

    Callers own the stage boundary and must convert recoverable failures into
    explicit detection failure evidence instead of this helper returning b"".
    """
    path_text = text_boundary_value(path, unsupported="") or ""
    limit, _limit_reason = no_hook_exact_nonnegative_int(
        max_size,
        default=2_000_000,
        reason="static_bytes_max_size_rejected",
        non_finite_reason="static_bytes_max_size_rejected",
        allow_exact_text=True,
    )
    data = Path(path_text).read_bytes()
    return data[:limit]


__all__ = ("find_known_eof_offset", "stage_read_bytes")
