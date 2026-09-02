"""Header-only timeout image dimension inspection support."""
from __future__ import annotations

import struct

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int


_JPEG_SOF_MARKERS = frozenset({
    0xC0,
    0xC1,
    0xC2,
    0xC3,
    0xC5,
    0xC6,
    0xC7,
    0xC9,
    0xCA,
    0xCB,
    0xCD,
    0xCE,
    0xCF,
})


def _pixel_area(
    width: object,
    height: object,
    *,
    zero_reason: str,
) -> tuple[int | None, str | None]:
    safe_width, width_reason = scheduler_int(
        width,
        default=0,
        minimum=0,
        reason=zero_reason,
    )
    safe_height, height_reason = scheduler_int(
        height,
        default=0,
        minimum=0,
        reason=zero_reason,
    )
    if width_reason or height_reason or safe_width == 0 or safe_height == 0:
        return None, zero_reason
    return int(safe_width) * int(safe_height), None


def static_image_pixel_count(
    head: bytes,
) -> tuple[int | None, str | None]:
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(head) < 24:
            return None, "png_header_truncated"
        if head[12:16] != b"IHDR":
            return None, "png_missing_ihdr"
        width, height = struct.unpack(">II", head[16:24])
        if width <= 0 or height <= 0:
            return None, "png_dimensions_zero"
        if width > 1000000 or height > 1000000:
            return None, "png_dimensions_unreasonable"
        return int(width) * int(height), None
    if len(head) >= 10 and head[:6] in (b"GIF87a", b"GIF89a"):
        width, height = struct.unpack("<HH", head[6:10])
        return _pixel_area(width, height, zero_reason="gif_dimensions_zero")
    if len(head) >= 30 and head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        chunk = head[12:16]
        if chunk == b"VP8X":
            width = 1 + int.from_bytes(head[24:27], "little")
            height = 1 + int.from_bytes(head[27:30], "little")
            return _pixel_area(width, height, zero_reason="webp_dimensions_zero")
        if chunk == b"VP8 ":
            width = int.from_bytes(head[26:28], "little") & 0x3FFF
            height = int.from_bytes(head[28:30], "little") & 0x3FFF
            return _pixel_area(width, height, zero_reason="webp_dimensions_zero")
        return None, None
    if len(head) >= 4 and head.startswith(b"\xff\xd8"):
        data = head[:65536]
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            i += 2
            if marker in (0xD8, 0xD9):
                continue
            if i + 2 > len(data):
                break
            length = int.from_bytes(data[i:i + 2], "big")
            if length < 2 or i + length > len(data):
                break
            if marker in _JPEG_SOF_MARKERS and length >= 7:
                height = int.from_bytes(data[i + 3:i + 5], "big")
                width = int.from_bytes(data[i + 5:i + 7], "big")
                return _pixel_area(width, height, zero_reason="jpeg_dimensions_zero")
            i += length
        return None, None
    return None, None


__all__ = ("static_image_pixel_count",)
