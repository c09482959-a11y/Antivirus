"""Scanner-owned low-level image bit and JPEG helpers."""
from __future__ import annotations

from pathlib import Path


PLR2004N8 = 8


def bits_to_bytes(bits: object, max_bytes: int = 262144) -> bytes:
    """Pack an iterable of LSB bits into bytes with an explicit scanner-owned cap."""
    out = bytearray()
    cur = 0
    count = 0
    for bit in bits or []:
        cur = (cur << 1) | (1 if bit else 0)
        count += 1
        if count == PLR2004N8:
            out.append(cur & 0xFF)
            if len(out) >= max_bytes:
                break
            cur = 0
            count = 0
    return bytes(out)


def image_is_jpeg(data: bytes | None = None, path: object = None, *, read_path: bool = False) -> bool:
    """Return whether the supplied image sample/path is JPEG-owned evidence.

    Path reads are opt-in so tag normalization never hides path-read failures.
    Callers that need byte-level certainty can enable ``read_path`` inside their
    own evidence-producing exception boundary.
    """
    if data is not None:
        return bytes(data[:3]) == bytes((0xFF, 0xD8, 0xFF))
    if path is None:
        return False
    if read_path:
        with Path(path).open("rb") as fh:
            return fh.read(3) == bytes((0xFF, 0xD8, 0xFF))
    return str(path).lower().endswith((".jpg", ".jpeg"))


__all__ = ("bits_to_bytes", "image_is_jpeg")
