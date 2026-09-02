"""Binary scanner bitstream helpers."""

from __future__ import annotations

PLR2004N8 = 8


def _umige_bits_to_bytes(bits: object, max_bytes: object = 262144) -> object:
    out = bytearray()
    cur = 0
    count = 0
    for bit in bits:
        cur = cur << 1 | int(bit) & 1
        count += 1
        if count == PLR2004N8:
            out.append(cur)
            if len(out) >= max_bytes:
                break
            cur = 0
            count = 0
    return bytes(out)

__all__ = ("_umige_bits_to_bytes",)
