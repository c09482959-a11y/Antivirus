"""Narrow parsing helpers for RENPY RPC chunk tables."""
from __future__ import annotations


def renpy_rpc_bytes(
    value: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[bytes | None, str]:
    """Materialize exact built-in binary containers with explicit status."""
    data: bytes | None = None
    status = "unsupported_binary_container"
    try:
        if type(value) is bytearray:
            data = bytes(value)
            status = ""
        elif type(value) is memoryview:
            data = value.tobytes()
            status = ""
        elif type(value) is bytes:
            data = value
            status = ""
    except recoverable_exceptions:
        status = "binary_container_probe_failed"
    return data, status


def renpy_rpc_header_boundary(
    data: bytes,
    max_header_bytes: int,
) -> tuple[int, int] | None:
    """Return the header boundary and separator width when bounded."""
    header_end = data.find(b"\n\n")
    separator_length = 2
    if header_end < 0:
        header_end = data.find(b"\r\n\r\n")
        separator_length = 4
    if header_end < 0 or header_end > max_header_bytes:
        return None
    return header_end, separator_length


def renpy_rpc_chunk_from_line(
    data: bytes,
    line: str,
    min_fields: int,
    max_decoded_bytes: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[tuple[str, bytes] | None, str]:
    """Parse one bounded table row and return an explicit parse status."""
    parts = line.strip().split()
    if len(parts) < min_fields:
        return None, "insufficient_chunk_fields"
    try:
        slot = int(parts[0])
        offset = int(parts[1])
        length = int(parts[2])
    except recoverable_exceptions:
        return None, "invalid_chunk_coordinates"
    if offset < 0 or length <= 0 or offset >= len(data):
        return None, "chunk_coordinates_out_of_range"
    chunk_end = min(len(data), offset + length, offset + max_decoded_bytes)
    chunk = data[offset:chunk_end]
    if not chunk:
        return None, "empty_chunk"
    record = "rpyc_rpc_slot" + int.__str__(slot) + "_chunk", chunk
    return record, ""


__all__ = (
    "renpy_rpc_bytes",
    "renpy_rpc_chunk_from_line",
    "renpy_rpc_header_boundary",
)
