"""Scanner-owned PE byte parsing helpers for binary analysis.

These helpers keep PE little-endian reads, C-string extraction, and RVA mapping
inside the binary scanner domain instead of importing private pipeline helpers.
"""
from __future__ import annotations

import struct

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_mapping_items


def _pe_field_text(field: str) -> str:
    if type(field) is str and field:
        return str.__str__(field)
    return "value"


def _pe_nonnegative_int(value: object, *, field: str, reason: str) -> int:
    del field  # Explicitly unused contract parameters.
    if value is None:
        raise ValueError(str.__str__(reason))
    parsed, parse_reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason=reason,
        allow_exact_text=False,
    )
    if parse_reason:
        raise ValueError(str.__str__(parse_reason))
    return parsed


def _pe_offset_text(offset: int) -> str:
    return int.__str__(offset)


def pe_cstr(data: bytes, off: int | None, limit: int = 260) -> str:
    """Return a bounded latin-1 C string from PE bytes.

    Malformed helper failures are intentionally allowed to propagate to the
    owning PE parser.  The parser wraps them in scanner-owned evidence tags;
    returning a string sentinel here would make import parsing look successful
    and hide the malformed binary condition from downstream evidence/JSON.
    """
    off_value = _pe_nonnegative_int(off, field="cstr_offset", reason="PE C-string offset rejected")
    limit_value = _pe_nonnegative_int(limit, field="cstr_limit", reason="PE C-string limit rejected")
    if off_value >= len(data):
        raise ValueError("invalid PE C-string offset " + _pe_offset_text(off_value))
    end = data.find(b"\x00", off_value, min(len(data), off_value + limit_value))
    if end < 0:
        end = min(len(data), off_value + limit_value)
    return data[off_value:end].decode("latin1", errors="ignore")


def _exact_section_sequence(sections: object) -> tuple[object, ...]:
    if sections is None:
        return ()
    if type(sections) is tuple:
        return sections
    if type(sections) is list:
        return tuple(sections)
    exception_message = "PE section sequence rejected"
    raise ValueError(exception_message)


def _pe_section_mapping_value(section: object, field: str, default: int = 0) -> object:
    items = no_hook_mapping_items(section)
    if items is None:
        exception_message = "PE section mapping rejected"
        raise ValueError(exception_message)
    for key, value in items:
        if type(key) is not str:
            exception_message = "PE section key rejected"
            raise ValueError(exception_message)
        if str.__eq__(key, field):
            return default if value is None else value
    return default


def _pe_section_nonnegative_int(section: object, field: str, default: int = 0) -> int:
    value, reason = no_hook_exact_nonnegative_int(
        _pe_section_mapping_value(section, field, default),
        default=default,
        reason="PE section integer rejected",
        allow_exact_text=False,
    )
    if reason:
        raise ValueError(str.__str__(reason))
    return value


def pe_rva_to_offset(rva: int, sections: object) -> int | None:
    """Map a PE RVA to a file offset using parsed section records.

    Malformed section records are allowed to propagate to the bounded PE
    parser, where scanner-owned evidence tags are emitted instead of hiding the
    failure as an ordinary unmapped RVA.
    """
    rva_value, rva_reason = no_hook_exact_nonnegative_int(
        rva,
        default=0,
        reason="PE RVA rejected",
        allow_exact_text=False,
    )
    if rva_reason:
        raise ValueError(str.__str__(rva_reason))
    for section in _exact_section_sequence(sections):
        start = _pe_section_nonnegative_int(section, "virtual_address")
        virtual_size = _pe_section_nonnegative_int(section, "virtual_size")
        raw_size = _pe_section_nonnegative_int(section, "raw_size")
        raw_ptr = _pe_section_nonnegative_int(section, "raw_ptr")
        end = start + max(virtual_size, raw_size, 1)
        if start <= rva_value < end:
            return raw_ptr + (rva_value - start)
    return None


def _require_read_bounds(data: bytes, off: int, width: int, field: str) -> None:
    off_value = _pe_nonnegative_int(off, field="read_offset", reason="PE read offset rejected")
    width_value = _pe_nonnegative_int(width, field="read_width", reason="PE read width rejected")
    if off_value + width_value > len(data):
        raise ValueError("truncated PE " + _pe_field_text(field) + " read at offset " + _pe_offset_text(off_value))


def pe_u16(data: bytes, off: int) -> int:
    _require_read_bounds(data, off, 2, "u16")
    return struct.unpack_from("<H", data, _pe_nonnegative_int(off, field="u16_offset", reason="PE read offset rejected"))[0]


def pe_u32(data: bytes, off: int) -> int:
    _require_read_bounds(data, off, 4, "u32")
    return struct.unpack_from("<I", data, _pe_nonnegative_int(off, field="u32_offset", reason="PE read offset rejected"))[0]


def pe_u64(data: bytes, off: int) -> int:
    _require_read_bounds(data, off, 8, "u64")
    return struct.unpack_from("<Q", data, _pe_nonnegative_int(off, field="u64_offset", reason="PE read offset rejected"))[0]


__all__ = ("pe_cstr", "pe_rva_to_offset", "pe_u16", "pe_u32", "pe_u64")
