"""Scanner-owned PE section and import table parsing."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.binary_pe_bytes import pe_cstr, pe_rva_to_offset, pe_u16, pe_u32, pe_u64
from Virus_Scan.scanners.binary_pe_evidence import immutable_tag_tuple, mark_pe_helper_error
from Virus_Scan.scanners.binary_pe_result_support import PEImportParseResult, PESectionParseResult
from Virus_Scan.scanners.entropy import entropy_bytes


def parse_pe_sections(data: object) -> PESectionParseResult:
    """Parse PE sections and return immutable section data plus evidence tags."""
    sections = []
    error_tags: tuple[str, ...] = ()
    try:
        if not data or not data.startswith(b"MZ"):
            return PESectionParseResult()
        pe_off = pe_u32(data, 60)
        if pe_off <= 0 or pe_off + 24 > len(data):
            tags = mark_pe_helper_error("pe_section_parse", ValueError("truncated PE header"))
            return PESectionParseResult(error_tags=immutable_tag_tuple(tags))
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return PESectionParseResult()
        nsec = pe_u16(data, pe_off + 6)
        sec_off = pe_off + 24 + pe_u16(data, pe_off + 20)
        if nsec and sec_off + min(nsec, 96) * 40 > len(data):
            error_tags = immutable_tag_tuple(mark_pe_helper_error("pe_section_parse", ValueError("truncated PE section table")))
        for i in range(min(nsec, 96)):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            raw_ptr = pe_u32(data, off + 20)
            raw_sz = pe_u32(data, off + 16)
            blob = data[raw_ptr:raw_ptr + raw_sz] if 0 <= raw_ptr < len(data) else b""
            sections.append(_section_record(data, off, raw_ptr, raw_sz, blob))
    except SCAN_CONTENT_ERRORS as exc:
        error_tags = immutable_tag_tuple(mark_pe_helper_error("pe_section_parse", exc))
    return PESectionParseResult(sections=tuple(sections), error_tags=error_tags)


def _section_record(data: object, off: int, raw_ptr: int, raw_sz: int, blob: bytes) -> dict:
    return {
        "name": data[off:off + 8].rstrip(b"\x00").decode("latin1", errors="ignore"),
        "virtual_size": pe_u32(data, off + 8),
        "virtual_address": pe_u32(data, off + 12),
        "raw_size": raw_sz,
        "raw_ptr": raw_ptr,
        "characteristics": pe_u32(data, off + 36),
        "entropy": entropy_bytes(blob),
    }


def parse_pe_import_names(data: object, sections: object, *, is_64: bool = False) -> PEImportParseResult:
    """Parse PE import names and return immutable import data plus evidence tags."""
    del is_64
    imports: list[tuple[str, tuple[str, ...]]] = []
    try:
        if not data or not data.startswith(b"MZ"):
            return PEImportParseResult()
        directory = _import_directory_offset(data, sections)
        if directory.error_tags or directory.offset is None:
            return PEImportParseResult(error_tags=directory.error_tags)
        step = 8 if directory.is_64 else 4
        ordinal_mask = 9223372036854775808 if directory.is_64 else 2147483648
        off = directory.offset
        while off + 20 <= len(data) and len(imports) < 512:
            entry = _read_import_descriptor(data, sections, off, step, ordinal_mask)
            if entry is None:
                break
            imports.append(entry)
            off += 20
        if off + 20 > len(data):
            tags = mark_pe_helper_error("pe_import_parse", ValueError("truncated import descriptor walk"))
            return PEImportParseResult(imports=tuple(imports), error_tags=immutable_tag_tuple(tags))
    except SCAN_CONTENT_ERRORS as exc:
        tags = mark_pe_helper_error("pe_import_parse", exc)
        return PEImportParseResult(imports=tuple(imports), error_tags=immutable_tag_tuple(tags))
    return PEImportParseResult(imports=tuple(imports))


@dataclass(frozen=True, slots=True)
class _ImportDirectoryOffset:
    offset: int | None = None
    is_64: bool = False
    error_tags: tuple[str, ...] = ()


def _import_directory_offset(data: object, sections: object) -> _ImportDirectoryOffset:
    pe_off = pe_u32(data, 60)
    if pe_off <= 0 or pe_off + 24 > len(data):
        tags = mark_pe_helper_error("pe_import_parse", ValueError("truncated PE header"))
        return _ImportDirectoryOffset(error_tags=immutable_tag_tuple(tags))
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return _ImportDirectoryOffset()
    opt_off = pe_off + 24
    is_64 = pe_u16(data, opt_off) == 523
    dd_off = opt_off + (112 if is_64 else 96)
    if dd_off + 16 > len(data):
        tags = mark_pe_helper_error("pe_import_parse", ValueError("truncated PE data directories"))
        return _ImportDirectoryOffset(is_64=is_64, error_tags=immutable_tag_tuple(tags))
    import_rva = pe_u32(data, dd_off + 8)
    if not import_rva:
        return _ImportDirectoryOffset(is_64=is_64)
    off = pe_rva_to_offset(import_rva, sections)
    if off is None:
        tags = mark_pe_helper_error("pe_import_parse", ValueError("import directory RVA not mapped by section table"))
        return _ImportDirectoryOffset(is_64=is_64, error_tags=immutable_tag_tuple(tags))
    return _ImportDirectoryOffset(offset=off, is_64=is_64)


def _read_import_descriptor(data: object, sections: object, off: int, step: int, ordinal_mask: int) -> object:
    original_first_thunk = pe_u32(data, off)
    name_rva = pe_u32(data, off + 12)
    first_thunk = pe_u32(data, off + 16)
    if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
        return None
    name_off = pe_rva_to_offset(name_rva, sections)
    if name_off is None:
        raise ValueError("import descriptor DLL name RVA not mapped by section table")
    dll = pe_cstr(data, name_off).lower()
    if not dll:
        raise ValueError("empty import descriptor DLL name")
    funcs = _read_import_functions(data, sections, original_first_thunk or first_thunk, step, ordinal_mask)
    return (dll, tuple(funcs))


def _read_import_functions(data: object, sections: object, thunk_rva: int, step: int, ordinal_mask: int) -> list[str]:
    thunk_off = pe_rva_to_offset(thunk_rva, sections)
    funcs: list[str] = []
    while thunk_off is not None and thunk_off + step <= len(data) and len(funcs) < 512:
        thunk = pe_u64(data, thunk_off) if step == 8 else pe_u32(data, thunk_off)
        if thunk == 0:
            break
        if thunk & ordinal_mask:
            funcs.append("ordinal_import")
        else:
            name_off = pe_rva_to_offset(int(thunk), sections)
            if name_off is None:
                raise ValueError("import function name RVA not mapped by section table")
            name = pe_cstr(data, name_off + 2)
            if name:
                funcs.append(name)
        thunk_off += step
    return funcs


__all__ = (
    "PEImportParseResult",
    "PESectionParseResult",
    "parse_pe_import_names",
    "parse_pe_sections",
)
