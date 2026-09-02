"""Canonical ELF64/x86-64 container and section-structure owner."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import struct

ELF_X86_64_STRUCTURE_SCHEMA_VERSION = "elf_x86_64_structure_v1"
ELF_X86_64_MAX_PROGRAM_HEADERS = 256
ELF_X86_64_MAX_SECTION_HEADERS = 4096
ELF_X86_64_MAX_EXECUTABLE_SECTIONS = 512

_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
_ELF_CLASS_64 = 2
_ELF_DATA_LITTLE_ENDIAN = 1
_ELF_VERSION_CURRENT = 1
_ELF_MACHINE_X86_64 = 62
_ELF_TYPE_EXECUTABLE = 2
_ELF_TYPE_SHARED = 3
_PT_LOAD = 1
_PF_EXECUTE = 1
_SHF_EXECINSTR = 4
_SHT_NOBITS = 8


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


ELF_X86_64_STRUCTURE_DIGEST = _digest({
    "schema": ELF_X86_64_STRUCTURE_SCHEMA_VERSION,
    "limits": {
        "program_headers": ELF_X86_64_MAX_PROGRAM_HEADERS,
        "section_headers": ELF_X86_64_MAX_SECTION_HEADERS,
        "executable_sections": ELF_X86_64_MAX_EXECUTABLE_SECTIONS,
    },
    "target": "elf64_little_endian_x86_64",
})


class NativeELFParseError(ValueError):
    """ELF bytes do not satisfy the canonical native frontend contract."""


@dataclass(frozen=True, slots=True)
class ELFSegment:
    index: int
    file_offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    flags: int

    @property
    def file_end(self) -> int:
        return self.file_offset + self.file_size

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + self.file_size


@dataclass(frozen=True, slots=True)
class ELFSection:
    index: int
    name: str
    section_type: int
    flags: int
    virtual_address: int
    file_offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int
    segment_index: int | None

    @property
    def file_end(self) -> int:
        return self.file_offset + self.size

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + self.size

    @property
    def executable(self) -> bool:
        return bool(self.flags & _SHF_EXECINSTR) and self.size > 0 and self.section_type != _SHT_NOBITS

    @property
    def section_identity(self) -> str:
        return f"elf_section:{self.index}:{self.name}"

    @property
    def region_identity(self) -> str:
        segment = -1 if self.segment_index is None else self.segment_index
        return f"elf_exec_region:{segment}:{self.index}"


@dataclass(frozen=True, slots=True)
class ELFModule:
    entrypoint: int
    segments: tuple[ELFSegment, ...]
    sections: tuple[ELFSection, ...]

    @property
    def executable_sections(self) -> tuple[ELFSection, ...]:
        return tuple(section for section in self.sections if section.executable)

    def section_by_name(self, name: str) -> ELFSection | None:
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def section_for_virtual_address(self, address: int) -> ELFSection | None:
        for section in self.executable_sections:
            if section.virtual_address <= address < section.virtual_end:
                return section
        return None

    def file_offset(self, address: int) -> int | None:
        section = self.section_for_virtual_address(address)
        if section is None:
            return None
        return section.file_offset + (address - section.virtual_address)

    def section_bytes(self, raw: bytes, name: str) -> bytes | None:
        section = self.section_by_name(name)
        if section is None or section.section_type == _SHT_NOBITS:
            return None
        return raw[section.file_offset:section.file_end]


@dataclass(frozen=True, slots=True)
class _Header:
    entrypoint: int
    program_header_offset: int
    section_header_offset: int
    program_header_size: int
    program_header_count: int
    section_header_size: int
    section_header_count: int
    section_name_index: int


def _checked_end(offset: int, size: int, limit: int, reason: str) -> int:
    if offset < 0 or size < 0:
        raise NativeELFParseError(reason)
    end = offset + size
    if end < offset or end > limit:
        raise NativeELFParseError(reason)
    return end


def _parse_header(raw: bytes) -> _Header:
    if len(raw) < _ELF_HEADER.size:
        raise NativeELFParseError("elf_header_truncated")
    fields = _ELF_HEADER.unpack_from(raw, 0)
    ident = fields[0]
    if ident[:4] != b"\x7fELF": raise NativeELFParseError("elf_magic_invalid")
    if ident[4] != _ELF_CLASS_64: raise NativeELFParseError("elf_class_unsupported")
    if ident[5] != _ELF_DATA_LITTLE_ENDIAN: raise NativeELFParseError("elf_endianness_unsupported")
    if ident[6] != _ELF_VERSION_CURRENT: raise NativeELFParseError("elf_ident_version_invalid")
    if fields[1] not in (_ELF_TYPE_EXECUTABLE, _ELF_TYPE_SHARED): raise NativeELFParseError("elf_type_unsupported")
    if fields[2] != _ELF_MACHINE_X86_64: raise NativeELFParseError("elf_architecture_unsupported")
    if fields[3] != _ELF_VERSION_CURRENT: raise NativeELFParseError("elf_version_invalid")
    if fields[8] != _ELF_HEADER.size: raise NativeELFParseError("elf_header_size_invalid")
    phoff, shoff = fields[5], fields[6]
    phentsize, phnum, shentsize, shnum, shstrndx = fields[9], fields[10], fields[11], fields[12], fields[13]
    if phnum == 0 or phnum > ELF_X86_64_MAX_PROGRAM_HEADERS: raise NativeELFParseError("elf_program_header_count_invalid")
    if phentsize != _PROGRAM_HEADER.size: raise NativeELFParseError("elf_program_header_size_invalid")
    if shnum == 0 or shnum > ELF_X86_64_MAX_SECTION_HEADERS: raise NativeELFParseError("elf_section_header_count_invalid")
    if shentsize != _SECTION_HEADER.size: raise NativeELFParseError("elf_section_header_size_invalid")
    if shstrndx >= shnum: raise NativeELFParseError("elf_section_name_index_invalid")
    _checked_end(phoff, phentsize * phnum, len(raw), "elf_program_header_table_invalid")
    _checked_end(shoff, shentsize * shnum, len(raw), "elf_section_header_table_invalid")
    return _Header(fields[4], phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)


def _segments(raw: bytes, header: _Header) -> tuple[ELFSegment, ...]:
    result: list[ELFSegment] = []
    for index in range(header.program_header_count):
        values = _PROGRAM_HEADER.unpack_from(raw, header.program_header_offset + index * header.program_header_size)
        if values[0] != _PT_LOAD or values[5] == 0:
            continue
        _checked_end(values[2], values[5], len(raw), "elf_segment_range_invalid")
        if values[6] < values[5]: raise NativeELFParseError("elf_segment_memory_size_invalid")
        result.append(ELFSegment(index, values[2], values[3], values[5], values[6], values[1]))
    if not any(item.flags & _PF_EXECUTE for item in result):
        raise NativeELFParseError("elf_executable_segment_unavailable")
    ordered = tuple(sorted(result, key=lambda item: (item.virtual_address, item.file_offset, item.index)))
    exec_ordered = tuple(item for item in ordered if item.flags & _PF_EXECUTE)
    for previous, current in zip(exec_ordered, exec_ordered[1:]):
        if current.virtual_address < previous.virtual_end:
            raise NativeELFParseError("elf_executable_segment_overlap")
    return ordered


def _section_name(table: bytes, offset: int, index: int) -> str:
    if offset < 0 or offset >= len(table): return f"section_{index}"
    end = table.find(b"\x00", offset)
    if end < 0: return f"section_{index}"
    try: name = table[offset:end].decode("utf-8", "strict")
    except UnicodeDecodeError: return f"section_{index}"
    if not name or len(name) > 128 or any(ord(ch) < 32 for ch in name): return f"section_{index}"
    return name


def parse_elf_x86_64_structure(raw: bytes) -> ELFModule:
    if type(raw) is not bytes:
        raise TypeError("native_elf_raw_bytes_required")
    header = _parse_header(raw)
    segments = _segments(raw, header)
    headers = tuple(_SECTION_HEADER.unpack_from(raw, header.section_header_offset + i * header.section_header_size) for i in range(header.section_header_count))
    name_header = headers[header.section_name_index]
    if name_header[1] == _SHT_NOBITS: raise NativeELFParseError("elf_section_name_table_invalid")
    name_end = _checked_end(name_header[4], name_header[5], len(raw), "elf_section_name_table_invalid")
    names = raw[name_header[4]:name_end]
    sections: list[ELFSection] = []
    executable_count = 0
    for index, values in enumerate(headers):
        name_index, section_type, flags = values[0], values[1], values[2]
        va, off, size, link, info, align, entsize = values[3], values[4], values[5], values[6], values[7], values[8], values[9]
        if section_type != _SHT_NOBITS and size:
            _checked_end(off, size, len(raw), "elf_section_range_invalid")
        segment_index: int | None = None
        if flags & _SHF_EXECINSTR and size and section_type != _SHT_NOBITS:
            executable_count += 1
            containing = tuple(seg for seg in segments if (seg.flags & _PF_EXECUTE) and seg.virtual_address <= va and va + size <= seg.virtual_end and seg.file_offset <= off and off + size <= seg.file_end)
            if len(containing) != 1: raise NativeELFParseError("elf_executable_section_mapping_invalid")
            segment_index = containing[0].index
        sections.append(ELFSection(index, _section_name(names, name_index, index), section_type, flags, va, off, size, link, info, align, entsize, segment_index))
    if executable_count == 0 or executable_count > ELF_X86_64_MAX_EXECUTABLE_SECTIONS:
        raise NativeELFParseError("elf_executable_section_count_invalid")
    module = ELFModule(header.entrypoint, segments, tuple(sections))
    ordered_exec = tuple(sorted(module.executable_sections, key=lambda item: (item.virtual_address, item.file_offset, item.index)))
    for previous, current in zip(ordered_exec, ordered_exec[1:]):
        if current.virtual_address < previous.virtual_end: raise NativeELFParseError("elf_executable_section_overlap")
    if module.section_for_virtual_address(module.entrypoint) is None:
        raise NativeELFParseError("elf_entrypoint_outside_executable_section")
    return module


__all__ = (
    "ELFModule", "ELFSection", "ELFSegment", "ELF_X86_64_STRUCTURE_DIGEST",
    "ELF_X86_64_STRUCTURE_SCHEMA_VERSION", "NativeELFParseError",
    "parse_elf_x86_64_structure",
)
