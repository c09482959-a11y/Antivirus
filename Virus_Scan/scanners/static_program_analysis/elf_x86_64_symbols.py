"""Canonical ELF64/x86-64 dynamic-symbol, relocation, PLT/GOT identity owner."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import struct

from Virus_Scan.scanners.static_program_analysis.elf_x86_64_structure import ELFModule

ELF_X86_64_SYMBOLS_SCHEMA_VERSION = "elf_x86_64_symbols_v1"
ELF_X86_64_MAX_DYNAMIC_SYMBOLS = 16_384
ELF_X86_64_MAX_RELOCATIONS = 16_384

_ELF64_SYMBOL = struct.Struct("<IBBHQQ")
_ELF64_RELA = struct.Struct("<QQq")
_ELF64_DYNAMIC = struct.Struct("<qQ")
_SHT_DYNSYM = 11
_SHT_RELA = 4
_SHT_DYNAMIC = 6
_SHN_UNDEF = 0


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


ELF_X86_64_SYMBOLS_DIGEST = _digest({
    "schema": ELF_X86_64_SYMBOLS_SCHEMA_VERSION,
    "max_dynamic_symbols": ELF_X86_64_MAX_DYNAMIC_SYMBOLS,
    "max_relocations": ELF_X86_64_MAX_RELOCATIONS,
    "relocation": "elf64_rela_x86_64",
})


@dataclass(frozen=True, slots=True)
class ImportedSymbol:
    symbol_index: int
    name: str
    binding: int
    symbol_type: int


@dataclass(frozen=True, slots=True)
class PLTTarget:
    plt_address: int
    got_address: int
    symbol_index: int
    symbol_name: str
    relocation_type: int


@dataclass(frozen=True, slots=True)
class ELFSymbolResolution:
    imports: tuple[ImportedSymbol, ...]
    plt_targets: tuple[PLTTarget, ...]
    dynamic_tags: tuple[tuple[int, int], ...]
    limitations: tuple[str, ...]

    def imported_name(self, symbol_index: int) -> str | None:
        for item in self.imports:
            if item.symbol_index == symbol_index:
                return item.name
        return None

    def plt_symbol(self, address: int) -> str | None:
        for item in self.plt_targets:
            if item.plt_address == address:
                return item.symbol_name
        return None

    @property
    def import_names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.imports)


def _cstring(table: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end < 0:
        return ""
    raw = table[offset:end]
    if not raw or len(raw) > 512:
        return ""
    value = raw.decode("utf-8", "replace")
    if "\ufffd" in value:
        return ""
    return value if all(ord(ch) >= 32 for ch in value) else ""


def _parse_dynamic_tags(raw: bytes, module: ELFModule, limitations: set[str]) -> tuple[tuple[int, int], ...]:
    section = module.section_by_name(".dynamic")
    if section is None or section.section_type != _SHT_DYNAMIC or section.size == 0:
        return ()
    entry_size = section.entry_size or _ELF64_DYNAMIC.size
    if entry_size != _ELF64_DYNAMIC.size or section.size % entry_size:
        limitations.add("argument_unresolved")
        return ()
    tags: list[tuple[int, int]] = []
    data = raw[section.file_offset:section.file_end]
    for offset in range(0, len(data), entry_size):
        tag, value = _ELF64_DYNAMIC.unpack_from(data, offset)
        tags.append((int(tag), int(value)))
        if tag == 0:
            break
    return tuple(tags)


def resolve_elf_x86_64_symbols(raw: bytes, module: ELFModule) -> ELFSymbolResolution:
    if type(raw) is not bytes or type(module) is not ELFModule:
        raise TypeError("native_elf_symbol_inputs_invalid")
    limitations: set[str] = set()
    dynsym = module.section_by_name(".dynsym")
    if dynsym is None:
        return ELFSymbolResolution((), (), _parse_dynamic_tags(raw, module, limitations), ())
    if dynsym.section_type != _SHT_DYNSYM:
        limitations.add("target_unresolved")
        return ELFSymbolResolution((), (), _parse_dynamic_tags(raw, module, limitations), tuple(sorted(limitations)))
    if not (0 <= dynsym.link < len(module.sections)):
        limitations.add("target_unresolved")
        return ELFSymbolResolution((), (), _parse_dynamic_tags(raw, module, limitations), tuple(sorted(limitations)))
    dynstr = module.sections[dynsym.link]
    string_bytes = raw[dynstr.file_offset:dynstr.file_end]
    entry_size = dynsym.entry_size or _ELF64_SYMBOL.size
    if entry_size != _ELF64_SYMBOL.size or dynsym.size % entry_size:
        limitations.add("target_unresolved")
        return ELFSymbolResolution((), (), _parse_dynamic_tags(raw, module, limitations), tuple(sorted(limitations)))
    count = dynsym.size // entry_size
    if count > ELF_X86_64_MAX_DYNAMIC_SYMBOLS:
        limitations.add("target_unresolved")
        count = ELF_X86_64_MAX_DYNAMIC_SYMBOLS
    imports: list[ImportedSymbol] = []
    by_index: dict[int, ImportedSymbol] = {}
    data = raw[dynsym.file_offset:dynsym.file_end]
    for index in range(count):
        name_offset, info, _other, shndx, _value, _size = _ELF64_SYMBOL.unpack_from(data, index * entry_size)
        if index == 0 or shndx != _SHN_UNDEF:
            continue
        name = _cstring(string_bytes, name_offset)
        if not name:
            limitations.add("target_unresolved")
            continue
        item = ImportedSymbol(index, name, info >> 4, info & 0xF)
        imports.append(item)
        by_index[index] = item

    rela = module.section_by_name(".rela.plt")
    plt = module.section_by_name(".plt")
    targets: list[PLTTarget] = []
    if rela is not None and plt is not None:
        if rela.section_type != _SHT_RELA:
            limitations.add("target_unresolved")
        else:
            rela_entry_size = rela.entry_size or _ELF64_RELA.size
            if rela_entry_size != _ELF64_RELA.size or rela.size % rela_entry_size:
                limitations.add("target_unresolved")
            else:
                relocation_count = rela.size // rela_entry_size
                if relocation_count > ELF_X86_64_MAX_RELOCATIONS:
                    limitations.add("target_unresolved")
                    relocation_count = ELF_X86_64_MAX_RELOCATIONS
                plt_entry_size = plt.entry_size or 16
                if plt_entry_size <= 0:
                    limitations.add("target_unresolved")
                else:
                    plt_entry_count = plt.size // plt_entry_size
                    reserved_entries = 1 if plt_entry_count == relocation_count + 1 else 0
                    rela_bytes = raw[rela.file_offset:rela.file_end]
                    for slot in range(relocation_count):
                        got_address, info, _addend = _ELF64_RELA.unpack_from(rela_bytes, slot * rela_entry_size)
                        symbol_index = int(info >> 32)
                        relocation_type = int(info & 0xFFFFFFFF)
                        symbol = by_index.get(symbol_index)
                        if symbol is None:
                            limitations.add("target_unresolved")
                            continue
                        plt_address = plt.virtual_address + (slot + reserved_entries) * plt_entry_size
                        if plt_address >= plt.virtual_end:
                            limitations.add("target_unresolved")
                            continue
                        targets.append(PLTTarget(plt_address, int(got_address), symbol_index, symbol.name, relocation_type))
    elif rela is not None or plt is not None:
        limitations.add("target_unresolved")

    return ELFSymbolResolution(
        tuple(sorted(imports, key=lambda item: item.symbol_index)),
        tuple(sorted(targets, key=lambda item: item.plt_address)),
        _parse_dynamic_tags(raw, module, limitations),
        tuple(sorted(limitations)),
    )


__all__ = (
    "ELFSymbolResolution", "ELF_X86_64_SYMBOLS_DIGEST", "ELF_X86_64_SYMBOLS_SCHEMA_VERSION",
    "ImportedSymbol", "PLTTarget", "resolve_elf_x86_64_symbols",
)
