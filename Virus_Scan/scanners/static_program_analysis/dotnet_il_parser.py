"""Bounded ECMA-335 PE/CLI metadata and IL method-body parser.

This module parses bytes only. It never loads, verifies, JIT-compiles, decompiles,
or executes a managed assembly. Parsed records are syntax facts used by the
canonical language-neutral static-program-analysis frontend.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping
import struct

DOTNET_IL_PARSER_SCHEMA_VERSION = "dotnet_il_parser_v1"
DOTNET_IL_MAX_SOURCE_BYTES = 10 * 1024 * 1024
DOTNET_IL_MAX_SECTIONS = 96
DOTNET_IL_MAX_STREAMS = 16
DOTNET_IL_MAX_TABLE_ROWS = 250_000
DOTNET_IL_MAX_METHODS = 16_384
DOTNET_IL_MAX_MEMBER_REFS = 65_536
DOTNET_IL_MAX_INSTRUCTIONS = 250_000
DOTNET_IL_MAX_METHOD_CODE_BYTES = 2 * 1024 * 1024
DOTNET_IL_MAX_STRING_BYTES = 16_384
DOTNET_IL_MAX_BLOB_BYTES = 65_536
DOTNET_IL_MAX_BRANCH_TARGETS = 4_096


class DotNetILNotApplicable(ValueError):
    """Raised when an exact artifact is not a managed PE/CLI image."""


class DotNetILParseError(ValueError):
    """Raised when a claimed managed PE/CLI image is malformed or out of bounds."""


@dataclass(frozen=True, slots=True)
class DotNetMethodReference:
    token: int
    declaring_type: str
    name: str
    parameter_count: int
    has_this: bool
    returns_void: bool
    pinvoke_module: str = ""
    pinvoke_name: str = ""

    @property
    def full_name(self) -> str:
        owner = self.declaring_type or "<module>"
        return owner + "::" + self.name

    @property
    def effective_name(self) -> str:
        return self.pinvoke_name or self.name


@dataclass(frozen=True, slots=True)
class DotNetILInstruction:
    offset: int
    size: int
    opcode: int
    mnemonic: str
    operand_kind: str
    operand: int | tuple[int, ...] | None
    branch_targets: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class DotNetILMethod:
    token: int
    declaring_type: str
    name: str
    rva: int
    max_stack: int
    local_signature_token: int
    code_size: int
    instructions: tuple[DotNetILInstruction, ...]
    reachable_offsets: frozenset[int]
    conditionally_reachable_offsets: frozenset[int]
    basic_block_starts: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DotNetUserString:
    token: int
    value: str


@dataclass(frozen=True, slots=True)
class DotNetILModule:
    runtime_version: str
    entrypoint_token: int
    methods: tuple[DotNetILMethod, ...]
    references: tuple[DotNetMethodReference, ...]
    user_strings: tuple[DotNetUserString, ...]
    unresolved_constructs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def reference_by_token(self) -> Mapping[int, DotNetMethodReference]:
        return MappingProxyType({item.token: item for item in self.references})

    def user_string_by_token(self) -> Mapping[int, str]:
        return MappingProxyType({item.token: item.value for item in self.user_strings})


@dataclass(frozen=True, slots=True)
class _Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True, slots=True)
class _MethodRow:
    token: int
    rva: int
    name: str
    signature_index: int
    flags: int
    impl_flags: int
    declaring_type: str = ""


@dataclass(frozen=True, slots=True)
class _MemberRow:
    token: int
    parent: int
    name: str
    signature_index: int


@dataclass(frozen=True, slots=True)
class _TypeDefRow:
    name: str
    namespace: str
    method_list: int


@dataclass(frozen=True, slots=True)
class _OpcodeSpec:
    mnemonic: str
    operand_kind: str


class _Reader:
    __slots__ = ("data",)

    def __init__(self, data: bytes) -> None:
        self.data = data

    def require(self, offset: int, size: int, reason: str) -> None:
        if type(offset) is not int or type(size) is not int or offset < 0 or size < 0:
            raise DotNetILParseError(reason)
        if offset > len(self.data) or size > len(self.data) - offset:
            raise DotNetILParseError(reason)

    def bytes(self, offset: int, size: int, reason: str) -> bytes:
        self.require(offset, size, reason)
        return self.data[offset:offset + size]

    def u8(self, offset: int, reason: str) -> int:
        self.require(offset, 1, reason)
        return self.data[offset]

    def i8(self, offset: int, reason: str) -> int:
        self.require(offset, 1, reason)
        return struct.unpack_from("<b", self.data, offset)[0]

    def u16(self, offset: int, reason: str) -> int:
        self.require(offset, 2, reason)
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int, reason: str) -> int:
        self.require(offset, 4, reason)
        return struct.unpack_from("<I", self.data, offset)[0]

    def i32(self, offset: int, reason: str) -> int:
        self.require(offset, 4, reason)
        return struct.unpack_from("<i", self.data, offset)[0]

    def u64(self, offset: int, reason: str) -> int:
        self.require(offset, 8, reason)
        return struct.unpack_from("<Q", self.data, offset)[0]


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _qualified_name(namespace: str, name: str) -> str:
    return namespace + "." + name if namespace else name


def _read_compressed_uint(data: bytes, offset: int, *, reason: str) -> tuple[int, int]:
    if offset < 0 or offset >= len(data):
        raise DotNetILParseError(reason)
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80:
        if offset + 2 > len(data):
            raise DotNetILParseError(reason)
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    if first & 0xE0 == 0xC0:
        if offset + 4 > len(data):
            raise DotNetILParseError(reason)
        value = (
            ((first & 0x1F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3]
        )
        return value, offset + 4
    raise DotNetILParseError(reason)


def _read_heap_string(heap: bytes, index: int) -> str:
    if index == 0:
        return ""
    if index < 0 or index >= len(heap):
        raise DotNetILParseError("dotnet_string_index_invalid")
    end = heap.find(b"\x00", index, min(len(heap), index + DOTNET_IL_MAX_STRING_BYTES + 1))
    if end < 0:
        raise DotNetILParseError("dotnet_string_terminator_missing")
    raw = heap[index:end]
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise DotNetILParseError("dotnet_string_utf8_invalid") from exc


def _read_heap_blob(heap: bytes, index: int) -> bytes:
    if index == 0:
        return b""
    length, cursor = _read_compressed_uint(heap, index, reason="dotnet_blob_length_invalid")
    if length > DOTNET_IL_MAX_BLOB_BYTES or cursor + length > len(heap):
        raise DotNetILParseError("dotnet_blob_bounds_invalid")
    return heap[cursor:cursor + length]


def _read_user_string(heap: bytes, index: int) -> str:
    if index == 0:
        return ""
    length, cursor = _read_compressed_uint(heap, index, reason="dotnet_user_string_length_invalid")
    if length == 0:
        return ""
    if length > DOTNET_IL_MAX_STRING_BYTES * 2 + 1 or cursor + length > len(heap):
        raise DotNetILParseError("dotnet_user_string_bounds_invalid")
    payload = heap[cursor:cursor + length]
    if len(payload) % 2 == 1:
        payload = payload[:-1]
    try:
        return payload.decode("utf-16-le", "strict")
    except UnicodeDecodeError as exc:
        raise DotNetILParseError("dotnet_user_string_utf16_invalid") from exc


def _skip_signature_type(blob: bytes, offset: int, *, depth: int = 0) -> tuple[int, int]:
    if depth > 32 or offset >= len(blob):
        raise DotNetILParseError("dotnet_signature_type_invalid")
    element = blob[offset]
    offset += 1
    if element in {0x1F, 0x20}:
        _, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_modifier_invalid")
        return _skip_signature_type(blob, offset, depth=depth + 1)
    if element in {0x0F, 0x10, 0x1D, 0x45, 0x41}:
        return _skip_signature_type(blob, offset, depth=depth + 1)
    if element in {0x11, 0x12, 0x13, 0x1E}:
        _, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_token_invalid")
        return element, offset
    if element == 0x14:
        _, offset = _skip_signature_type(blob, offset, depth=depth + 1)
        rank, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_array_rank_invalid")
        sizes, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_array_sizes_invalid")
        for _ in range(sizes):
            _, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_array_size_invalid")
        lower, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_array_bounds_invalid")
        for _ in range(lower):
            _, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_array_bound_invalid")
        if rank > 64:
            raise DotNetILParseError("dotnet_signature_array_rank_invalid")
        return element, offset
    if element == 0x15:
        if offset >= len(blob) or blob[offset] not in {0x11, 0x12}:
            raise DotNetILParseError("dotnet_signature_generic_type_invalid")
        offset += 1
        _, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_generic_token_invalid")
        count, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_generic_count_invalid")
        if count > 256:
            raise DotNetILParseError("dotnet_signature_generic_count_invalid")
        for _ in range(count):
            _, offset = _skip_signature_type(blob, offset, depth=depth + 1)
        return element, offset
    if element == 0x1B:
        _, _, _, offset = _parse_method_signature(blob, offset=offset)
        return element, offset
    return element, offset


def _parse_method_signature(blob: bytes, *, offset: int = 0) -> tuple[int, bool, bool, int]:
    if offset >= len(blob):
        raise DotNetILParseError("dotnet_method_signature_empty")
    flags = blob[offset]
    offset += 1
    if flags & 0x0F == 0x06:
        return 0, False, False, offset
    has_this = bool(flags & 0x20)
    if flags & 0x10:
        generic_count, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_generic_arity_invalid")
        if generic_count > 1024:
            raise DotNetILParseError("dotnet_signature_generic_arity_invalid")
    param_count, offset = _read_compressed_uint(blob, offset, reason="dotnet_signature_param_count_invalid")
    if param_count > 4096:
        raise DotNetILParseError("dotnet_signature_param_count_invalid")
    return_element, offset = _skip_signature_type(blob, offset)
    for _ in range(param_count):
        if offset < len(blob) and blob[offset] == 0x41:
            offset += 1
        _, offset = _skip_signature_type(blob, offset)
    return param_count, has_this, return_element == 0x01, offset


def _build_opcode_specs() -> Mapping[int, _OpcodeSpec]:
    specs: dict[int, _OpcodeSpec] = {}

    def add(code: int, name: str, operand: str = "none") -> None:
        specs[code] = _OpcodeSpec(name, operand)

    names_none = {
        0x00: "nop", 0x01: "break", 0x02: "ldarg.0", 0x03: "ldarg.1",
        0x04: "ldarg.2", 0x05: "ldarg.3", 0x06: "ldloc.0", 0x07: "ldloc.1",
        0x08: "ldloc.2", 0x09: "ldloc.3", 0x0A: "stloc.0", 0x0B: "stloc.1",
        0x0C: "stloc.2", 0x0D: "stloc.3", 0x14: "ldnull", 0x15: "ldc.i4.m1",
        0x16: "ldc.i4.0", 0x17: "ldc.i4.1", 0x18: "ldc.i4.2", 0x19: "ldc.i4.3",
        0x1A: "ldc.i4.4", 0x1B: "ldc.i4.5", 0x1C: "ldc.i4.6", 0x1D: "ldc.i4.7",
        0x1E: "ldc.i4.8", 0x25: "dup", 0x26: "pop", 0x2A: "ret",
        0x46: "ldind.i1", 0x47: "ldind.u1", 0x48: "ldind.i2", 0x49: "ldind.u2",
        0x4A: "ldind.i4", 0x4B: "ldind.u4", 0x4C: "ldind.i8", 0x4D: "ldind.i",
        0x4E: "ldind.r4", 0x4F: "ldind.r8", 0x50: "ldind.ref", 0x51: "stind.ref",
        0x52: "stind.i1", 0x53: "stind.i2", 0x54: "stind.i4", 0x55: "stind.i8",
        0x56: "stind.r4", 0x57: "stind.r8", 0x58: "add", 0x59: "sub",
        0x5A: "mul", 0x5B: "div", 0x5C: "div.un", 0x5D: "rem", 0x5E: "rem.un",
        0x5F: "and", 0x60: "or", 0x61: "xor", 0x62: "shl", 0x63: "shr",
        0x64: "shr.un", 0x65: "neg", 0x66: "not", 0x67: "conv.i1", 0x68: "conv.i2",
        0x69: "conv.i4", 0x6A: "conv.i8", 0x6B: "conv.r4", 0x6C: "conv.r8",
        0x6D: "conv.u4", 0x6E: "conv.u8", 0x76: "conv.r.un", 0x7A: "throw",
        0x8E: "ldlen", 0x90: "ldelem.i1", 0x91: "ldelem.u1", 0x92: "ldelem.i2",
        0x93: "ldelem.u2", 0x94: "ldelem.i4", 0x95: "ldelem.u4", 0x96: "ldelem.i8",
        0x97: "ldelem.i", 0x98: "ldelem.r4", 0x99: "ldelem.r8", 0x9A: "ldelem.ref",
        0x9B: "stelem.i", 0x9C: "stelem.i1", 0x9D: "stelem.i2", 0x9E: "stelem.i4",
        0x9F: "stelem.i8", 0xA0: "stelem.r4", 0xA1: "stelem.r8", 0xA2: "stelem.ref",
        0xB3: "conv.ovf.i1", 0xB4: "conv.ovf.u1", 0xB5: "conv.ovf.i2",
        0xB6: "conv.ovf.u2", 0xB7: "conv.ovf.i4", 0xB8: "conv.ovf.u4",
        0xB9: "conv.ovf.i8", 0xBA: "conv.ovf.u8", 0xC3: "ckfinite",
        0xD1: "conv.u2", 0xD2: "conv.u1", 0xD3: "conv.i", 0xD4: "conv.ovf.i",
        0xD5: "conv.ovf.u", 0xD6: "add.ovf", 0xD7: "add.ovf.un", 0xD8: "mul.ovf",
        0xD9: "mul.ovf.un", 0xDA: "sub.ovf", 0xDB: "sub.ovf.un", 0xDC: "endfinally",
        0xDF: "stind.i", 0xE0: "conv.u",
    }
    for code, name in names_none.items():
        add(code, name)
    for code, name in {
        0x0E: "ldarg.s", 0x0F: "ldarga.s", 0x10: "starg.s", 0x11: "ldloc.s",
        0x12: "ldloca.s", 0x13: "stloc.s",
    }.items():
        add(code, name, "short_var")
    add(0x1F, "ldc.i4.s", "short_i")
    add(0x20, "ldc.i4", "i4")
    add(0x21, "ldc.i8", "i8")
    add(0x22, "ldc.r4", "r4")
    add(0x23, "ldc.r8", "r8")
    add(0x27, "jmp", "method")
    add(0x28, "call", "method")
    add(0x29, "calli", "sig")
    add(0x6F, "callvirt", "method")
    add(0x72, "ldstr", "string")
    add(0x73, "newobj", "method")
    for code, name in {
        0x70: "cpobj", 0x71: "ldobj", 0x74: "castclass", 0x75: "isinst",
        0x79: "unbox", 0x81: "stobj", 0x8C: "box", 0x8D: "newarr",
        0x8F: "ldelema", 0xA3: "ldelem", 0xA4: "stelem", 0xA5: "unbox.any",
        0xC2: "refanyval", 0xC6: "mkrefany",
    }.items():
        add(code, name, "type")
    for code, name in {0x7B: "ldfld", 0x7C: "ldflda", 0x7D: "stfld", 0x7E: "ldsfld", 0x7F: "ldsflda", 0x80: "stsfld"}.items():
        add(code, name, "field")
    add(0xD0, "ldtoken", "token")
    for code, name in {
        0x2B: "br.s", 0x2C: "brfalse.s", 0x2D: "brtrue.s", 0x2E: "beq.s",
        0x2F: "bge.s", 0x30: "bgt.s", 0x31: "ble.s", 0x32: "blt.s",
        0x33: "bne.un.s", 0x34: "bge.un.s", 0x35: "bgt.un.s", 0x36: "ble.un.s",
        0x37: "blt.un.s", 0xDE: "leave.s",
    }.items():
        add(code, name, "short_branch")
    for code, name in {
        0x38: "br", 0x39: "brfalse", 0x3A: "brtrue", 0x3B: "beq", 0x3C: "bge",
        0x3D: "bgt", 0x3E: "ble", 0x3F: "blt", 0x40: "bne.un", 0x41: "bge.un",
        0x42: "bgt.un", 0x43: "ble.un", 0x44: "blt.un", 0xDD: "leave",
    }.items():
        add(code, name, "branch")
    add(0x45, "switch", "switch")
    for code, name in {
        0xFE00: "arglist", 0xFE01: "ceq", 0xFE02: "cgt", 0xFE03: "cgt.un",
        0xFE04: "clt", 0xFE05: "clt.un", 0xFE0F: "localloc", 0xFE11: "endfilter",
        0xFE13: "volatile.", 0xFE14: "tail.", 0xFE17: "cpblk", 0xFE18: "initblk",
        0xFE1A: "rethrow", 0xFE1D: "refanytype", 0xFE1E: "readonly.",
    }.items():
        add(code, name)
    for code, name in {0xFE06: "ldftn", 0xFE07: "ldvirtftn"}.items():
        add(code, name, "method")
    for code, name in {0xFE09: "ldarg", 0xFE0A: "ldarga", 0xFE0B: "starg", 0xFE0C: "ldloc", 0xFE0D: "ldloca", 0xFE0E: "stloc"}.items():
        add(code, name, "var")
    add(0xFE12, "unaligned.", "short_i")
    for code, name in {0xFE15: "initobj", 0xFE16: "constrained.", 0xFE1C: "sizeof"}.items():
        add(code, name, "type")
    return MappingProxyType(specs)


_OPCODE_SPECS = _build_opcode_specs()
_UNCONDITIONAL_BRANCHES = frozenset({"br", "br.s", "leave", "leave.s"})
_TERMINATORS = frozenset({"ret", "throw", "rethrow", "endfinally", "endfilter", "jmp"})
_CONDITIONAL_BRANCHES = frozenset({
    "brfalse", "brfalse.s", "brtrue", "brtrue.s", "beq", "beq.s", "bge", "bge.s",
    "bgt", "bgt.s", "ble", "ble.s", "blt", "blt.s", "bne.un", "bne.un.s",
    "bge.un", "bge.un.s", "bgt.un", "bgt.un.s", "ble.un", "ble.un.s",
    "blt.un", "blt.un.s", "switch",
})


_CODED_INDEX_TARGETS = MappingProxyType({
    "TypeDefOrRef": (2, (2, 1, 27)),
    "HasConstant": (2, (4, 8, 23)),
    "HasCustomAttribute": (5, (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43)),
    "HasFieldMarshal": (1, (4, 8)),
    "HasDeclSecurity": (2, (2, 6, 32)),
    "MemberRefParent": (3, (2, 1, 26, 6, 27)),
    "HasSemantics": (1, (20, 23)),
    "MethodDefOrRef": (1, (6, 10)),
    "MemberForwarded": (1, (4, 6)),
    "Implementation": (2, (38, 35, 39)),
    "CustomAttributeType": (3, (6, 10)),
    "ResolutionScope": (2, (0, 26, 35, 1)),
    "TypeOrMethodDef": (1, (2, 6)),
})


class _Tables:
    def __init__(self, stream: bytes, strings: bytes, blobs: bytes) -> None:
        self.reader = _Reader(stream)
        self.strings = strings
        self.blobs = blobs
        self.heap_sizes = self.reader.u8(6, "dotnet_tables_header_invalid")
        self.valid = self.reader.u64(8, "dotnet_tables_header_invalid")
        self.rows: dict[int, int] = {}
        cursor = 24
        total = 0
        for table_id in range(64):
            if self.valid & (1 << table_id):
                count = self.reader.u32(cursor, "dotnet_table_row_count_invalid")
                cursor += 4
                if count > DOTNET_IL_MAX_TABLE_ROWS:
                    raise DotNetILParseError("dotnet_table_row_limit_exceeded")
                total += count
                if total > DOTNET_IL_MAX_TABLE_ROWS:
                    raise DotNetILParseError("dotnet_total_table_row_limit_exceeded")
                self.rows[table_id] = count
        self.data_start = cursor
        self.offsets: dict[int, int] = {}
        for table_id in sorted(self.rows):
            if table_id > 44:
                raise DotNetILParseError("dotnet_table_unsupported")
            self.offsets[table_id] = cursor
            cursor += self.row_size(table_id) * self.rows[table_id]
            if cursor > len(stream):
                raise DotNetILParseError("dotnet_table_bounds_invalid")

    @property
    def string_size(self) -> int:
        return 4 if self.heap_sizes & 0x01 else 2

    @property
    def guid_size(self) -> int:
        return 4 if self.heap_sizes & 0x02 else 2

    @property
    def blob_size(self) -> int:
        return 4 if self.heap_sizes & 0x04 else 2

    def table_index_size(self, table_id: int) -> int:
        return 4 if self.rows.get(table_id, 0) >= 65536 else 2

    def coded_index_size(self, name: str) -> int:
        tag_bits, targets = _CODED_INDEX_TARGETS[name]
        threshold = 1 << (16 - tag_bits)
        return 4 if max((self.rows.get(table, 0) for table in targets), default=0) >= threshold else 2

    def row_size(self, table_id: int) -> int:
        ti = self.table_index_size
        ci = self.coded_index_size
        s, g, b = self.string_size, self.guid_size, self.blob_size
        if table_id == 0: return 2 + s + g * 3
        if table_id == 1: return ci("ResolutionScope") + s * 2
        if table_id == 2: return 4 + s * 2 + ci("TypeDefOrRef") + ti(4) + ti(6)
        if table_id == 3: return ti(4)
        if table_id == 4: return 2 + s + b
        if table_id == 5: return ti(6)
        if table_id == 6: return 8 + s + b + ti(8)
        if table_id == 7: return ti(8)
        if table_id == 8: return 4 + s
        if table_id == 9: return ti(2) + ci("TypeDefOrRef")
        if table_id == 10: return ci("MemberRefParent") + s + b
        if table_id == 11: return 2 + ci("HasConstant") + b
        if table_id == 12: return ci("HasCustomAttribute") + ci("CustomAttributeType") + b
        if table_id == 13: return ci("HasFieldMarshal") + b
        if table_id == 14: return 2 + ci("HasDeclSecurity") + b
        if table_id == 15: return 6 + ti(2)
        if table_id == 16: return 4 + ti(4)
        if table_id == 17: return b
        if table_id == 18: return ti(2) + ti(20)
        if table_id == 19: return ti(20)
        if table_id == 20: return 2 + s + ci("TypeDefOrRef")
        if table_id == 21: return ti(2) + ti(23)
        if table_id == 22: return ti(23)
        if table_id == 23: return 2 + s + b
        if table_id == 24: return 2 + ti(6) + ci("HasSemantics")
        if table_id == 25: return ti(2) + ci("MethodDefOrRef") * 2
        if table_id == 26: return s
        if table_id == 27: return b
        if table_id == 28: return 2 + ci("MemberForwarded") + s + ti(26)
        if table_id == 29: return 4 + ti(4)
        if table_id == 30: return 8
        if table_id == 31: return 4
        if table_id == 32: return 16 + b + s * 2
        if table_id == 33: return 4
        if table_id == 34: return 12
        if table_id == 35: return 12 + b * 2 + s * 2
        if table_id == 36: return 4 + ti(35)
        if table_id == 37: return 12 + ti(35)
        if table_id == 38: return 4 + s + b
        if table_id == 39: return 8 + s * 2 + ci("Implementation")
        if table_id == 40: return 8 + s + ci("Implementation")
        if table_id == 41: return ti(2) * 2
        if table_id == 42: return 4 + ci("TypeOrMethodDef") + s
        if table_id == 43: return ci("MethodDefOrRef") + b
        if table_id == 44: return ti(42) + ci("TypeDefOrRef")
        raise DotNetILParseError("dotnet_table_unsupported")

    def index(self, offset: int, size: int) -> int:
        return self.reader.u16(offset, "dotnet_table_index_invalid") if size == 2 else self.reader.u32(offset, "dotnet_table_index_invalid")

    def row_offset(self, table_id: int, rid: int) -> int:
        count = self.rows.get(table_id, 0)
        if rid < 1 or rid > count:
            raise DotNetILParseError("dotnet_table_rid_invalid")
        return self.offsets[table_id] + (rid - 1) * self.row_size(table_id)

    def string_at(self, offset: int) -> tuple[str, int]:
        index = self.index(offset, self.string_size)
        return _read_heap_string(self.strings, index), offset + self.string_size

    def blob_at(self, offset: int) -> tuple[bytes, int]:
        index = self.index(offset, self.blob_size)
        return _read_heap_blob(self.blobs, index), offset + self.blob_size


def _decode_coded(value: int, name: str) -> tuple[int, int]:
    tag_bits, targets = _CODED_INDEX_TARGETS[name]
    tag = value & ((1 << tag_bits) - 1)
    rid = value >> tag_bits
    if rid == 0:
        return 0, 0
    if tag >= len(targets):
        raise DotNetILParseError("dotnet_coded_index_tag_invalid")
    return targets[tag], rid


def _parse_sections(reader: _Reader) -> tuple[list[_Section], int, int, int]:
    if reader.bytes(0, 2, "dotnet_dos_header_invalid") != b"MZ":
        raise DotNetILNotApplicable("not_pe")
    pe_offset = reader.u32(0x3C, "dotnet_pe_offset_invalid")
    if reader.bytes(pe_offset, 4, "dotnet_pe_signature_invalid") != b"PE\x00\x00":
        raise DotNetILNotApplicable("not_pe")
    coff = pe_offset + 4
    section_count = reader.u16(coff + 2, "dotnet_coff_header_invalid")
    optional_size = reader.u16(coff + 16, "dotnet_coff_header_invalid")
    if section_count < 1 or section_count > DOTNET_IL_MAX_SECTIONS:
        raise DotNetILParseError("dotnet_section_count_invalid")
    optional = coff + 20
    magic = reader.u16(optional, "dotnet_optional_header_invalid")
    if magic == 0x10B:
        directory = optional + 96
    elif magic == 0x20B:
        directory = optional + 112
    else:
        raise DotNetILNotApplicable("not_supported_pe")
    if optional_size < directory - optional + 15 * 8:
        raise DotNetILParseError("dotnet_optional_header_truncated")
    cli_rva = reader.u32(directory + 14 * 8, "dotnet_cli_directory_invalid")
    cli_size = reader.u32(directory + 14 * 8 + 4, "dotnet_cli_directory_invalid")
    if cli_rva == 0 or cli_size < 24:
        raise DotNetILNotApplicable("clr_directory_absent")
    section_table = optional + optional_size
    sections: list[_Section] = []
    for index in range(section_count):
        offset = section_table + index * 40
        reader.require(offset, 40, "dotnet_section_header_invalid")
        virtual_size = reader.u32(offset + 8, "dotnet_section_header_invalid")
        virtual_address = reader.u32(offset + 12, "dotnet_section_header_invalid")
        raw_size = reader.u32(offset + 16, "dotnet_section_header_invalid")
        raw_offset = reader.u32(offset + 20, "dotnet_section_header_invalid")
        if raw_size:
            reader.require(raw_offset, raw_size, "dotnet_section_raw_bounds_invalid")
        sections.append(_Section(virtual_address, virtual_size, raw_offset, raw_size))
    return sections, cli_rva, cli_size, magic


def _rva_offset(rva: int, sections: list[_Section], *, reason: str) -> int:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            delta = rva - section.virtual_address
            if delta >= section.raw_size:
                raise DotNetILParseError(reason)
            return section.raw_offset + delta
    raise DotNetILParseError(reason)


def _metadata_streams(reader: _Reader, metadata_offset: int, metadata_size: int) -> tuple[str, Mapping[str, bytes]]:
    reader.require(metadata_offset, metadata_size, "dotnet_metadata_bounds_invalid")
    if reader.bytes(metadata_offset, 4, "dotnet_metadata_signature_invalid") != b"BSJB":
        raise DotNetILParseError("dotnet_metadata_signature_invalid")
    version_length = reader.u32(metadata_offset + 12, "dotnet_metadata_header_invalid")
    if version_length > 1024:
        raise DotNetILParseError("dotnet_metadata_version_invalid")
    version_raw = reader.bytes(metadata_offset + 16, version_length, "dotnet_metadata_version_invalid")
    runtime_version = version_raw.rstrip(b"\x00").decode("ascii", "replace")[:128]
    cursor = _align4(metadata_offset + 16 + version_length)
    reader.require(cursor, 4, "dotnet_metadata_stream_header_invalid")
    stream_count = reader.u16(cursor + 2, "dotnet_metadata_stream_header_invalid")
    if stream_count < 1 or stream_count > DOTNET_IL_MAX_STREAMS:
        raise DotNetILParseError("dotnet_metadata_stream_count_invalid")
    cursor += 4
    streams: dict[str, bytes] = {}
    metadata_end = metadata_offset + metadata_size
    for _ in range(stream_count):
        stream_offset = reader.u32(cursor, "dotnet_metadata_stream_invalid")
        stream_size = reader.u32(cursor + 4, "dotnet_metadata_stream_invalid")
        name_start = cursor + 8
        name_end = name_start
        while name_end < min(metadata_end, name_start + 32) and reader.data[name_end] != 0:
            name_end += 1
        if name_end >= metadata_end or name_end == name_start:
            raise DotNetILParseError("dotnet_metadata_stream_name_invalid")
        name = reader.data[name_start:name_end].decode("ascii", "strict")
        cursor = _align4(name_end + 1)
        absolute = metadata_offset + stream_offset
        reader.require(absolute, stream_size, "dotnet_metadata_stream_bounds_invalid")
        if absolute + stream_size > metadata_end:
            raise DotNetILParseError("dotnet_metadata_stream_bounds_invalid")
        if name in streams:
            raise DotNetILParseError("dotnet_metadata_stream_duplicate")
        streams[name] = reader.data[absolute:absolute + stream_size]
    return runtime_version, MappingProxyType(streams)


def _parse_metadata(streams: Mapping[str, bytes]) -> tuple[
    tuple[_MethodRow, ...], tuple[_MemberRow, ...], Mapping[int, str], Mapping[int, str],
    Mapping[int, tuple[str, str]], Mapping[int, int], Mapping[int, tuple[str, str]], bytes, bytes,
]:
    tables_blob = streams.get("#~") or streams.get("#-")
    strings = streams.get("#Strings")
    blobs = streams.get("#Blob")
    user_strings = streams.get("#US", b"")
    if tables_blob is None or strings is None or blobs is None:
        raise DotNetILParseError("dotnet_required_metadata_stream_missing")
    tables = _Tables(tables_blob, strings, blobs)

    type_refs: dict[int, str] = {}
    for rid in range(1, tables.rows.get(1, 0) + 1):
        cursor = tables.row_offset(1, rid) + tables.coded_index_size("ResolutionScope")
        name, cursor = tables.string_at(cursor)
        namespace, _ = tables.string_at(cursor)
        type_refs[rid] = _qualified_name(namespace, name)

    type_defs: list[_TypeDefRow] = []
    for rid in range(1, tables.rows.get(2, 0) + 1):
        cursor = tables.row_offset(2, rid) + 4
        name, cursor = tables.string_at(cursor)
        namespace, cursor = tables.string_at(cursor)
        cursor += tables.coded_index_size("TypeDefOrRef") + tables.table_index_size(4)
        method_list = tables.index(cursor, tables.table_index_size(6))
        type_defs.append(_TypeDefRow(name, namespace, method_list))

    methods: list[_MethodRow] = []
    method_count = tables.rows.get(6, 0)
    if method_count > DOTNET_IL_MAX_METHODS:
        raise DotNetILParseError("dotnet_method_limit_exceeded")
    for rid in range(1, method_count + 1):
        cursor = tables.row_offset(6, rid)
        rva = tables.reader.u32(cursor, "dotnet_method_row_invalid")
        impl_flags = tables.reader.u16(cursor + 4, "dotnet_method_row_invalid")
        flags = tables.reader.u16(cursor + 6, "dotnet_method_row_invalid")
        cursor += 8
        name, cursor = tables.string_at(cursor)
        signature_index = tables.index(cursor, tables.blob_size)
        methods.append(_MethodRow(0x06000000 | rid, rva, name, signature_index, flags, impl_flags))

    for index, type_def in enumerate(type_defs):
        start = type_def.method_list
        end = type_defs[index + 1].method_list if index + 1 < len(type_defs) else method_count + 1
        if start == 0:
            continue
        if start > end or end > method_count + 1:
            raise DotNetILParseError("dotnet_typedef_method_range_invalid")
        owner = _qualified_name(type_def.namespace, type_def.name)
        for rid in range(start, end):
            row = methods[rid - 1]
            methods[rid - 1] = _MethodRow(row.token, row.rva, row.name, row.signature_index, row.flags, row.impl_flags, owner)

    module_refs: dict[int, str] = {}
    for rid in range(1, tables.rows.get(26, 0) + 1):
        name, _ = tables.string_at(tables.row_offset(26, rid))
        module_refs[rid] = name

    pinvoke: dict[int, tuple[str, str]] = {}
    for rid in range(1, tables.rows.get(28, 0) + 1):
        cursor = tables.row_offset(28, rid) + 2
        forwarded = tables.index(cursor, tables.coded_index_size("MemberForwarded"))
        cursor += tables.coded_index_size("MemberForwarded")
        import_name, cursor = tables.string_at(cursor)
        module_rid = tables.index(cursor, tables.table_index_size(26))
        table_id, member_rid = _decode_coded(forwarded, "MemberForwarded")
        if table_id == 6 and member_rid:
            pinvoke[0x06000000 | member_rid] = (module_refs.get(module_rid, ""), import_name)

    members: list[_MemberRow] = []
    member_count = tables.rows.get(10, 0)
    if member_count > DOTNET_IL_MAX_MEMBER_REFS:
        raise DotNetILParseError("dotnet_member_ref_limit_exceeded")
    for rid in range(1, member_count + 1):
        cursor = tables.row_offset(10, rid)
        parent = tables.index(cursor, tables.coded_index_size("MemberRefParent"))
        cursor += tables.coded_index_size("MemberRefParent")
        name, cursor = tables.string_at(cursor)
        signature_index = tables.index(cursor, tables.blob_size)
        members.append(_MemberRow(0x0A000000 | rid, parent, name, signature_index))

    method_specs: dict[int, int] = {}
    for rid in range(1, tables.rows.get(43, 0) + 1):
        cursor = tables.row_offset(43, rid)
        coded = tables.index(cursor, tables.coded_index_size("MethodDefOrRef"))
        table_id, target_rid = _decode_coded(coded, "MethodDefOrRef")
        if table_id in {6, 10} and target_rid:
            method_specs[0x2B000000 | rid] = (table_id << 24) | target_rid

    method_names = {row.token: (row.declaring_type, row.name) for row in methods}
    type_defs_by_rid = {rid: _qualified_name(row.namespace, row.name) for rid, row in enumerate(type_defs, 1)}
    member_parents: dict[int, tuple[str, str]] = {}
    for row in members:
        table_id, parent_rid = _decode_coded(row.parent, "MemberRefParent")
        owner = ""
        if table_id == 1:
            owner = type_refs.get(parent_rid, "")
        elif table_id == 2:
            owner = type_defs_by_rid.get(parent_rid, "")
        elif table_id == 26:
            owner = module_refs.get(parent_rid, "")
        elif table_id == 6:
            owner = method_names.get(0x06000000 | parent_rid, ("", ""))[0]
        elif table_id == 27:
            owner = "<typespec:" + str(parent_rid) + ">"
        member_parents[row.token] = (owner, row.name)

    return (
        tuple(methods), tuple(members), MappingProxyType(type_refs), MappingProxyType(type_defs_by_rid),
        MappingProxyType(pinvoke), MappingProxyType(method_specs), MappingProxyType(member_parents), blobs, user_strings,
    )


def _operand(reader: _Reader, code_start: int, cursor: int, end: int, kind: str) -> tuple[int | tuple[int, ...] | None, int, tuple[int, ...]]:
    def ensure(size: int) -> None:
        if cursor + size > end:
            raise DotNetILParseError("dotnet_il_operand_truncated")
    if kind == "none":
        return None, cursor, ()
    if kind in {"short_i", "short_var"}:
        ensure(1)
        value = reader.i8(cursor, "dotnet_il_operand_invalid") if kind == "short_i" else reader.u8(cursor, "dotnet_il_operand_invalid")
        return value, cursor + 1, ()
    if kind == "var":
        ensure(2)
        return reader.u16(cursor, "dotnet_il_operand_invalid"), cursor + 2, ()
    if kind in {"i4", "r4", "method", "field", "type", "string", "sig", "token"}:
        ensure(4)
        value = reader.u32(cursor, "dotnet_il_operand_invalid")
        return value, cursor + 4, ()
    if kind in {"i8", "r8"}:
        ensure(8)
        return reader.u64(cursor, "dotnet_il_operand_invalid"), cursor + 8, ()
    if kind == "short_branch":
        ensure(1)
        delta = reader.i8(cursor, "dotnet_il_branch_invalid")
        target = cursor + 1 - code_start + delta
        return target, cursor + 1, (target,)
    if kind == "branch":
        ensure(4)
        delta = reader.i32(cursor, "dotnet_il_branch_invalid")
        target = cursor + 4 - code_start + delta
        return target, cursor + 4, (target,)
    if kind == "switch":
        ensure(4)
        count = reader.u32(cursor, "dotnet_il_switch_invalid")
        if count > DOTNET_IL_MAX_BRANCH_TARGETS:
            raise DotNetILParseError("dotnet_il_switch_limit_exceeded")
        base = cursor + 4 + count * 4
        if base > end:
            raise DotNetILParseError("dotnet_il_switch_truncated")
        targets = tuple(base - code_start + reader.i32(cursor + 4 + index * 4, "dotnet_il_switch_invalid") for index in range(count))
        return targets, base, targets
    raise DotNetILParseError("dotnet_il_operand_kind_invalid")


def _decode_method(reader: _Reader, offset: int, rva: int, token: int, declaring_type: str, name: str) -> DotNetILMethod:
    first = reader.u8(offset, "dotnet_method_header_invalid")
    more_sections = False
    if first & 0x03 == 0x02:
        header_size = 1
        code_size = first >> 2
        max_stack = 8
        local_token = 0
    elif first & 0x03 == 0x03:
        flags_size = reader.u16(offset, "dotnet_method_header_invalid")
        header_dwords = flags_size >> 12
        if header_dwords < 3 or header_dwords > 16:
            raise DotNetILParseError("dotnet_method_header_size_invalid")
        header_size = header_dwords * 4
        max_stack = reader.u16(offset + 2, "dotnet_method_header_invalid")
        code_size = reader.u32(offset + 4, "dotnet_method_header_invalid")
        local_token = reader.u32(offset + 8, "dotnet_method_header_invalid")
        more_sections = bool(flags_size & 0x08)
    else:
        raise DotNetILParseError("dotnet_method_header_format_invalid")
    if code_size > DOTNET_IL_MAX_METHOD_CODE_BYTES:
        raise DotNetILParseError("dotnet_method_code_limit_exceeded")
    code_start = offset + header_size
    code_end = code_start + code_size
    reader.require(code_start, code_size, "dotnet_method_code_truncated")
    instructions: list[DotNetILInstruction] = []
    cursor = code_start
    while cursor < code_end:
        if len(instructions) >= DOTNET_IL_MAX_INSTRUCTIONS:
            raise DotNetILParseError("dotnet_instruction_limit_exceeded")
        instruction_start = cursor
        first_op = reader.u8(cursor, "dotnet_il_opcode_invalid")
        cursor += 1
        opcode = first_op
        if first_op == 0xFE:
            if cursor >= code_end:
                raise DotNetILParseError("dotnet_il_opcode_truncated")
            opcode = 0xFE00 | reader.u8(cursor, "dotnet_il_opcode_invalid")
            cursor += 1
        spec = _OPCODE_SPECS.get(opcode)
        if spec is None:
            raise DotNetILParseError("dotnet_il_opcode_unsupported:" + hex(opcode))
        operand, cursor, targets = _operand(reader, code_start, cursor, code_end, spec.operand_kind)
        local_offset = instruction_start - code_start
        instructions.append(DotNetILInstruction(
            offset=local_offset,
            size=cursor - instruction_start,
            opcode=opcode,
            mnemonic=spec.mnemonic,
            operand_kind=spec.operand_kind,
            operand=operand,
            branch_targets=targets,
        ))
    offsets = {item.offset for item in instructions}
    leaders = {0}
    next_by_offset: dict[int, int | None] = {}
    for index, instruction in enumerate(instructions):
        next_offset = instructions[index + 1].offset if index + 1 < len(instructions) else None
        next_by_offset[instruction.offset] = next_offset
        for target in instruction.branch_targets:
            if target not in offsets:
                raise DotNetILParseError("dotnet_il_branch_target_invalid")
            leaders.add(target)
        if instruction.mnemonic in _UNCONDITIONAL_BRANCHES | _CONDITIONAL_BRANCHES | _TERMINATORS and next_offset is not None:
            leaders.add(next_offset)
    reachable: set[int] = set()
    conditional: set[int] = set()
    pending: list[tuple[int, bool]] = [(0, False)] if instructions else []
    instruction_by_offset = {item.offset: item for item in instructions}
    visited_states: set[tuple[int, bool]] = set()
    while pending:
        current, conditional_path = pending.pop()
        state = (current, conditional_path)
        if state in visited_states:
            continue
        visited_states.add(state)
        instruction = instruction_by_offset.get(current)
        if instruction is None:
            continue
        reachable.add(current)
        if conditional_path:
            conditional.add(current)
        successors: list[tuple[int, bool]] = []
        if instruction.mnemonic in _UNCONDITIONAL_BRANCHES:
            successors.extend((target, conditional_path) for target in instruction.branch_targets)
        elif instruction.mnemonic in _TERMINATORS:
            pass
        elif instruction.mnemonic in _CONDITIONAL_BRANCHES:
            successors.extend((target, True) for target in instruction.branch_targets)
            next_offset = next_by_offset[current]
            if next_offset is not None:
                successors.append((next_offset, True))
        else:
            next_offset = next_by_offset[current]
            if next_offset is not None:
                successors.append((next_offset, conditional_path))
        pending.extend(successors)
    if more_sections:
        # Exception handlers are bounded by the method body but not interpreted in v1.
        pass
    return DotNetILMethod(
        token=token,
        declaring_type=declaring_type,
        name=name,
        rva=rva,
        max_stack=max_stack,
        local_signature_token=local_token,
        code_size=code_size,
        instructions=tuple(instructions),
        reachable_offsets=frozenset(reachable),
        conditionally_reachable_offsets=frozenset(conditional),
        basic_block_starts=tuple(sorted(leaders)),
    )


def parse_dotnet_il(data: bytes) -> DotNetILModule:
    """Parse one exact managed PE/CLI image into immutable metadata and IL records."""
    if type(data) is not bytes:
        raise TypeError("dotnet_il_bytes_required")
    if len(data) > DOTNET_IL_MAX_SOURCE_BYTES:
        raise DotNetILParseError("dotnet_source_size_limit_exceeded")
    reader = _Reader(data)
    sections, cli_rva, _cli_size, _magic = _parse_sections(reader)
    cli_offset = _rva_offset(cli_rva, sections, reason="dotnet_cli_rva_invalid")
    reader.require(cli_offset, 24, "dotnet_cli_header_truncated")
    metadata_rva = reader.u32(cli_offset + 8, "dotnet_cli_header_invalid")
    metadata_size = reader.u32(cli_offset + 12, "dotnet_cli_header_invalid")
    entrypoint_token = reader.u32(cli_offset + 20, "dotnet_cli_header_invalid")
    if metadata_rva == 0 or metadata_size == 0 or metadata_size > DOTNET_IL_MAX_SOURCE_BYTES:
        raise DotNetILParseError("dotnet_metadata_directory_invalid")
    metadata_offset = _rva_offset(metadata_rva, sections, reason="dotnet_metadata_rva_invalid")
    runtime_version, streams = _metadata_streams(reader, metadata_offset, metadata_size)
    methods, members, _type_refs, _type_defs, pinvoke, method_specs, member_parents, blobs, user_strings = _parse_metadata(streams)

    references: dict[int, DotNetMethodReference] = {}
    for row in methods:
        signature = _read_heap_blob(blobs, row.signature_index)
        param_count, has_this, returns_void, _ = _parse_method_signature(signature)
        module_name, import_name = pinvoke.get(row.token, ("", ""))
        references[row.token] = DotNetMethodReference(
            token=row.token,
            declaring_type=row.declaring_type,
            name=row.name,
            parameter_count=param_count,
            has_this=has_this,
            returns_void=returns_void,
            pinvoke_module=module_name,
            pinvoke_name=import_name,
        )
    for row in members:
        signature = _read_heap_blob(blobs, row.signature_index)
        param_count, has_this, returns_void, _ = _parse_method_signature(signature)
        owner, name = member_parents.get(row.token, ("", row.name))
        references[row.token] = DotNetMethodReference(
            token=row.token,
            declaring_type=owner,
            name=name,
            parameter_count=param_count,
            has_this=has_this,
            returns_void=returns_void,
        )
    for token, target in method_specs.items():
        base = references.get(target)
        if base is not None:
            references[token] = DotNetMethodReference(
                token=token,
                declaring_type=base.declaring_type,
                name=base.name,
                parameter_count=base.parameter_count,
                has_this=base.has_this,
                returns_void=base.returns_void,
                pinvoke_module=base.pinvoke_module,
                pinvoke_name=base.pinvoke_name,
            )

    decoded: list[DotNetILMethod] = []
    limitations: set[str] = set()
    total_instructions = 0
    for row in methods:
        if row.rva == 0:
            continue
        offset = _rva_offset(row.rva, sections, reason="dotnet_method_rva_invalid")
        method = _decode_method(reader, offset, row.rva, row.token, row.declaring_type, row.name)
        total_instructions += len(method.instructions)
        if total_instructions > DOTNET_IL_MAX_INSTRUCTIONS:
            raise DotNetILParseError("dotnet_instruction_limit_exceeded")
        decoded.append(method)
    if any(reader.u16(_rva_offset(row.rva, sections, reason="dotnet_method_rva_invalid"), "dotnet_method_header_invalid") & 0x08 for row in methods if row.rva and (reader.u8(_rva_offset(row.rva, sections, reason="dotnet_method_rva_invalid"), "dotnet_method_header_invalid") & 0x03) == 0x03):
        limitations.add("exception_sections_not_interpreted")

    unresolved: set[str] = set()
    referenced_user_strings: dict[int, str] = {}
    for method in decoded:
        for instruction in method.instructions:
            if instruction.operand_kind == "string" and type(instruction.operand) is int:
                try:
                    referenced_user_strings[instruction.operand] = _read_user_string(
                        user_strings, instruction.operand & 0x00FFFFFF,
                    )
                except DotNetILParseError:
                    unresolved.add("user_string_token_invalid:" + hex(instruction.operand))
            if instruction.operand_kind == "method" and type(instruction.operand) is int and instruction.operand not in references:
                unresolved.add("method_token_unresolved:" + hex(instruction.operand))
    return DotNetILModule(
        runtime_version=runtime_version,
        entrypoint_token=entrypoint_token,
        methods=tuple(decoded),
        references=tuple(references[token] for token in sorted(references)),
        user_strings=tuple(
            DotNetUserString(token=token, value=referenced_user_strings[token])
            for token in sorted(referenced_user_strings)
        ),
        unresolved_constructs=tuple(sorted(unresolved)),
        limitations=tuple(sorted(limitations)),
    )


__all__ = (
    "DOTNET_IL_MAX_INSTRUCTIONS",
    "DOTNET_IL_MAX_METHODS",
    "DOTNET_IL_MAX_SOURCE_BYTES",
    "DOTNET_IL_PARSER_SCHEMA_VERSION",
    "DotNetILInstruction",
    "DotNetILMethod",
    "DotNetILModule",
    "DotNetILNotApplicable",
    "DotNetILParseError",
    "DotNetMethodReference",
    "DotNetUserString",
    "parse_dotnet_il",
)
