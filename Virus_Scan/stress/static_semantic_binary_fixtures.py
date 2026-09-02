"""Canonical deterministic inert PE/CLI and ELF fixtures for static-semantic evaluation."""
from __future__ import annotations

import struct


def _identity_overlay(identity_marker: str) -> bytes:
    if type(identity_marker) is not str:
        raise TypeError("static_semantic_binary_identity_marker_invalid")
    if not identity_marker:
        return b""
    encoded = identity_marker.encode("ascii", "strict")
    if len(encoded) > 160 or not encoded.startswith(b"UMIGE_STATIC_SEMANTIC:"):
        raise ValueError("static_semantic_binary_identity_marker_invalid")
    return b"\n" + encoded + b"\n"


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _compressed_uint(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    if value < 0x4000:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    return bytes((
        0xC0 | ((value >> 24) & 0x1F),
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
    ))


class _Heap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self.indexes: dict[object, int] = {}

    def string(self, value: str) -> int:
        key = ("string", value)
        if key in self.indexes:
            return self.indexes[key]
        index = len(self.data)
        self.data += value.encode("utf-8", "strict") + b"\x00"
        self.indexes[key] = index
        return index

    def blob(self, value: bytes) -> int:
        key = ("blob", value)
        if key in self.indexes:
            return self.indexes[key]
        index = len(self.data)
        self.data += _compressed_uint(len(value)) + value
        self.indexes[key] = index
        return index

    def user_string(self, value: str) -> int:
        key = ("user", value)
        if key in self.indexes:
            return self.indexes[key]
        index = len(self.data)
        raw = value.encode("utf-16-le", "strict") + b"\x00"
        self.data += _compressed_uint(len(raw)) + raw
        self.indexes[key] = index
        return index


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _token(table_id: int, rid: int) -> int:
    return (table_id << 24) | rid


def build_managed_dotnet_fixture(
    *,
    include_pinvoke: bool = True,
    documentation_only: bool = False,
    identity_marker: str = "",
) -> bytes:
    """Return a non-executed managed PE with reachable, dead, flow, and P/Invoke IL."""
    strings = _Heap()
    blobs = _Heap()
    user_strings = _Heap()
    names = {
        value: strings.string(value)
        for value in (
            "FixtureModule", "Program", "Fixture", "Main", "Dead", "NativeOpenProcess",
            "System.IO", "File", "System.Net.Http", "HttpClient",
            "System.Diagnostics", "Process", "System", "Convert", "ReadAllBytes",
            "PostAsync", "Start", "FromBase64String", "mscorlib", "kernel32.dll",
            "OpenProcess",
        )
    }
    signature_main = blobs.blob(bytes((0x00, 0x00, 0x01)))
    signature_read = blobs.blob(bytes((0x00, 0x01, 0x1D, 0x05, 0x0E)))
    signature_post = blobs.blob(bytes((0x20, 0x02, 0x1C, 0x0E, 0x1C)))
    signature_start = blobs.blob(bytes((0x00, 0x01, 0x1C, 0x0E)))
    signature_decode = blobs.blob(bytes((0x00, 0x01, 0x1D, 0x05, 0x0E)))
    signature_pinvoke = blobs.blob(bytes((0x00, 0x03, 0x18, 0x08, 0x02, 0x08)))
    literals = {
        value: user_strings.user_string(value)
        for value in (
            "C:/Users/Test/Login Data",
            "https://example.invalid/upload",
            "calc.exe",
        )
    }

    method_count = 3 if include_pinvoke else 2
    table_ids = [0, 1, 2, 6, 10, 35]
    if include_pinvoke:
        table_ids.extend((26, 28))
    valid = sum(1 << table_id for table_id in table_ids)
    tables = bytearray()
    tables += _u32(0) + bytes((2, 0, 0, 1)) + _u64(valid) + _u64(0)
    row_counts = {0: 1, 1: 4, 2: 1, 6: method_count, 10: 4, 35: 1}
    if include_pinvoke:
        row_counts.update({26: 1, 28: 1})
    for table_id in sorted(row_counts):
        tables += _u32(row_counts[table_id])

    tables += _u16(0) + _u16(names["FixtureModule"]) + _u16(0) * 3
    for name, namespace in (
        ("File", "System.IO"),
        ("HttpClient", "System.Net.Http"),
        ("Process", "System.Diagnostics"),
        ("Convert", "System"),
    ):
        tables += _u16(6) + _u16(names[name]) + _u16(names[namespace])
    tables += (
        _u32(0x00100001)
        + _u16(names["Program"])
        + _u16(names["Fixture"])
        + _u16(0)
        + _u16(1)
        + _u16(1)
    )
    method_rows = [
        (0x2400, "Main", signature_main, 0x0016),
        (0x2460, "Dead", signature_main, 0x0016),
    ]
    if include_pinvoke:
        method_rows.append((0, "NativeOpenProcess", signature_pinvoke, 0x2016))
    for rva, name, signature, flags in method_rows:
        tables += (
            _u32(rva) + _u16(0) + _u16(flags) + _u16(names[name])
            + _u16(signature) + _u16(1)
        )
    for rid, name, signature in (
        (1, "ReadAllBytes", signature_read),
        (2, "PostAsync", signature_post),
        (3, "Start", signature_start),
        (4, "FromBase64String", signature_decode),
    ):
        tables += _u16((rid << 3) | 1) + _u16(names[name]) + _u16(signature)
    if include_pinvoke:
        tables += _u16(names["kernel32.dll"])
        tables += (
            _u16(0)
            + _u16((3 << 1) | 1)
            + _u16(names["OpenProcess"])
            + _u16(1)
        )
    tables += (
        _u16(4) + _u16(0) * 3 + _u32(0) + _u16(0)
        + _u16(names["mscorlib"]) + _u16(0) + _u16(0)
    )

    streams = (
        ("#~", bytes(tables)),
        ("#Strings", bytes(strings.data)),
        ("#US", bytes(user_strings.data)),
        ("#Blob", bytes(blobs.data)),
    )
    version = b"v4.0.30319\x00"
    metadata = bytearray(b"BSJB" + _u16(1) + _u16(1) + _u32(0) + _u32(len(version)) + version)
    while len(metadata) % 4:
        metadata += b"\x00"
    metadata += _u16(0) + _u16(len(streams))
    header_start = len(metadata)
    header_sizes = tuple(8 + _align(len(name) + 1, 4) for name, _ in streams)
    data_start = _align(header_start + sum(header_sizes), 4)
    cursor = data_start
    headers = bytearray()
    stream_data: list[tuple[int, bytes]] = []
    for (name, data), _header_size in zip(streams, header_sizes, strict=True):
        headers += _u32(cursor) + _u32(len(data)) + name.encode("ascii") + b"\x00"
        while len(headers) % 4:
            headers += b"\x00"
        stream_data.append((cursor, data))
        cursor = _align(cursor + len(data), 4)
    metadata += headers
    while len(metadata) < data_start:
        metadata += b"\x00"
    for offset, data in stream_data:
        while len(metadata) < offset:
            metadata += b"\x00"
        metadata += data
        while len(metadata) % 4:
            metadata += b"\x00"

    main = bytearray()
    if not documentation_only:
        main += b"\x72" + _u32(0x70000000 | literals["C:/Users/Test/Login Data"])
        main += b"\x28" + _u32(_token(10, 1)) + b"\x0A"
        main += b"\x14"
        main += b"\x72" + _u32(0x70000000 | literals["https://example.invalid/upload"])
        main += b"\x06"
        main += b"\x6F" + _u32(_token(10, 2)) + b"\x26"
        main += b"\x72" + _u32(0x70000000 | literals["calc.exe"])
        main += b"\x28" + _u32(_token(10, 3)) + b"\x26"
        if include_pinvoke:
            main += b"\x16\x16\x16\x28" + _u32(_token(6, 3)) + b"\x26"
    main += b"\x2A"
    if len(main) >= 64:
        raise AssertionError("fixture_main_tiny_header_exceeded")
    main_body = bytes(((len(main) << 2) | 2,)) + main

    if documentation_only:
        dead = bytearray(b"\x2A")
    else:
        dead = bytearray(b"\x2B\x0B")
        dead += b"\x72" + _u32(0x70000000 | literals["calc.exe"])
        dead += b"\x28" + _u32(_token(10, 3)) + b"\x26\x2A"
        if len(dead) != 14:
            raise AssertionError("fixture_dead_layout_invalid")
    dead_body = bytes(((len(dead) << 2) | 2,)) + dead

    pe_offset = 0x80
    optional_size = 0xE0
    headers_size = 0x200
    raw_size = 0x1200
    image = bytearray(headers_size + raw_size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    coff = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, coff, 0x14C, 1, 0, 0, 0, optional_size, 0x2102)
    optional = coff + 20
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 16, 0x2400)
    struct.pack_into("<I", image, optional + 20, 0x2000)
    struct.pack_into("<I", image, optional + 24, 0x2000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<I", image, optional + 32, 0x2000)
    struct.pack_into("<I", image, optional + 36, 0x200)
    struct.pack_into("<I", image, optional + 56, 0x4000)
    struct.pack_into("<I", image, optional + 60, headers_size)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<I", image, optional + 72, 0x100000)
    struct.pack_into("<I", image, optional + 76, 0x1000)
    struct.pack_into("<I", image, optional + 80, 0x100000)
    struct.pack_into("<I", image, optional + 84, 0x1000)
    struct.pack_into("<I", image, optional + 92, 16)
    directory = optional + 96
    struct.pack_into("<II", image, directory + 14 * 8, 0x2000, 72)
    section = optional + optional_size
    image[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        section + 8,
        raw_size,
        0x2000,
        raw_size,
        headers_size,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    cli = headers_size
    struct.pack_into(
        "<IHHIIII",
        image,
        cli,
        72,
        2,
        5,
        0x2100,
        len(metadata),
        1,
        _token(6, 1),
    )
    image[0x300:0x300 + len(metadata)] = metadata
    image[0x600:0x600 + len(main_body)] = main_body
    image[0x660:0x660 + len(dead_body)] = dead_body
    return bytes(image) + _identity_overlay(identity_marker)


def build_native_pe_control(*, identity_marker: str = "") -> bytes:
    """Return a PE-shaped control with no CLI directory."""
    image = bytearray(build_managed_dotnet_fixture(include_pinvoke=False))
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    optional = pe_offset + 4 + 20
    directory = optional + 96
    struct.pack_into("<II", image, directory + 14 * 8, 0, 0)
    return bytes(image) + _identity_overlay(identity_marker)


_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
_TEXT_OFFSET = 0x100
_TEXT_VIRTUAL_ADDRESS = 0x401000
_NAMES_OFFSET = 0x180
_SECTION_HEADERS_OFFSET = 0x200
_NAMES = b"\x00.text\x00.shstrtab\x00"


def build_elf64_x86_64(
    text: bytes,
    *,
    entry_offset: int = 0,
    identity_marker: str = "",
) -> bytes:
    if type(text) is not bytes or not text:
        raise ValueError("native_fixture_text_invalid")
    if type(entry_offset) is not int or entry_offset < 0 or entry_offset >= len(text):
        raise ValueError("native_fixture_entry_invalid")
    total = _SECTION_HEADERS_OFFSET + 3 * _SECTION_HEADER.size
    raw = bytearray(total)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\x00" * 7
    raw[:_ELF_HEADER.size] = _ELF_HEADER.pack(
        ident,
        2,
        62,
        1,
        _TEXT_VIRTUAL_ADDRESS + entry_offset,
        _ELF_HEADER.size,
        _SECTION_HEADERS_OFFSET,
        0,
        _ELF_HEADER.size,
        _PROGRAM_HEADER.size,
        1,
        _SECTION_HEADER.size,
        3,
        2,
    )
    raw[_ELF_HEADER.size:_ELF_HEADER.size + _PROGRAM_HEADER.size] = _PROGRAM_HEADER.pack(
        1,
        5,
        _TEXT_OFFSET,
        _TEXT_VIRTUAL_ADDRESS,
        _TEXT_VIRTUAL_ADDRESS,
        len(text),
        len(text),
        0x1000,
    )
    raw[_TEXT_OFFSET:_TEXT_OFFSET + len(text)] = text
    raw[_NAMES_OFFSET:_NAMES_OFFSET + len(_NAMES)] = _NAMES
    section_one = _SECTION_HEADERS_OFFSET + _SECTION_HEADER.size
    raw[section_one:section_one + _SECTION_HEADER.size] = _SECTION_HEADER.pack(
        1,
        1,
        0x6,
        _TEXT_VIRTUAL_ADDRESS,
        _TEXT_OFFSET,
        len(text),
        0,
        0,
        16,
        0,
    )
    section_two = section_one + _SECTION_HEADER.size
    raw[section_two:section_two + _SECTION_HEADER.size] = _SECTION_HEADER.pack(
        7,
        3,
        0,
        0,
        _NAMES_OFFSET,
        len(_NAMES),
        0,
        0,
        1,
        0,
    )
    return bytes(raw) + _identity_overlay(identity_marker)


def build_control_flow_fixture(*, identity_marker: str = "") -> bytes:
    # Existing native frontend fixture: direct/indirect calls, branches, syscall, return.
    return build_elf64_x86_64(
        b"\xe8\x0b\x00\x00\x00"
        b"\x75\x05"
        b"\xeb\x05"
        b"\x90\x90\x90"
        b"\xff\xd0"
        b"\x0f\x05"
        b"\xc3",
        identity_marker=identity_marker,
    )


def build_mid_instruction_target_fixture(*, identity_marker: str = "") -> bytes:
    return build_elf64_x86_64(
        b"\xe9\xfc\xff\xff\xff\xc3",
        identity_marker=identity_marker,
    )


def _build_inert_native_control_flow_fixture(*, identity_marker: str) -> bytes:
    # Corpus-only control-flow carrier intentionally contains no syscall and no useful payload.
    return build_elf64_x86_64(
        b"\xe8\x0b\x00\x00\x00"  # direct call
        b"\x75\x05"              # conditional branch
        b"\xeb\x05"              # direct jump
        b"\x90\x90\x90"          # unreachable padding
        b"\xff\xd0"              # unresolved indirect call
        b"\x90\x90"              # inert padding preserving direct target offset
        b"\xc3",                   # direct-call target return
        identity_marker=identity_marker,
    )


_SEMANTIC_ELF_VARIANTS = frozenset({
    "import_flow_positive",
    "symbols_no_calls",
    "calls_unreachable",
    "wrong_sink",
    "wrong_target_identity",
    "no_value_flow",
    "data_only",
    "unresolved_indirect",
    "adjacent_import",
    "syscall_flow_positive",
    "adjacent_syscall",
})

_SEMANTIC_ELF_BASE = 0x400000
_SEMANTIC_ELF_SECTION_LAYOUT = (
    (".text", 0x200),
    (".rodata", 0x300),
    (".dynstr", 0x380),
    (".dynsym", 0x400),
    (".rela.plt", 0x500),
    (".plt", 0x600),
    (".got.plt", 0x700),
    (".dynamic", 0x780),
    (".shstrtab", 0x880),
)
_SEMANTIC_ELF_SECTION_HEADERS_OFFSET = 0xA00
_ELF64_SYMBOL = struct.Struct("<IBBHQQ")
_ELF64_RELA = struct.Struct("<QQq")
_ELF64_DYNAMIC = struct.Struct("<qQ")


def _elf_rel32(call_site_address: int, target_address: int) -> bytes:
    displacement = target_address - (call_site_address + 5)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise ValueError("native_semantic_fixture_call_target_invalid")
    return b"\xe8" + struct.pack("<i", displacement)


def _semantic_elf_text(variant: str, *, text_address: int, plt_address: int) -> tuple[bytes, tuple[str, ...], bytes]:
    """Return inert code bytes, dynamic imports, and physical rodata for one challenge variant."""
    if variant in {"import_flow_positive", "wrong_target_identity", "calls_unreachable", "no_value_flow"}:
        imports = ("read", "send")
    elif variant == "wrong_sink":
        imports = ("read", "write")
    elif variant == "adjacent_import":
        imports = ("read", "recv")
    elif variant == "symbols_no_calls":
        imports = ("read", "send")
    else:
        imports = ()

    rodata = b"phase5-native-buffer\x00"
    if variant == "wrong_target_identity":
        rodata += b"resource:channel:secondary\x00"
    elif variant != "data_only":
        rodata += b"resource:channel:primary\x00"
    if variant == "data_only":
        rodata += b"read\x00send\x00documentation-only\x00"

    def call(symbol_index: int, code_offset: int) -> bytes:
        return _elf_rel32(text_address + code_offset, plt_address + symbol_index * 16)

    if variant in {"import_flow_positive", "wrong_target_identity"}:
        # Set read(fd=0, ...) explicitly so both source and sink resource
        # identities are independently recoverable from executable state.
        first_offset = 5
        first = call(0, first_offset)
        second_offset = first_offset + len(first) + 2 + 5
        # The wrong-target control changes the executable send target itself.
        target_fd = 2 if variant == "wrong_target_identity" else 1
        code = (
            b"\xbf\x00\x00\x00\x00" + first + b"\x89\xc2"
            + b"\xbf" + struct.pack("<I", target_fd) + call(1, second_offset) + b"\xc3"
        )
    elif variant == "symbols_no_calls":
        code = b"\x90\xc3"
    elif variant == "calls_unreachable":
        first_offset = 1
        first = call(0, first_offset)
        second_offset = first_offset + len(first) + 2
        code = b"\xc3" + first + b"\x89\xc2" + call(1, second_offset) + b"\xc3"
    elif variant == "wrong_sink":
        first = call(0, 0)
        second_offset = len(first) + 2
        code = first + b"\x89\xc2" + call(1, second_offset) + b"\xc3"
    elif variant == "no_value_flow":
        first_offset = 5
        first = call(0, first_offset)
        second_offset = first_offset + len(first) + 2 + 5
        code = (
            b"\xbf\x00\x00\x00\x00" + first + b"\x31\xd2"
            + b"\xbf\x01\x00\x00\x00" + call(1, second_offset) + b"\xc3"
        )
    elif variant == "data_only":
        code = b"\xc3"
    elif variant == "unresolved_indirect":
        code = b"\xff\xd0\xc3"
    elif variant == "adjacent_import":
        first = call(0, 0)
        second_offset = len(first) + 2
        code = first + b"\x89\xc2" + call(1, second_offset) + b"\xc3"
    elif variant == "syscall_flow_positive":
        code = (
            b"\xbf\x00\x00\x00\x00" + b"\xb8\x00\x00\x00\x00" + b"\x0f\x05"
            + b"\x89\xc2" + b"\xbf\x01\x00\x00\x00" + b"\xb8\x2c\x00\x00\x00"
            + b"\x0f\x05\xc3"
        )
    elif variant == "adjacent_syscall":
        code = (
            b"\xbf\x00\x00\x00\x00" + b"\xb8\x00\x00\x00\x00" + b"\x0f\x05"
            + b"\x89\xc2" + b"\xbf\x01\x00\x00\x00" + b"\xb8\x01\x00\x00\x00"
            + b"\x0f\x05\xc3"
        )
    else:
        raise ValueError("native_semantic_fixture_variant_invalid")
    return code, imports, rodata


def build_semantic_elf64_x86_64_fixture(
    variant: str,
    *,
    identity_marker: str = "",
) -> bytes:
    """Build a deterministic, inert ELF64 semantic challenge without host compiler/linker input."""
    if type(variant) is not str or variant not in _SEMANTIC_ELF_VARIANTS:
        raise ValueError("native_semantic_fixture_variant_invalid")
    if type(identity_marker) is not str:
        raise TypeError("static_semantic_binary_identity_marker_invalid")

    offsets = dict(_SEMANTIC_ELF_SECTION_LAYOUT)
    addresses = {name: _SEMANTIC_ELF_BASE + offset for name, offset in _SEMANTIC_ELF_SECTION_LAYOUT}
    text_bytes, imports, rodata = _semantic_elf_text(
        variant,
        text_address=addresses[".text"],
        plt_address=addresses[".plt"],
    )

    dynstr = bytearray(b"\x00")
    dynstr_offsets: dict[str, int] = {}
    for symbol in imports:
        dynstr_offsets[symbol] = len(dynstr)
        dynstr += symbol.encode("ascii", "strict") + b"\x00"

    dynsym = bytearray(_ELF64_SYMBOL.size)
    for symbol in imports:
        dynsym += _ELF64_SYMBOL.pack(dynstr_offsets[symbol], 0x12, 0, 0, 0, 0)

    got = bytearray(max(8, 8 * len(imports)))
    plt = bytearray()
    rela = bytearray()
    for index, _symbol in enumerate(imports):
        plt_entry_address = addresses[".plt"] + index * 16
        got_address = addresses[".got.plt"] + index * 8
        rip_displacement = got_address - (plt_entry_address + 6)
        plt += b"\xff\x25" + struct.pack("<i", rip_displacement) + b"\x90" * 10
        rela += _ELF64_RELA.pack(got_address, ((index + 1) << 32) | 7, 0)

    dynamic_entries = (
        (5, addresses[".dynstr"]),   # DT_STRTAB
        (6, addresses[".dynsym"]),   # DT_SYMTAB
        (11, _ELF64_SYMBOL.size),     # DT_SYMENT
        (23, addresses[".rela.plt"]),# DT_JMPREL
        (2, len(rela)),               # DT_PLTRELSZ
        (20, 7),                      # DT_PLTREL = DT_RELA
        (0, 0),                       # DT_NULL
    )
    dynamic = b"".join(_ELF64_DYNAMIC.pack(tag, value) for tag, value in dynamic_entries)

    names = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name, _offset in _SEMANTIC_ELF_SECTION_LAYOUT:
        name_offsets[name] = len(names)
        names += name.encode("ascii", "strict") + b"\x00"

    section_payloads = {
        ".text": text_bytes,
        ".rodata": rodata,
        ".dynstr": bytes(dynstr),
        ".dynsym": bytes(dynsym),
        ".rela.plt": bytes(rela),
        ".plt": bytes(plt),
        ".got.plt": bytes(got),
        ".dynamic": dynamic,
        ".shstrtab": bytes(names),
    }
    section_specs = {
        ".text": (1, 0x6, 0, 0, 16, 0),
        ".rodata": (1, 0x2, 0, 0, 8, 0),
        ".dynstr": (3, 0x2, 0, 0, 1, 0),
        ".dynsym": (11, 0x2, 3, 1, 8, _ELF64_SYMBOL.size),
        ".rela.plt": (4, 0x2, 4, 6, 8, _ELF64_RELA.size),
        ".plt": (1, 0x6, 0, 0, 16, 16),
        ".got.plt": (1, 0x3, 0, 0, 8, 8),
        ".dynamic": (6, 0x3, 3, 0, 8, _ELF64_DYNAMIC.size),
        ".shstrtab": (3, 0x0, 0, 0, 1, 0),
    }

    section_count = 1 + len(_SEMANTIC_ELF_SECTION_LAYOUT)
    total = _SEMANTIC_ELF_SECTION_HEADERS_OFFSET + section_count * _SECTION_HEADER.size
    raw = bytearray(total)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\x00" * 7
    raw[:_ELF_HEADER.size] = _ELF_HEADER.pack(
        ident,
        2,
        62,
        1,
        addresses[".text"],
        _ELF_HEADER.size,
        _SEMANTIC_ELF_SECTION_HEADERS_OFFSET,
        0,
        _ELF_HEADER.size,
        _PROGRAM_HEADER.size,
        1,
        _SECTION_HEADER.size,
        section_count,
        section_count - 1,
    )
    raw[_ELF_HEADER.size:_ELF_HEADER.size + _PROGRAM_HEADER.size] = _PROGRAM_HEADER.pack(
        1,
        5,
        0,
        _SEMANTIC_ELF_BASE,
        _SEMANTIC_ELF_BASE,
        _SEMANTIC_ELF_SECTION_HEADERS_OFFSET,
        _SEMANTIC_ELF_SECTION_HEADERS_OFFSET,
        0x1000,
    )

    for name, offset in _SEMANTIC_ELF_SECTION_LAYOUT:
        payload = section_payloads[name]
        next_offsets = [candidate for _other, candidate in _SEMANTIC_ELF_SECTION_LAYOUT if candidate > offset]
        limit = min(next_offsets) if next_offsets else _SEMANTIC_ELF_SECTION_HEADERS_OFFSET
        if offset + len(payload) > limit:
            raise ValueError("native_semantic_fixture_section_overflow")
        raw[offset:offset + len(payload)] = payload

    for section_index, (name, offset) in enumerate(_SEMANTIC_ELF_SECTION_LAYOUT, start=1):
        section_type, flags, link, info, alignment, entry_size = section_specs[name]
        header_offset = _SEMANTIC_ELF_SECTION_HEADERS_OFFSET + section_index * _SECTION_HEADER.size
        payload = section_payloads[name]
        raw[header_offset:header_offset + _SECTION_HEADER.size] = _SECTION_HEADER.pack(
            name_offsets[name],
            section_type,
            flags,
            addresses[name] if flags & 0x2 else 0,
            offset,
            len(payload),
            link,
            info,
            alignment,
            entry_size,
        )
    return bytes(raw) + _identity_overlay(identity_marker)


_STATIC_SEMANTIC_BINARY_VARIANTS = frozenset({
    ("managed_pe", "managed_behavior"),
    ("managed_pe", "managed_documentation_only"),
    ("native_elf_x86_64", "native_control_flow"),
    ("native_elf_x86_64", "native_return_control"),
}) | frozenset(("native_elf_x86_64", variant) for variant in _SEMANTIC_ELF_VARIANTS)


def render_static_semantic_binary_fixture(
    renderer_kind: str,
    fixture_variant: str,
    sample_id: str,
) -> bytes:
    if type(renderer_kind) is not str or type(fixture_variant) is not str or type(sample_id) is not str:
        raise TypeError("static_semantic_binary_fixture_identity_invalid")
    if (renderer_kind, fixture_variant) not in _STATIC_SEMANTIC_BINARY_VARIANTS:
        raise ValueError("static_semantic_binary_fixture_variant_invalid")
    marker = "UMIGE_STATIC_SEMANTIC:" + sample_id
    if renderer_kind == "managed_pe":
        return build_managed_dotnet_fixture(
            include_pinvoke=fixture_variant == "managed_behavior",
            documentation_only=fixture_variant == "managed_documentation_only",
            identity_marker=marker,
        )
    if fixture_variant in _SEMANTIC_ELF_VARIANTS:
        return build_semantic_elf64_x86_64_fixture(
            fixture_variant, identity_marker=marker,
        )
    if fixture_variant == "native_control_flow":
        return _build_inert_native_control_flow_fixture(identity_marker=marker)
    return build_elf64_x86_64(b"\xc3", identity_marker=marker)


def is_exact_static_semantic_binary_fixture(
    renderer_kind: str,
    fixture_variant: str,
    sample_id: str,
    data: bytes,
) -> bool:
    if type(data) is not bytes:
        raise TypeError("static_semantic_binary_fixture_bytes_invalid")
    try:
        expected = render_static_semantic_binary_fixture(renderer_kind, fixture_variant, sample_id)
    except (TypeError, ValueError, UnicodeError):
        return False
    return data == expected


__all__ = (
    "build_control_flow_fixture",
    "build_elf64_x86_64",
    "build_managed_dotnet_fixture",
    "build_mid_instruction_target_fixture",
    "build_native_pe_control",
    "build_semantic_elf64_x86_64_fixture",
    "is_exact_static_semantic_binary_fixture",
    "render_static_semantic_binary_fixture",
)
