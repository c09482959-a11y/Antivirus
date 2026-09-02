"""Scanner-owned pure Python PE surface scanning."""
from __future__ import annotations

import re
from types import MappingProxyType

from Virus_Scan.scanners.binary_path_identity import get_binary_scan_extension
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.binary_io import read_binary_file_bytes, binary_string_evidence_tags
from Virus_Scan.scanners.binary_exception_policy import is_binary_programmer_error
from Virus_Scan.scanners.binary_pe_evidence import mark_pe_helper_error
from Virus_Scan.scanners.binary_pe_sections import parse_pe_import_names, parse_pe_sections
from Virus_Scan.scanners.binary_pe_bytes import pe_u16, pe_u32
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_exact_nonnegative_int,
    no_hook_text,
)

PLR2004N332 = 332
PLR2004N34404 = 34404

PE_API_TAGS = MappingProxyType({
    "createprocess": ("process_exec", "process_creation"),
    "shellexecute": ("process_exec", "process_creation"),
    "winexec": ("process_exec", "process_creation"),
    "virtualalloc": ("memory_allocation",),
    "virtualprotect": ("memory_protect", "memory_protection"),
    "writeprocessmemory": ("memory_write",),
    "createremotethread": ("thread_execution",),
    "ntcreatethreadex": ("thread_execution",),
    "openprocess": ("process_access",),
    "regsetvalue": ("registry_mod", "registry_write"),
    "regcreatekey": ("registry_mod", "registry_write"),
    "internetopen": ("network_activity",),
    "internetconnect": ("network_activity",),
    "httpsendrequest": ("network_activity", "http_upload"),
    "urldownloadtofile": ("network_download", "download"),
    "isdebuggerpresent": ("anti_debug",),
    "checkremotedebuggerpresent": ("anti_debug",),
    "cryptdecrypt": ("crypto_api",),
    "cryptencrypt": ("crypto_api",),
})


def scan_pure_python_pe_file(path: object, *, finalize: bool = True, include_strings: bool = True) -> object:
    """Pure-stdlib PE surface scanner; no pefile/lief dependency or execution."""
    tags: list[str] = []
    meta = {"is_pe": False, "sections": 0, "imports": 0}
    try:
        data = read_binary_file_bytes(path, max_size=8000000)
        valid_pe, malformed_header_tags = _pe_header_status(data)
        if malformed_header_tags:
            tags.extend(malformed_header_tags)
            meta["pe_header_degraded"] = True
        if not valid_pe:
            if finalize:
                return (normalize_tags(tags), meta)
            return (list(tags or []), meta)
        _add_header_tags(tags, meta, data, path)
        sections = _add_section_evidence(tags, meta, data)
        imports = _add_import_evidence(tags, meta, data, sections)
        _add_import_api_tags(tags, imports)
        _add_runtime_reference_tags(tags, data)
        if include_strings:
            _add_string_tags(tags, data, path)
    except SCAN_CONTENT_ERRORS as exc:
        if is_binary_programmer_error(exc):
            raise
        tags.extend(mark_pe_helper_error("scan_pure_python_pe_file", exc))
        tags.append("pure_pe_scan_error")
    if finalize:
        return (normalize_tags(tags), meta)
    return (list(tags or []), meta)


def _pe_header_status(data: bytes) -> tuple[bool, tuple[str, ...]]:
    """Return PE header validity and explicit malformed-header evidence."""
    if not data.startswith(b"MZ"):
        return False, ()
    if len(data) < 64:
        return False, tuple(mark_pe_helper_error("pe_header_parse", ValueError("truncated MZ/PE header")))
    pe_off = pe_u32(data, 60)
    if pe_off <= 0 or pe_off + 4 > len(data):
        return False, tuple(mark_pe_helper_error("pe_header_parse", ValueError("truncated PE signature offset")))
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return False, tuple(mark_pe_helper_error("pe_header_parse", ValueError("missing PE signature at header offset")))
    if pe_off + 24 > len(data):
        return False, tuple(mark_pe_helper_error("pe_header_parse", ValueError("truncated PE COFF header")))
    return True, ()


def _add_header_tags(tags: list[str], meta: dict, data: bytes, path: object) -> None:
    meta["is_pe"] = True
    tags.append("pe_file")
    ext = get_binary_scan_extension(path)
    if ext == ".exe":
        tags += ["pe_exe", "executable_file"]
    if ext == ".dll":
        tags += ["pe_dll", "dll_file"]
    machine = pe_u16(data, pe_u32(data, 60) + 4)
    if machine == PLR2004N34404:
        tags.append("pe_x64")
    elif machine == PLR2004N332:
        tags.append("pe_x86")
    if pe_u16(data, pe_u32(data, 60) + 22) & 8192:
        tags.append("pe_dll_characteristic")


def _add_section_evidence(tags: list[str], meta: dict, data: bytes) -> list[dict]:
    result = parse_pe_sections(data)
    sections: list[dict] = []
    for section in result.sections:
        materialized, reason = _owned_pe_section_mapping(section)
        if materialized is None:
            tags.extend(_pe_section_materialization_error_tags(reason))
            meta["section_parse_degraded"] = True
            continue
        sections.append(materialized)
    if result.error_tags:
        tags.extend(result.error_tags)
        meta["section_parse_degraded"] = True
    else:
        section_status, helper_error_tags = _declared_section_record_status(data, sections)
        if helper_error_tags:
            tags.extend(helper_error_tags)
            meta["section_parse_degraded"] = True
        elif section_status == "missing_records":
            tags.extend(mark_pe_helper_error("pe_section_parse", ValueError("PE declared sections but parser returned none")))
            meta["section_parse_degraded"] = True
    meta["sections"] = len(sections)
    for section in sections:
        _add_single_section_tags(tags, section)
    return sections


def _declared_section_record_status(data: bytes, sections: list[dict]) -> tuple[str, tuple[str, ...]]:
    """Return explicit declared-section status plus scanner-owned error evidence."""
    try:
        expected_sections = pe_u16(data, pe_u32(data, 60) + 6)
        if expected_sections and not sections:
            return "missing_records", ()
        return "records_present_or_not_declared", ()
    except SCAN_CONTENT_ERRORS as exc:
        if is_binary_programmer_error(exc):
            raise
        return "helper_error", tuple(mark_pe_helper_error("pe_section_parse", exc))


def _pe_section_materialization_error_tags(reason: str) -> tuple[str, ...]:
    if type(reason) is not str or not reason:
        reason = "pe_section_materialization_rejected"
    return tuple(mark_pe_helper_error("pe_section_materialize", ValueError(str.__str__(reason))))


def _owned_pe_section_mapping(section: object) -> tuple[dict[str, object] | None, str]:
    items = no_hook_mapping_items(section)
    if items is None:
        return None, "pe_section_mapping_rejected"
    materialized: dict[str, object] = {}
    for key, value in items:
        if type(key) is not str:
            return None, "pe_section_key_rejected"
        materialized[str.__str__(key)] = value
    return materialized, ""


def _section_value(section: dict[str, object], key: str, default: object) -> object:
    value = dict.get(section, key, default)
    return default if value is None else value


def _add_single_section_tags(tags: list[str], section: dict) -> None:
    section_map, mapping_reason = _owned_pe_section_mapping(section)
    if section_map is None:
        tags.extend(_pe_section_materialization_error_tags(mapping_reason))
        return

    name_value = _section_value(section_map, "name", "")
    name, name_reason = no_hook_text(
        name_value,
        missing_reason="pe_section_name_missing",
        unsupported_reason="pe_section_name_rejected",
    )
    if name_reason:
        tags.extend(_pe_section_materialization_error_tags(name_reason))
        name = ""
    name = str.lower(name) if type(name) is str else ""

    entropy, entropy_reason = no_hook_finite_float(
        _section_value(section_map, "entropy", 0.0),
        default=0.0,
        minimum=0.0,
        reason="pe_section_entropy_rejected",
        allow_exact_text=False,
    )
    if entropy_reason:
        tags.extend(_pe_section_materialization_error_tags(entropy_reason))

    raw_size, raw_reason = no_hook_exact_nonnegative_int(
        _section_value(section_map, "raw_size", 0),
        default=0,
        reason="pe_section_raw_size_rejected",
        allow_exact_text=False,
    )
    if raw_reason:
        tags.extend(_pe_section_materialization_error_tags(raw_reason))
    virtual_size, virtual_reason = no_hook_exact_nonnegative_int(
        _section_value(section_map, "virtual_size", 0),
        default=0,
        reason="pe_section_virtual_size_rejected",
        allow_exact_text=False,
    )
    if virtual_reason:
        tags.extend(_pe_section_materialization_error_tags(virtual_reason))

    if name:
        normalized_name = re.sub("[^a-z0-9_.]+", "_", name).strip("_")
        if normalized_name:
            tags.append("pe_section_" + normalized_name)
    if entropy >= 7.2:
        tags += ["high_entropy_section", "packed_or_obfuscated"]
    if raw_size == 0 and virtual_size > 0:
        tags.append("virtual_only_section")


def _add_import_evidence(tags: list[str], meta: dict, data: bytes, sections: list[dict]) -> list[tuple[str, list[str]]]:
    result = parse_pe_import_names(data, sections)
    imports = [(dll, list(funcs)) for dll, funcs in result.imports]
    if result.error_tags:
        tags.extend(result.error_tags)
        meta["import_parse_degraded"] = True
    meta["imports"] = sum(len(functions) for _, functions in imports)
    return imports


def _add_import_api_tags(tags: list[str], imports: list[tuple[str, list[str]]]) -> None:
    imported_text = " ".join([dll + " " + " ".join(funcs) for dll, funcs in imports]).lower()
    for needle, mapped in no_hook_mapping_items(PE_API_TAGS) or ():
        if needle in imported_text:
            tags.extend(mapped)


def _add_runtime_reference_tags(tags: list[str], data: bytes) -> None:
    text = data.decode("latin1", errors="ignore").lower()
    if "node.dll" in text or "nw.dll" in text or "nw_elf.dll" in text or "nwjs" in text:
        tags += ["nwjs_runtime_reference", "rpgm_nwjs_runtime"]
    if "package.json" in text and ("www/js" in text or "rpg" in text):
        tags += ["rpgm_package_reference", "rpgm_game_exe"]


def _add_string_tags(tags: list[str], data: bytes, path: object) -> None:
    text = data.decode("latin1", errors="ignore").lower()
    tags.extend(binary_string_evidence_tags(text, path=path, finalize=False))


__all__ = ("scan_pure_python_pe_file",)
