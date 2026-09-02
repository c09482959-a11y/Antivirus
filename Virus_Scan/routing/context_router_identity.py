"""Router-identity conversion for contextual routing."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import exact_bool_or_none, no_hook_mapping_items, no_hook_sequence_items, no_hook_text
from Virus_Scan.routing.file_identity import FileIdentity
from Virus_Scan.routing.extension_outcome import route_identity_record

_ROUTER_MAGIC_TYPES = frozenset(
    {
        "png",
        "jpg",
        "gif",
        "webp",
        "bmp",
        "ogg",
        "mp3",
        "wav",
        "zip",
        "jar",
        "apk",
        "docx_zip",
        "elf",
        "macho",
        "rpa",
        "rgss_archive",
        "rpgm_encrypted_asset",
        "javascript",
        "json",
        "python_source",
        "wasm",
        "asar",
    }
)


def _router_mapping(router_identity: object) -> dict[object, object] | None:
    return route_identity_record(router_identity)


def _router_value(router_identity: dict[object, object], key: str, default: object = None) -> object:
    return dict.get(router_identity, key, default)


def _router_text(router_identity: dict[object, object], key: str, default: str = "") -> str:
    text, reason = no_hook_text(
        _router_value(router_identity, key),
        missing_reason=str.__add__(key, "_missing"),
        unsupported_reason=str.__add__(key, "_rejected"),
    )
    token = default if reason or text == "" else text.lower().strip()
    return token or default


def _safe_token(value: object) -> str:
    text, reason = no_hook_text(value, missing_reason="router_tag_missing", unsupported_reason="router_tag_rejected")
    if reason or text == "":
        return ""
    return text.strip().lower()


def _tag_tuple(value: object) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for item in no_hook_sequence_items(value):
        token = _safe_token(item)
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return tuple(out)


def _router_flag(router_identity: dict[object, object], key: str) -> bool:
    return exact_bool_or_none(_router_value(router_identity, key, False)) is True


def _join(parts: tuple[str, ...]) -> str:
    return "".join(parts)


def file_identity_from_router_identity(router_identity: object) -> FileIdentity | None:
    safe_identity = _router_mapping(router_identity)
    if safe_identity is None:
        return None
    declared = _router_text(safe_identity, "ext")
    tags = _tag_tuple(_router_value(safe_identity, "tags", ()))
    embedded = _embedded_payloads_from_tags(tags)
    mismatch = (
        "extension_mismatch" in tags
        or "extension_magic_type_mismatch" in tags
        or _router_flag(safe_identity, "extension_mismatch")
    )
    sniffed_type = _sniffed_type_from_router_identity(safe_identity)
    evidence = _router_identity_evidence(declared, sniffed_type, tags, safe_identity, mismatch)
    return FileIdentity(
        declared_extension=declared,
        sniffed_type=sniffed_type,
        sniffed_embedded_types=embedded,
        extension_mismatch=mismatch,
        evidence=evidence,
    )


def _embedded_payloads_from_tags(tags: tuple[str, ...]) -> tuple[str, ...]:
    embedded: list[str] = []
    if "embedded_pe_signature" in tags or "embedded_pe_payload" in tags:
        embedded.append("pe")
    if "embedded_zip_signature" in tags or "embedded_zip_payload" in tags:
        embedded.append("zip")
    return tuple(dict.fromkeys(embedded))


def _sniffed_type_from_router_identity(router_identity: dict[str, object]) -> str:
    magic_type = _router_text(router_identity, "magic_type")
    magic_stage = _router_text(router_identity, "magic_stage")
    if magic_type in {"pe_mz", "mono_dotnet_assembly"}:
        return "pe" if magic_type == "pe_mz" else "mono_dotnet_assembly"
    if magic_type == "jpeg":
        return "jpg"
    if magic_type in _ROUTER_MAGIC_TYPES:
        return magic_type
    ext = _router_text(router_identity, "ext")
    if ext.startswith("."):
        return ext[1:]
    if magic_stage in {"image", "asset"}:
        return ext[1:] if ext.startswith(".") else (ext or "unknown")
    return magic_type or "unknown"


def _router_identity_evidence(
    declared: str,
    sniffed_type: str,
    tags: tuple[str, ...],
    router_identity: dict[str, object],
    mismatch: bool,
) -> tuple[str, ...]:
    evidence = [_join(("extension:", declared or "none"))]
    magic = _router_text(router_identity, "magic_type")
    if magic and magic != "unknown":
        evidence.append(_join(("magic:", magic)))
    for tag in tags:
        if tag.startswith(("magic_", "filetype_")) or tag in {
            "image_file",
            "audio_file",
            "media_file",
            "pe_file",
            "archive_file",
        }:
            evidence.append(_join(("router:", tag)))
    if mismatch:
        evidence.extend(("extension_mismatch", _join(("declared_extension:", declared or "<no_ext>")), _join(("sniffed_type:", sniffed_type))))
    return tuple(dict.fromkeys(evidence))
