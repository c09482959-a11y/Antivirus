"""Bounded text/header collector groups for raw-stage dispatch."""
from __future__ import annotations

RAW_TEXT_COLLECTORS = frozenset({"binary_context", "decode", "payload", "js_exec"})
RAW_HEADER_COLLECTORS = frozenset(
    {
        "pe_api",
        "pure_pe",
        "dotnet",
        "unity_dotnet",
        "il2cpp",
        "bytecode",
        "renpy",
        "rpgm_js_ast",
    }
)
RAW_BLOB_LIMIT = 65536


def _store_header_fields(
    out: dict[str, object],
    tmp: object,
    *,
    include_meta: bool,
) -> dict[str, object]:
    out["tags"] = tmp.get("tags", [])
    if include_meta:
        out["meta"] = tmp.get("meta", {})
    return out


def dispatch_raw_text_collector(
    *,
    path: object,
    collector: str,
    start: int,
    size: int,
    out: dict[str, object],
    deps: object,
) -> dict[str, object]:
    text = deps.read_range_text(path, start=start, size=size)
    out["strings_blob"] = text[:RAW_BLOB_LIMIT]
    if collector == "binary_context":
        out["tags"] = (
            deps.contextual_chunk_raw(text, path=path, source="binary", offset=start)
            if deps.should_context_scan(text)
            else []
        )
    elif collector == "decode":
        out["tags"] = deps.decoded_chunk_tags(text, path=path, offset=start) if deps.should_decode_scan(text) else []
    elif collector == "payload":
        out["tags"] = deps.explicit_missed_family_tag_scan(text, path=path)
    elif collector == "js_exec":
        out["tags"] = deps.js_execution_model_tags(text, path=path, finalize=False)
    return out


def dispatch_raw_header_collector(
    *,
    path: object,
    collector: str,
    out: dict[str, object],
    deps: object,
) -> dict[str, object]:
    if collector == "pe_api":
        return _store_header_fields(out, deps.pe_api_header(path), include_meta=True)
    elif collector == "pure_pe":
        tmp = deps.pure_pe_header(path)
        _store_header_fields(out, tmp, include_meta=True)
        out["suspicious"] = bool(out.get("suspicious")) or bool(tmp.get("suspicious"))
    elif collector == "dotnet":
        return _store_header_fields(
            out,
            deps.dotnet_header(path, scan_dotnet_file=deps.scan_dotnet_file),
            include_meta=True,
        )
    elif collector == "unity_dotnet":
        return _store_header_fields(
            out,
            deps.unity_dotnet_header(path, scan_unity_dotnet_layered_file=deps.scan_unity_dotnet_layered_file),
            include_meta=True,
        )
    elif collector == "il2cpp":
        return _store_header_fields(
            out,
            deps.il2cpp_header(path, read_file_bytes=deps.read_file_bytes),
            include_meta=False,
        )
    elif collector == "bytecode":
        return _store_header_fields(out, deps.bytecode_header(path), include_meta=False)
    elif collector == "renpy":
        return _store_header_fields(out, deps.renpy_header(path), include_meta=False)
    elif collector == "rpgm_js_ast":
        return _store_header_fields(out, deps.rpgm_js_ast_header(path), include_meta=False)
    return out
