"""Canonical file identity sniffing for analyzer routing and JSON evidence."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.routing.path_boundaries import routing_path
from Virus_Scan.routing.file_identity_policy import (
    ACCEPTED_EQUIVALENT_SNIFFED_TYPES,
    MEDIA_EXTENSION_TYPES,
    MEDIA_TYPES,
    RENPY_RUNTIME_NAMES,
    RPGM_DLL_NAMES,
    TYPE_BY_EXTENSION,
    UNITY_DLL_NAMES,
)
from Virus_Scan.routing.file_identity_sniffing import find_embedded, read_head, sniff_primary


@dataclass(frozen=True)
class FileIdentity:
    declared_extension: str
    sniffed_type: str
    sniffed_embedded_types: tuple[str, ...]
    extension_mismatch: bool
    evidence: tuple[str, ...]


def sniff_file_identity(path: object) -> FileIdentity:
    p, path_reason = routing_path(path, missing_reason="file_path_missing", unsupported_reason="unsafe_file_path_rejected")
    if path_reason or p is None:
        return FileIdentity("<no_ext>", "unknown", (), False, (path_reason or "file_path_unavailable",))
    declared = p.suffix.lower()
    data = read_head(p)
    sniffed, sniff_evidence = sniff_primary(data, p, declared)
    evidence = list(sniff_evidence)
    embedded = find_embedded(data, sniffed)
    expected = TYPE_BY_EXTENSION.get(declared, "unknown")
    equivalent_sniffed_types = ACCEPTED_EQUIVALENT_SNIFFED_TYPES.get(expected, frozenset())
    mismatch = bool(
        expected != "unknown"
        and sniffed not in {"unknown", expected}
        and sniffed not in equivalent_sniffed_types
    )
    if mismatch:
        evidence.extend((
            "extension_mismatch",
            str.__add__("declared_extension:", declared or "<no_ext>"),
            str.__add__("expected_type:", expected),
            str.__add__("sniffed_type:", sniffed),
        ))
    if embedded:
        evidence.extend(str.__add__("embedded:", item) for item in embedded)
    return FileIdentity(declared or "<no_ext>", sniffed, embedded, mismatch, tuple(evidence[:48]))


def artifact_engine_from_identity(path: object, identity: FileIdentity) -> tuple[str, float, tuple[str, ...]]:
    suffix = identity.declared_extension
    sniffed = identity.sniffed_type
    p, path_reason = routing_path(path, missing_reason="file_path_missing", unsupported_reason="unsafe_file_path_rejected")
    name = "" if path_reason or p is None else p.name.lower()
    evidence: list[str] = [str.__add__("sniffed_type:", sniffed)]
    if sniffed in {"renpy_source", "renpy_bytecode", "rpa"} or suffix in {".rpy", ".rpyc", ".rpyb", ".rpymc", ".rpa"} or name in RENPY_RUNTIME_NAMES:
        return "renpy", 0.99 if sniffed != "unknown" else 0.8, tuple(evidence)
    if sniffed in {"rpgm_encrypted_asset", "rgss_archive"} or suffix in {".rpgmvp", ".rpgmvo", ".rpgmvm", ".rxdata", ".rvdata", ".rvdata2"} or name in RPGM_DLL_NAMES:
        return "rpgm", 0.99 if sniffed != "unknown" else 0.8, tuple(evidence)
    if sniffed in {"unity_asset_bundle", "unity_serialized_asset", "il2cpp_metadata", "mono_dotnet_assembly"} or name in UNITY_DLL_NAMES or "structure:unity_dotnet_or_runtime" in identity.evidence:
        return "unity", 0.99, tuple(evidence)
    if sniffed in MEDIA_EXTENSION_TYPES or suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ogg", ".mp3", ".wav"}:
        return "media", 0.97 if sniffed in MEDIA_EXTENSION_TYPES else 0.75, tuple(evidence)
    if sniffed in {"pe", "elf", "macho", "zip", "jar", "apk", "docx_zip", "wasm", "asar", "javascript", "python_source", "json", "data"}:
        return "other", 0.72, tuple(evidence)
    return "other", 0.4, tuple(evidence)


__all__ = (
    "ACCEPTED_EQUIVALENT_SNIFFED_TYPES",
    "MEDIA_EXTENSION_TYPES",
    "MEDIA_TYPES",
    "RENPY_RUNTIME_NAMES",
    "RPGM_DLL_NAMES",
    "TYPE_BY_EXTENSION",
    "UNITY_DLL_NAMES",
    "FileIdentity",
    "artifact_engine_from_identity",
    "sniff_file_identity",
)
