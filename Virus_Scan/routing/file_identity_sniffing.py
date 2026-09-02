"""Bounded sniffing helpers for canonical file identity routing."""
from __future__ import annotations
from typing import TYPE_CHECKING

from Virus_Scan.contracts.artifact_read_snapshot import read_artifact_prefix

from Virus_Scan.routing.file_identity_policy import (
    MEDIA_EXTENSION_TYPES,
    RENPY_RUNTIME_NAMES,
    RPGM_DLL_NAMES,
    TYPE_BY_EXTENSION,
    UNITY_DLL_NAMES,
)

PLR2004N12 = 12
PLR2004N3 = 3

if TYPE_CHECKING:
    from pathlib import Path

SniffResult = tuple[str, tuple[str, ...]]


def read_head(path: Path, limit: int = 1048576) -> bytes:
    try:
        return read_artifact_prefix(path, limit)
    except (OSError, ValueError):
        return b""


def _printable_text(data: bytes) -> str:
    return data[:65536].decode("latin1", errors="ignore")


def _zip_subtype(lower: str, lower_name: str) -> SniffResult:
    if "androidmanifest.xml" in lower or "classes.dex" in lower or lower_name.endswith(".apk"):
        return "apk", ("zip_subtype:apk",)
    if "meta-inf/manifest.mf" in lower or lower_name.endswith(".jar"):
        return "jar", ("zip_subtype:jar",)
    if "[content_types].xml" in lower or "word/document.xml" in lower or lower_name.endswith(".docx"):
        return "docx_zip", ("zip_subtype:docx",)
    return "zip", ("magic:zip",)


def _sniff_executable(data: bytes, lower_name: str, declared_extension: str) -> SniffResult | None:
    if data.startswith(b"MZ"):
        evidence = ["magic:pe_mz"]
        pe_head = data[:65536].lower()
        if lower_name in UNITY_DLL_NAMES or b"unityengine" in pe_head or b"assembly-csharp" in pe_head:
            evidence.append("structure:unity_dotnet_or_runtime")
            if declared_extension not in {".dll", ".exe"} or b"assembly-csharp" in pe_head or b"unityengine" in pe_head:
                return "mono_dotnet_assembly", tuple(evidence)
        if b"bsjb" in data[:262144].lower() or b"mscorlib" in pe_head or b".netframework" in pe_head:
            evidence.append("structure:mono_dotnet_metadata")
            return "mono_dotnet_assembly", tuple(evidence)
        if lower_name in RPGM_DLL_NAMES:
            evidence.append("structure:rpgm_runtime_dll")
        if lower_name in RENPY_RUNTIME_NAMES:
            evidence.append("structure:renpy_runtime_binary")
        return "pe", tuple(evidence)
    if data.startswith(b"\x7fELF"):
        return "elf", ("magic:elf",)
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")):
        return "macho", ("magic:macho",)
    return None


def _sniff_archive_or_engine(data: bytes, lower: str, lower_name: str, declared_extension: str) -> SniffResult | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return _zip_subtype(lower, lower_name)
    if data.startswith(b"RPA-") or declared_extension == ".rpa" or lower_name.endswith(".rpa"):
        return "rpa", ("magic_or_extension:rpa",)
    if declared_extension in {".rgssad", ".rgss2a", ".rgss3a"} or data.startswith((b"RGSSAD", b"RGSS")):
        return "rgss_archive", ("magic_or_extension:rgss_archive",)
    if declared_extension in {".rpgmvp", ".rpgmvo", ".rpgmvm"} or data.startswith((b"RPGMV", b"RPGMVO", b"RPGMVM")):
        return "rpgm_encrypted_asset", ("magic_or_extension:rpgm_encrypted_asset",)
    if len(data) > PLR2004N12:
        asar_len = int.from_bytes(data[:4], "little", signed=False)
        if 0 < asar_len < min(len(data), 1048576) and b"files" in data[8:8 + asar_len].lower():
            return "asar", ("structure:asar_header",)
    return None


def _sniff_media(data: bytes) -> SniffResult | None:
    media_markers: tuple[tuple[bool, SniffResult], ...] = (
        (data.startswith(b"\x89PNG\r\n\x1a\n"), ("png", ("magic:png",))),
        (data.startswith(b"\xff\xd8\xff"), ("jpg", ("magic:jpg",))),
        (data.startswith((b"GIF87a", b"GIF89a")), ("gif", ("magic:gif",))),
        (data.startswith(b"RIFF") and data[8:12] == b"WEBP", ("webp", ("magic:webp",))),
        (data.startswith(b"BM"), ("bmp", ("magic:bmp",))),
        (data.startswith(b"OggS"), ("ogg", ("magic:ogg",))),
        (data.startswith(b"ID3") or data[:2] in {b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"}, ("mp3", ("magic:mp3",))),
        (data.startswith(b"RIFF") and data[8:12] == b"WAVE", ("wav", ("magic:wav",))),
    )
    for matched, result in media_markers:
        if matched:
            return result
    return None


def _sniff_unity_or_dotnet(data: bytes, lower_name: str, declared_extension: str) -> SniffResult | None:
    lowered_head = data[:65536].lower()
    if data.startswith(b"\x00asm"):
        return "wasm", ("magic:wasm",)
    if data.startswith((b"UnityFS", b"UnityWeb", b"UnityRaw")):
        return "unity_asset_bundle", ("magic:unity_asset_bundle",)
    if b"serializedfile" in lowered_head or b"unity default resources" in lowered_head:
        return "unity_serialized_asset", ("structure:unity_serialized_file",)
    if lower_name == "global-metadata.dat" or b"\xaf\x1b\xb1\xfa" in data[:64]:
        return "il2cpp_metadata", ("structure:il2cpp_metadata",)
    markers = (b"bsjb", b"#strings", b"#us", b"mscoree.dll", b"system.reflection", b"assembly.load", b"methodinfo.invoke", b"type.gettype")
    if sum(1 for marker in markers if marker in data[:262144].lower()) >= PLR2004N3:
        return "mono_dotnet_assembly", ("structure:mono_dotnet_metadata", "structure:dotnet_metadata_without_pe_magic")
    if lower_name in {"globalgamemanagers", "maindata", "level0"} or declared_extension in {".assets", ".ress", ".resource"}:
        return "unity_serialized_asset", ("structure:unity_serialized_asset",)
    return None


def _sniff_text_or_extension(data: bytes, lower: str, lower_name: str, lowered_path: str, declared_extension: str) -> SniffResult:
    if declared_extension == ".asar" or lower_name.endswith(".asar"):
        return "asar", ("extension:asar",)
    if declared_extension in {".rpyc", ".rpyb", ".rpymc"} or b"RENPY" in data[:512]:
        return "renpy_bytecode", ("extension_or_marker:renpy_bytecode",)
    if "renpy" in lower[:8192] or declared_extension == ".rpy":
        return "renpy_source", ("text:renpy_source",)
    if lower.startswith(("{", "[")):
        return "json", ("text:json_shape",)
    if "function" in lower[:8192] or "require(" in lower[:8192] or declared_extension == ".js":
        return "javascript", ("text:javascript",)
    if (lower.startswith("#!") and "python" in lower[:128]) or "import " in lower[:4096] or "def " in lower[:4096]:
        return "python_source", ("text:python_source",)
    if "unity" in lowered_path and declared_extension in {".dat", ".data", ".bin"}:
        return "unity_serialized_asset", ("path:unity_data",)
    if declared_extension in TYPE_BY_EXTENSION:
        return TYPE_BY_EXTENSION[declared_extension], (str.__add__("extension:", declared_extension),)
    return "unknown", ("unknown_identity",)


def sniff_primary(data: bytes, path: Path, declared_extension: str) -> SniffResult:
    lower_name = path.name.lower()
    lowered_path = str(path).replace("\\", "/").lower()
    lower = _printable_text(data).lower().strip()
    for sniff in (
        _sniff_executable(data, lower_name, declared_extension),
        _sniff_archive_or_engine(data, lower, lower_name, declared_extension),
        _sniff_media(data),
        _sniff_unity_or_dotnet(data, lower_name, declared_extension),
    ):
        if sniff is not None:
            return sniff
    return _sniff_text_or_extension(data, lower, lower_name, lowered_path, declared_extension)


def find_embedded(data: bytes, primary: str) -> tuple[str, ...]:
    hits: list[str] = []
    lowered = data.lower()
    markers = (
        (b"MZ", "pe"), (b"PK\x03\x04", "zip"), (b"\x7fELF", "elf"),
        (b"RPA-", "rpa"), (b"\x00asm", "wasm"), (b"UnityFS", "unity_asset_bundle"),
        (b"UnityWeb", "unity_asset_bundle"), (b"RGSSAD", "rgss_archive"),
    )
    for marker, label in markers:
        idx = data.find(marker, 1)
        if idx > 0 and label != primary:
            hits.append(label)
    if primary in MEDIA_EXTENSION_TYPES and any(marker in lowered for marker in (b"<script", b"powershell", b"cmd.exe")):
        hits.append("script_payload")
    if primary == "renpy_bytecode":
        if b"c__builtin__\nexec" in data or b"builtins\nexec" in data or b"GLOBAL" in data or b"REDUCE" in data:
            hits.append("pickle_execution_markers")
        if b"marshal.loads" in lowered or b"base64.b64decode" in lowered:
            hits.append("encoded_python_launcher")
    return tuple(dict.fromkeys(hits))


__all__ = ("find_embedded", "read_head", "sniff_primary")
