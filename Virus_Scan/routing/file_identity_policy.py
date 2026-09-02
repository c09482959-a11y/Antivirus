"""Immutable file-identity routing policy tables."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

MEDIA_TYPES = ("png", "jpg", "gif", "webp", "bmp", "ogg", "mp3", "wav")
MEDIA_EXTENSION_TYPES = frozenset(MEDIA_TYPES)

TYPE_BY_EXTENSION: Mapping[str, str] = MappingProxyType({
    ".exe": "pe", ".dll": "pe", ".dat": "data", ".bin": "data", ".data": "data", ".so": "elf",
    ".dylib": "macho", ".zip": "zip", ".jar": "zip", ".apk": "zip", ".docx": "zip",
    ".rpa": "rpa", ".rgssad": "rgss_archive", ".rgss2a": "rgss_archive", ".rgss3a": "rgss_archive",
    ".rpgmvp": "rpgm_encrypted_asset", ".rpgmvo": "rpgm_encrypted_asset", ".rpgmvm": "rpgm_encrypted_asset",
    ".png": "png", ".jpg": "jpg", ".jpeg": "jpg", ".gif": "gif", ".webp": "webp", ".bmp": "bmp",
    ".ogg": "ogg", ".mp3": "mp3", ".wav": "wav", ".json": "json", ".js": "javascript", ".py": "python_source",
    ".rpy": "renpy_source", ".rpyc": "renpy_bytecode", ".rpyb": "renpy_bytecode", ".rpymc": "renpy_bytecode",
    ".assets": "unity_serialized_asset", ".asset": "unity_serialized_asset", ".bundle": "unity_asset_bundle", ".unity3d": "unity_asset_bundle", ".unity": "unity_serialized_asset",
    ".resource": "unity_resource", ".ress": "unity_resource", ".resS": "unity_resource", ".asar": "asar", ".wasm": "wasm",
})

UNITY_DLL_NAMES = frozenset({
    "unityplayer.dll", "assembly-csharp.dll", "assembly-csharp-firstpass.dll", "assembly-unityscript.dll",
    "gameassembly.dll", "unityengine.dll", "unityengine.coremodule.dll", "mono.dll", "mono-2.0-bdwgc.dll",
})
RPGM_DLL_NAMES = frozenset({
    "rgss102e.dll", "rgss100j.dll", "rgss200e.dll", "rgss202e.dll", "rgss300.dll", "rgss301.dll",
    "nw.dll", "node.dll", "nw_elf.dll",
})
RENPY_RUNTIME_NAMES = frozenset({
    "renpy.exe", "python27.dll", "python36.dll", "python37.dll", "python38.dll", "python39.dll",
    "python310.dll", "python311.dll", "python312.dll", "pythonw.exe", "librenpy.so", "renpy.py", "renpy.sh",
})

ACCEPTED_EQUIVALENT_SNIFFED_TYPES: Mapping[str, frozenset[str]] = MappingProxyType({
    "pe": frozenset({"mono_dotnet_assembly"}),
    "jpg": frozenset({"jpeg"}),
    "jpeg": frozenset({"jpg"}),
    "zip": frozenset({"jar", "apk", "docx_zip"}),
})

__all__ = (
    "ACCEPTED_EQUIVALENT_SNIFFED_TYPES",
    "MEDIA_EXTENSION_TYPES",
    "MEDIA_TYPES",
    "RENPY_RUNTIME_NAMES",
    "RPGM_DLL_NAMES",
    "TYPE_BY_EXTENSION",
    "UNITY_DLL_NAMES",
)
