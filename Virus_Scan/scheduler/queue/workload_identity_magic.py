"""Bounded scheduler-owned magic header identity rules."""
from __future__ import annotations

from typing import NamedTuple, TypeAlias

from Virus_Scan.utils.fast_assets import probe_rpgm_encrypted_header


class WorkloadMagicIdentity(NamedTuple):
    stage: str
    magic_type: str
    confidence: float
    tags: tuple[str, ...]


PrefixRule: TypeAlias = tuple[tuple[bytes, ...], str, str, float, tuple[str, ...]]

_BINARY_PREFIX_RULES: tuple[PrefixRule, ...] = (
    ((b"MZ",), "binary", "pe_mz", 1.0, ("pe_file", "filetype_binary")),
    ((b"\x7fELF",), "binary", "elf", 1.0, ("elf_file", "filetype_binary")),
    (
        (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"),
        "binary",
        "macho",
        1.0,
        ("macho_file", "filetype_binary"),
    ),
)

_ARCHIVE_PREFIX_RULES: tuple[PrefixRule, ...] = (
    ((b"RPA-",), "archive", "renpy_rpa", 1.0, ("archive_file", "renpy_archive")),
    ((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"), "archive", "zip", 1.0, ("archive_file",)),
    ((b"7z\xbc\xaf\x27\x1c",), "archive", "7z", 1.0, ("archive_file",)),
    ((b"Rar!\x1a\x07",), "archive", "rar", 1.0, ("archive_file",)),
    ((b"\x1f\x8b",), "archive", "gzip", 0.95, ("archive_file",)),
)

_IMAGE_PREFIX_RULES: tuple[PrefixRule, ...] = (
    ((b"\x89PNG\r\n\x1a\n",), "image", "png", 1.0, ("image_file", "filetype_image")),
    ((b"\xff\xd8\xff",), "image", "jpeg", 1.0, ("image_file", "filetype_image")),
    ((b"GIF87a", b"GIF89a"), "image", "gif", 1.0, ("image_file", "filetype_image")),
    ((b"BM",), "image", "bmp", 0.9, ("image_file", "filetype_image")),
)
_ASSET_PREFIX_RULES: tuple[PrefixRule, ...] = (
    (
        (b"UnityFS", b"UnityRaw", b"UnityWeb", b"UnityWebData1.0"),
        "asset",
        "unity_assetbundle",
        0.98,
        ("unity_asset", "unity_container_asset", "filetype_asset"),
    ),
    ((b"OggS",), "asset", "ogg", 0.98, ("media_file", "audio_file", "filetype_asset")),
    ((b"fLaC",), "asset", "flac", 0.98, ("media_file", "audio_file", "filetype_asset")),
    (
        (b"\x00\x01\x00\x00", b"true", b"OTTO", b"wOFF", b"wOF2"),
        "asset",
        "font",
        0.98,
        ("font_file", "filetype_asset"),
    ),
)

_UNKNOWN_MAGIC_IDENTITY = WorkloadMagicIdentity("unknown", "unknown", 0.0, ())


def unknown_workload_magic_identity() -> WorkloadMagicIdentity:
    return _UNKNOWN_MAGIC_IDENTITY


def _prefix_identity(header: bytes, rules: tuple[PrefixRule, ...]) -> WorkloadMagicIdentity | None:
    for prefixes, stage, magic_type, confidence, tags in rules:
        if header.startswith(prefixes):
            return WorkloadMagicIdentity(stage, magic_type, confidence, tags)
    return None


def identify_workload_magic_header(
    filesystem_path: str,
    header: bytes,
    ext: str,
) -> WorkloadMagicIdentity:
    """Classify a scheduler workload header without detector/scoring imports."""
    binary = _prefix_identity(header, _BINARY_PREFIX_RULES)
    if binary is not None:
        return binary
    archive = _prefix_identity(header, _ARCHIVE_PREFIX_RULES)
    if archive is not None:
        return archive
    if len(header) >= 265 and header[257:262] == b"ustar":
        return WorkloadMagicIdentity("archive", "tar", 1.0, ("archive_file",))
    image = _prefix_identity(header, _IMAGE_PREFIX_RULES)
    if image is not None:
        return image
    if header.startswith(b"RIFF") and b"WEBP" in header[:16]:
        return WorkloadMagicIdentity("image", "webp", 1.0, ("image_file", "filetype_image"))
    if header.startswith((b"RPGMV", b"RPGMZ")):
        probe = probe_rpgm_encrypted_header(filesystem_path, header, ext=ext)
        return WorkloadMagicIdentity(
            "asset",
            "rpgm_mv_encrypted_asset",
            0.98,
            ("filetype_asset", *tuple(probe.get("tags") or ())),
        )
    container_asset = _prefix_identity(header, _ASSET_PREFIX_RULES)
    if container_asset is not None:
        return container_asset
    if header.startswith(b"CAB-") or b"CAB-" in header[:128]:
        return WorkloadMagicIdentity(
            "asset",
            "unity_serialized_asset",
            0.75,
            ("unity_asset", "unity_container_asset", "filetype_asset"),
        )
    has_mp3_frame = len(header) >= 2 and header[0] == 0xFF and (header[1] & 0xE0) == 0xE0
    if header.startswith(b"ID3") or has_mp3_frame:
        return WorkloadMagicIdentity(
            "asset",
            "mp3",
            0.90,
            ("media_file", "audio_file", "filetype_asset"),
        )
    if header.startswith(b"RIFF") and b"WAVE" in header[:16]:
        return WorkloadMagicIdentity(
            "asset",
            "wav_riff",
            0.98,
            ("media_file", "audio_file", "filetype_asset"),
        )
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return WorkloadMagicIdentity(
            "asset",
            "mp4_iso_bmff",
            0.95,
            ("media_file", "video_file", "filetype_asset"),
        )
    if header.startswith(b"RIFF") and b"AVI " in header[:16]:
        return WorkloadMagicIdentity(
            "asset",
            "avi_riff",
            0.95,
            ("media_file", "video_file", "filetype_asset"),
        )
    if header.startswith(b"\x1aE\xdf\xa3"):
        return WorkloadMagicIdentity(
            "asset",
            "matroska_webm",
            0.95,
            ("media_file", "video_file", "filetype_asset"),
        )
    return unknown_workload_magic_identity()


__all__=("WorkloadMagicIdentity","identify_workload_magic_header","unknown_workload_magic_identity")
