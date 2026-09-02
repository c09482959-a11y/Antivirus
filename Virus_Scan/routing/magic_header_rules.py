from dataclasses import dataclass
from typing import Tuple

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.utils.fast_assets import probe_rpgm_encrypted_header
from Virus_Scan.utils.stages import sanitize_tag_part as _umige_sanitize_tag_part


PLR2004N0_85 = 0.85
PLR2004N12 = 12
PLR2004N126 = 126
PLR2004N2 = 2
PLR2004N224 = 224
PLR2004N255 = 255
PLR2004N265 = 265
PLR2004N32 = 32

@dataclass(frozen=True)
class MagicHeaderClassification:
    magic_stage: str
    magic_type: str
    confidence: float
    tags: Tuple[str, ...]
    rpgm_recovered_type: str = ""
    rpgm_recovered_header: bytes = b""
    rpgm_recovery_key_found: bool = False


def _classification(stage: str, magic_type: str, confidence: float, *tags: str) -> MagicHeaderClassification:
    return MagicHeaderClassification(stage, magic_type, confidence, tuple(tags))


def _magic_header_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="magic_header_text_missing",
        unsupported_reason="magic_header_text_rejected",
    )
    return "" if reason else text


def _magic_header_bytes(value: object) -> bytes:
    if type(value) is bytes:
        return value
    if type(value) is bytearray:
        return bytes(value)
    return b""


def is_valid_renpy_bytecode_header(ext: object, header: object) -> bool:
    ext_text = _magic_header_text(ext).lower()
    if ext_text not in {".rpyc", ".rpyb", ".rpymc"}:
        return False
    return _magic_header_bytes(header).startswith((b"RENPY RPC", b"RENPY RPC2", b"RENPY RPC3"))


def renpy_bytecode_identity_tags(ext: object) -> Tuple[str, ...]:
    ext_part = _magic_header_text(ext).lower().lstrip(".") or "unknown"
    return (
        "magic_renpy_rpyc",
        "filetype_runtime",
        "renpy",
        "renpy_bytecode",
        "renpy_bytecode_" + _umige_sanitize_tag_part(ext_part),
    )


def classify_known_container_header(path: object, ext: str, ext_stage: str, header: bytes) -> MagicHeaderClassification | None:
    del ext_stage  # Explicitly unused contract parameters.
    if header.startswith(b"MZ"):
        return _classification("binary", "pe_mz", 1.0, "magic_pe", "filetype_binary", "pe_file")
    if header.startswith(b"\x7fELF"):
        return _classification("binary", "elf", 1.0, "magic_elf", "filetype_binary", "elf_file")
    if header.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")):
        return _classification("binary", "macho", 1.0, "magic_macho", "filetype_binary", "macho_file")
    if header.startswith(b"RPA-"):
        return _classification("archive", "renpy_rpa", 1.0, "magic_renpy_rpa", "filetype_archive", "archive_file", "renpy", "renpy_archive")
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return _classification("archive", "zip", 1.0, "magic_zip", "filetype_archive", "archive_file")
    if header.startswith(b"7z\xbc\xaf'\x1c"):
        return _classification("archive", "7z", 1.0, "magic_7z", "filetype_archive", "archive_file")
    if header.startswith(b"Rar!\x1a\x07"):
        return _classification("archive", "rar", 1.0, "magic_rar", "filetype_archive", "archive_file")
    if header.startswith(b"\x1f\x8b"):
        return _classification("archive", "gzip", 0.95, "magic_gzip", "filetype_archive", "archive_file")
    if len(header) >= PLR2004N265 and header[257:262] == b"ustar":
        return _classification("archive", "tar", 1.0, "magic_tar", "filetype_archive", "archive_file")
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return _classification("image", "png", 1.0, "magic_png", "filetype_image", "image_file")
    if header.startswith(b"\xff\xd8\xff"):
        return _classification("image", "jpeg", 1.0, "magic_jpeg", "filetype_image", "image_file")
    if header.startswith((b"GIF87a", b"GIF89a")):
        return _classification("image", "gif", 1.0, "magic_gif", "filetype_image", "image_file")
    if header.startswith(b"BM"):
        return _classification("image", "bmp", 0.9, "magic_bmp", "filetype_image", "image_file")
    if header.startswith(b"RIFF") and b"WEBP" in header[:16]:
        return _classification("image", "webp", 1.0, "magic_webp", "filetype_image", "image_file")
    if header.startswith((b"RPGMV", b"RPGMZ")):
        probe = probe_rpgm_encrypted_header(path, header, ext=ext)
        return MagicHeaderClassification(
            "asset",
            "rpgm_mv_encrypted_asset",
            0.98,
            ("magic_rpgm_encrypted_asset", "filetype_asset", *tuple(probe.get("tags") or ())),
            str(probe.get("recovered_type") or "encrypted_asset"),
            bytes(probe.get("recovered_header") or b""),
            bool(probe.get("key_found")),
        )
    return None


def classify_media_or_runtime_header(ext: str, ext_stage: str, header: bytes) -> MagicHeaderClassification | None:
    if header.startswith(b"ID3"):
        return _classification("asset", "mp3_id3", 0.98, "magic_mp3", "filetype_asset", "media_file", "audio_file")
    if len(header) >= PLR2004N2 and header[0] == PLR2004N255 and (header[1] & 224 == PLR2004N224):
        return _classification("asset", "mp3_frame", 0.9, "magic_mp3", "filetype_asset", "media_file", "audio_file")
    if header.startswith(b"RIFF") and b"WAVE" in header[:16]:
        return _classification("asset", "wav_riff", 0.98, "magic_wav", "filetype_asset", "media_file", "audio_file")
    if header.startswith(b"OggS"):
        return _classification("asset", "ogg", 0.98, "magic_ogg", "filetype_asset", "media_file", "audio_file")
    if header.startswith(b"fLaC"):
        return _classification("asset", "flac", 0.98, "magic_flac", "filetype_asset", "media_file", "audio_file")
    if len(header) >= PLR2004N12 and header[4:8] == b"ftyp":
        brand = header[8:12].lower()
        return _classification("asset", "quicktime" if brand == b"qt  " else "mp4_iso_bmff", 0.95, "magic_mp4", "filetype_asset", "media_file", "video_file")
    if header.startswith(b"RIFF") and b"AVI " in header[:16]:
        return _classification("asset", "avi_riff", 0.95, "magic_avi", "filetype_asset", "media_file", "video_file")
    if header.startswith(b"\x1aE\xdf\xa3"):
        return _classification("asset", "matroska_webm", 0.95, "magic_matroska", "filetype_asset", "media_file", "video_file")
    if is_valid_renpy_bytecode_header(ext, header):
        return MagicHeaderClassification(ext_stage, "renpy_rpyc", 0.98, renpy_bytecode_identity_tags(ext))
    if header.startswith((b"UnityFS", b"UnityRaw", b"UnityWeb")):
        return _classification("asset", "unity_assetbundle", 0.98, "magic_unity_assetbundle", "filetype_asset", "unity_asset", "unity_container_asset")
    if header.startswith(b"UnityWebData1.0"):
        return _classification("asset", "unity_webdata", 0.98, "magic_unity_webdata", "filetype_asset", "unity_asset", "unity_container_asset")
    if header.startswith(b"CAB-") or b"CAB-" in header[:128]:
        return _classification("asset", "unity_serialized_asset", 0.75, "magic_unity_cab", "filetype_asset", "unity_asset", "unity_container_asset")
    return None


def classify_font_or_runtime_header(ext: str, header: bytes) -> MagicHeaderClassification | None:
    if header.startswith((b"\x00\x01\x00\x00", b"true")):
        return _classification("asset", "ttf_font", 0.98, "magic_ttf", "filetype_asset", "font_file")
    if header.startswith(b"OTTO"):
        return _classification("asset", "otf_font", 0.98, "magic_otf", "filetype_asset", "font_file")
    if header.startswith(b"wOFF"):
        return _classification("asset", "woff_font", 0.98, "magic_woff", "filetype_asset", "font_file")
    if header.startswith(b"wOF2"):
        return _classification("asset", "woff2_font", 0.98, "magic_woff2", "filetype_asset", "font_file")
    if ext in {".rvdata", ".rvdata2", ".rxdata"} and header[:2] in {b"\x04\x08", b"\x04\x06", b"\x04\x07"}:
        return _classification("runtime", "rpgm_marshal", 0.9, "magic_rpgm_marshal", "filetype_runtime", "rpgm", "rpgm_resource")
    return None


def classify_text_or_unknown_header(header: bytes) -> MagicHeaderClassification:
    sample = header[:4096]
    textish = False
    if b"\x00" not in sample:
        printable = sum(1 for byte in sample if byte in b"\r\n\t" or PLR2004N32 <= byte <= PLR2004N126)
        textish = bool(sample) and printable / max(1, len(sample)) > PLR2004N0_85
    if not textish:
        return _classification("binary", "unknown_binary_blob", 0.35, "magic_binary_blob", "filetype_binary")
    decoded = sample.decode("latin1", errors="ignore").lower()
    stripped = decoded.lstrip()
    if stripped.startswith(("{", "[")):
        return _classification("asset", "json_text", 0.7, "magic_text", "filetype_text", "filetype_asset", "json_text_file", "text_config_file")
    if stripped.startswith("<?xml"):
        return _classification("asset", "xml_text", 0.7, "magic_text", "filetype_text", "filetype_asset", "xml_text_file", "text_config_file")
    if stripped.startswith(("<html", "<!doctype html")):
        return _classification("asset", "html_text", 0.7, "magic_text", "filetype_text", "filetype_asset", "html_text_file")
    script_markers = ("powershell", "cmd.exe", "import ", "function ", "var ", "const ", "class ", "eval(", "subprocess", "createobject(")
    if decoded.startswith("#!") or any(marker in decoded for marker in script_markers):
        return _classification("runtime", "script_text", 0.7, "magic_text", "filetype_text", "filetype_runtime", "script_file")
    if "=" in decoded[:512] or ":" in decoded[:512]:
        return _classification("asset", "text_config", 0.6, "magic_text", "filetype_text", "filetype_asset", "text_config_file")
    return _classification("asset", "text", 0.5, "magic_text", "filetype_text", "filetype_asset", "text_file")


def classify_magic_header(path: object, ext: str, ext_stage: str, header: bytes) -> MagicHeaderClassification:
    return (
        classify_known_container_header(path, ext, ext_stage, header)
        or classify_media_or_runtime_header(ext, ext_stage, header)
        or classify_font_or_runtime_header(ext, header)
        or classify_text_or_unknown_header(header)
    )
