"""Fast passive-asset triage helpers.

These helpers are low-level and direct-import safe. They do not mutate scanner
state, do not import scanner modules, and do not depend on historical global
injection. Scanner modules own normalization, evidence recording, and final tag
rewrite policy.
"""
from __future__ import annotations
import json

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value
from pathlib import Path
from typing import List, Tuple

PLR2004N12 = 12
PLR2004N16 = 16
PLR2004N32 = 32

DEFAULT_IMAGE_FAST_STRING_BYTES = 32768
_PAYLOAD_SIGNATURES = (
    (b"MZ", "embedded_executable"),
    (b"PK\x03\x04", "embedded_zip_payload"),
    (b"\x1f\x8b\x08", "embedded_gzip_payload"),
    (b"7z\xbc\xaf\x27\x1c", "embedded_7z_payload"),
    (b"Rar!\x1a\x07", "embedded_rar_payload"),
)
_SUSPICIOUS_TEXT = (
    b"powershell", b"cmd.exe", b"frombase64string", b"mimikatz", b"certutil", b"bitsadmin",
)

RPGM_ENCRYPTED_SIGNATURES = (b"RPGMV", b"RPGMZ")
RPGM_ENCRYPTED_HEADER_SIZE = 16
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _asset_text(value: object, *, default: str = "") -> str:
    text = text_boundary_value(value, unsupported=None)
    if type(text) is str:
        return str.__str__(text)
    return default


def _asset_lower_text(value: object, *, default: str = "") -> str:
    return _asset_text(value, default=default).lower()


def _asset_nonnegative_int(value: object, *, default: int) -> int:
    number, reason = no_hook_exact_nonnegative_int(value, default=default, reason="invalid_fast_asset_integer")
    return default if reason else number


def _asset_read_size(value: object, *, default: int) -> int:
    if value is None:
        return default
    if type(value) is bool:
        return default
    if type(value) is int:
        return max(0, value)
    if type(value) is float and value.is_integer():
        return max(0, int(value))
    return _asset_nonnegative_int(value, default=default)


def _asset_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if type(value) is bytes:
        return bytes(value)
    if type(value) is bytearray:
        return bytes(value)
    return b""


def _hex_to_rpgm_key(value: object) -> bytes | None:
    text = _asset_text(value).strip()
    if len(text) < PLR2004N32:
        return None
    key_text = text[:32]
    if any(ch not in _HEX_DIGITS for ch in key_text):
        return None
    key = bytes.fromhex(key_text)
    return key if len(key) == PLR2004N16 else None


def _bounded_rpgm_system_json_candidates(path: object, *, max_parents: int = 8) -> List[Path]:
    """Return deterministic nearby RPG Maker System.json candidates.

    The probe is intentionally local and bounded so a single asset cannot trigger
    an unbounded directory walk from scheduler admission or worker triage.
    """
    path_text = _asset_text(path)
    if path_text == "":
        return []
    try:
        cur = Path(path_text).resolve().parent
    except IO_CONFIGURATION_ERRORS:
        cur = Path(path_text).parent
    candidates: List[Path] = []
    seen = set()
    for depth, base in enumerate([cur, *cur.parents]):
        if depth >= max(1, _asset_nonnegative_int(max_parents, default=8)):
            break
        for rel in (Path("data/System.json"), Path("www/data/System.json"), Path("System.json")):
            cand = base / rel
            key = str(cand).lower()
            if key not in seen:
                seen.add(key)
                candidates.append(cand)
    return candidates


def find_rpgm_encryption_key(path: object, *, max_json_bytes: int = 1_048_576) -> bytes | None:
    """Find a nearby RPG Maker MV/MZ encryption key without global scanning."""
    for cand in _bounded_rpgm_system_json_candidates(path):
        if not cand.is_file():
            continue
        try:
            if cand.stat().st_size > max_json_bytes:
                continue
            data = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError, TypeError, UnicodeError):
            continue
        if isinstance(data, dict):
            key = _hex_to_rpgm_key(data.get("encryptionKey"))
            if key:
                return key
    return None


def sniff_recovered_rpgm_payload_type(recovered: bytes | bytearray | None, ext: str = "") -> tuple[str, List[str]]:
    """Classify a recovered RPGM plaintext header; never trusts extension alone."""
    data = _asset_bytes(recovered)
    tags: List[str] = []
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", ["rpgm_recovered_magic_png", "image_file", "filetype_image"]
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg", ["rpgm_recovered_magic_jpeg", "image_file", "filetype_image"]
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif", ["rpgm_recovered_magic_gif", "image_file", "filetype_image"]
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        return "webp", ["rpgm_recovered_magic_webp", "image_file", "filetype_image"]
    if data.startswith(b"OggS"):
        return "ogg", ["rpgm_recovered_magic_ogg", "media_file", "audio_file"]
    if len(data) >= PLR2004N12 and data[4:8] == b"ftyp":
        return "m4a", ["rpgm_recovered_magic_m4a", "media_file", "audio_file"]
    if data.startswith(b"RIFF") and b"WAVE" in data[:16]:
        return "wav", ["rpgm_recovered_magic_wav", "media_file", "audio_file"]
    e = _asset_lower_text(ext)
    if e in {".png_", ".jpg_", ".jpeg_", ".webp_", ".gif_", ".bmp_"}:
        return "encrypted_image_unverified", ["rpgm_encrypted_image", "image_file"]
    if e in {".ogg_", ".m4a_", ".mp3_", ".wav_"}:
        return "encrypted_audio_unverified", ["rpgm_encrypted_audio", "media_file", "audio_file"]
    return "encrypted_asset", tags


def probe_rpgm_encrypted_header(path: object, header: bytes | bytearray | None = None, ext: str = "") -> dict[str, object]:
    """Bounded RPGM MV/MZ encrypted asset header probe.

    It reads at most the first 32 bytes, optionally recovers the original file
    header with a nearby System.json encryption key, and returns deterministic
    classification tags. It does not decrypt or write asset contents.
    """
    h = _asset_bytes(header)
    if not any(h.startswith(sig) for sig in RPGM_ENCRYPTED_SIGNATURES):
        return {"is_rpgm_encrypted": False}
    result_tags = ["rpgm", "rpgm_resource", "rpgm_encrypted_asset", "rpgm_header_probe"]
    result: dict[str, object] = {
        "is_rpgm_encrypted": True,
        "container": h[:5].decode("ascii", errors="ignore").lower(),
        "recovered_type": "unknown",
        "recovered_header": b"",
        "key_found": False,
        "tags": result_tags,
    }
    raw_ext = _asset_lower_text(ext)
    name = Path(_asset_text(path)).name.lower()
    if name.endswith("_") and not raw_ext.endswith("_"):
        base_suffix = Path(name[:-1]).suffix.lower()
        if base_suffix:
            raw_ext = base_suffix + "_"
    key = find_rpgm_encryption_key(path)
    if key and len(h) >= RPGM_ENCRYPTED_HEADER_SIZE + 16:
        encrypted = h[RPGM_ENCRYPTED_HEADER_SIZE:RPGM_ENCRYPTED_HEADER_SIZE + 16]
        recovered = bytes((b ^ key[i]) for i, b in enumerate(encrypted))
        rtype, rt_tags = sniff_recovered_rpgm_payload_type(recovered, ext=raw_ext)
        result.update({"recovered_type": rtype, "recovered_header": recovered, "key_found": True})
        result_tags.extend(["rpgm_header_recovered", *rt_tags])
    else:
        rtype, rt_tags = sniff_recovered_rpgm_payload_type(b"", ext=raw_ext)
        result.update({"recovered_type": rtype, "key_found": False})
        result_tags.extend(["rpgm_header_recovery_key_missing", *rt_tags])
    return result



def recover_rpgm_encrypted_sample(path: object, header: bytes | bytearray | None = None, ext: str = "", *, max_bytes: int = 131072) -> dict[str, object]:
    """Recover a bounded RPGM MV/MZ plaintext sample for scanner evidence.

    RPG Maker MV/MZ encrypted media wraps the asset with a 16-byte RPGM header
    and XORs the original first 16 bytes with the project encryption key; the
    remainder of the asset is stored after that encrypted prefix. This returns a
    bounded plaintext sample for detection and evidence classification without
    writing decrypted files or performing unbounded reads.
    """
    probe = probe_rpgm_encrypted_header(path, header=header, ext=ext)
    if not probe.get("is_rpgm_encrypted"):
        return {"is_rpgm_encrypted": False, "probe": probe, "sample": b"", "tags": []}
    tags: List[str] = ["rpgm_encrypted_asset_sampled"]
    recovered_header = bytes(probe.get("recovered_header") or b"")
    if not recovered_header or not probe.get("key_found"):
        return {"is_rpgm_encrypted": True, "probe": probe, "sample": b"", "tags": [*tags, "rpgm_decryption_key_missing"]}
    try:
        p = Path(path)
        with p.open("rb") as fh:
            fh.seek(RPGM_ENCRYPTED_HEADER_SIZE + 16)
            remainder = fh.read(max(0, _asset_read_size(max_bytes, default=131072) - len(recovered_header)))
    except OSError as exc:
        return {"is_rpgm_encrypted": True, "probe": probe, "sample": recovered_header, "tags": [*tags, "rpgm_decrypted_sample_tail_unreadable"], "error": str(exc)}
    sample = recovered_header + remainder
    rtype, rt_tags = sniff_recovered_rpgm_payload_type(sample[:32], ext=ext)
    return {
        "is_rpgm_encrypted": True,
        "probe": probe,
        "sample": sample,
        "recovered_type": rtype,
        "tags": [*tags, "rpgm_decrypted_sample_available", *rt_tags],
    }

def sample_file_prefix_suffix(
    path: object,
    *,
    artifact_read_snapshot: object,
    prefix_size: int = DEFAULT_IMAGE_FAST_STRING_BYTES,
    suffix_size: int = DEFAULT_IMAGE_FAST_STRING_BYTES,
) -> Tuple[bytes, bytes, int]:
    """Project bounded prefix/suffix samples from the canonical artifact snapshot."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    if not snapshot.complete:
        return b"", b"", 0
    prefix_limit = _asset_read_size(prefix_size, default=DEFAULT_IMAGE_FAST_STRING_BYTES)
    suffix_limit = _asset_read_size(suffix_size, default=DEFAULT_IMAGE_FAST_STRING_BYTES)
    prefix = snapshot.read_prefix(prefix_limit)
    suffix = b""
    if suffix_limit and snapshot.size > prefix_limit:
        suffix = snapshot.tail_bytes[-suffix_limit:]
    return prefix, suffix, snapshot.size


def validated_embedded_payload_hits(sample: bytes, min_offset: int = 32) -> List[Tuple[int, str]]:
    """Return embedded payload signatures that occur after the file header."""
    data = _asset_bytes(sample)
    hits: List[Tuple[int, str]] = []
    for needle, tag in _PAYLOAD_SIGNATURES:
        off = data.find(needle, _asset_read_size(min_offset, default=32))
        if off >= 0:
            hits.append((off, tag))
    return hits


def png_decode_observation(sample: bytes) -> str | None:
    """Return a non-suspicious decode observation for obviously malformed PNG samples.

    This is deliberately structural and cheap. It prevents corrupt/partial game
    PNG assets from being reported as clean fast-triage assets while avoiding
    expensive Pillow imports in the fast path. Payload/signature checks remain
    separate and can still escalate suspicious content.
    """
    data = _asset_bytes(sample)
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    if b"IEND" not in data:
        return "image_decode_failed"
    pos = 8
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos:pos+4], "big")
        if length > 64 * 1024 * 1024:
            return "image_decode_failed"
        crc_end = pos + 8 + length + 4
        if crc_end > len(data):
            return "image_decode_failed"
        ctype = data[pos+4:pos+8]
        if ctype == b"IEND":
            return None
        pos = crc_end
    return "image_decode_failed"


def scan_image_file_fast_triage(
    path: object, *, artifact_read_snapshot: object, sample_bytes: int = DEFAULT_IMAGE_FAST_STRING_BYTES,
) -> Tuple[List[str], bool, bytes]:
    """Cheap image triage for fast/auto-fast modes: returns tags, suspicious, sample."""
    tags: List[str] = ["image", "image_fast_triage", "asset_fast_triage"]
    prefix, suffix, _size = sample_file_prefix_suffix(
        path, artifact_read_snapshot=artifact_read_snapshot,
        prefix_size=sample_bytes, suffix_size=sample_bytes,
    )
    sample = (prefix or b"") + (suffix or b"")
    low = sample.lower()
    suspicious = False

    decode_observation = png_decode_observation(sample)
    if decode_observation:
        tags.append(decode_observation)

    for _off, tag in validated_embedded_payload_hits(sample, min_offset=32):
        tags.extend([tag, "asset_embedded_payload_signature", "asset_deep_scan_escalated"])
        suspicious = True

    if b"http://" in low or b"https://" in low:
        tags.extend(["image_metadata_url_reference", "asset_metadata_reference"])

    if any(token in low for token in _SUSPICIOUS_TEXT):
        tags.extend(["embedded_command_or_url", "image_embedded_suspicious_string", "asset_deep_scan_escalated"])
        suspicious = True

    if not suspicious:
        tags.append("image_fast_triage_clean")
    return tags, suspicious, sample
