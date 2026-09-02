"""Scanner-owned game asset suffix normalization for image/media routing."""
from __future__ import annotations

from Virus_Scan.scanners.config import load_engine_policy_snapshot, load_filetype_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_contract_text

_FILETYPE_POLICY = load_filetype_policy_snapshot()
_ENGINE_POLICY = load_engine_policy_snapshot()
_KNOWN_ASSET_SUFFIXES = frozenset(
    str(ext).lower()
    for ext in (
        tuple(_FILETYPE_POLICY.all_routable_extensions)
        + tuple(_ENGINE_POLICY.media_profile_extensions)
        + tuple(_ENGINE_POLICY.unity_container_asset_extensions)
        + (".ogg", ".oga", ".opus", ".mp3", ".wav", ".flac", ".m4a", ".aac", ".wma")
        + (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".ttf", ".otf", ".fnt")
    )
    if str(ext).startswith(".")
)


def normalize_game_asset_suffix_extension(name: object) -> str | None:
    """Normalize preserved game asset suffixes like ``file.png_`` for routing."""
    normalized = scanner_contract_text(name, replacement="").lower()
    if not normalized.endswith("_"):
        return None
    base = normalized[:-1]
    for ext in sorted(_KNOWN_ASSET_SUFFIXES, key=len, reverse=True):
        if base.endswith(ext):
            return ext
    return None


__all__ = ("normalize_game_asset_suffix_extension",)
