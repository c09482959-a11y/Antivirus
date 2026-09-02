"""Detection-owned immutable engine-context selection.

Detection profile selection must not depend on routing/runtime engine helpers. This
module owns the bounded, side-effect-free engine context used by detection code.
It derives context only from explicit file/path/string/tag evidence and returns
immutable records for downstream profile selection and explainability.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.detection.profiles.generic.profile import DETECTION_PROFILE as GENERIC_PROFILE
from Virus_Scan.detection.profiles.media.profile import DETECTION_PROFILE as MEDIA_PROFILE
from Virus_Scan.detection.profiles.renpy.profile import DETECTION_PROFILE as RENPY_PROFILE
from Virus_Scan.detection.profiles.rpgm.profile import DETECTION_PROFILE as RPGM_PROFILE
from Virus_Scan.detection.profiles.unity.profile import DETECTION_PROFILE as UNITY_PROFILE
from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
    no_hook_text,
)

PLR2004N0_65 = 0.65

_ENGINE_PROFILE_NAMES = (RENPY_PROFILE.name, RPGM_PROFILE.name, UNITY_PROFILE.name, MEDIA_PROFILE.name)
_ENGINE_KEYS = _ENGINE_PROFILE_NAMES
_PROFILE_BY_NAME = MappingProxyType(
    {
        RENPY_PROFILE.name: RENPY_PROFILE,
        RPGM_PROFILE.name: RPGM_PROFILE,
        UNITY_PROFILE.name: UNITY_PROFILE,
        MEDIA_PROFILE.name: MEDIA_PROFILE,
        GENERIC_PROFILE.name: GENERIC_PROFILE,
    }
)
_ENGINE_PATH_MARKERS = MappingProxyType(
    {
        "renpy": ("/game/scripts", "/game/", "renpy", ".rpa", ".rpy", ".rpyc"),
        "rpgm": ("/www/data", "/www/js", "rpg_core.js", "rpg_managers.js", ".rgss", ".rpgm"),
        "unity": ("unityplayer", "assembly-csharp", "gameassembly", "globalgamemanagers", "/managed/"),
        "media": ("/audio/", "/images/", "/img/", "/movies/", "/video/"),
    }
)
_ENGINE_STRING_MARKERS = MappingProxyType(
    {
        "renpy": ("renpy", "init python", "label ", "screen ", "renpy.exports"),
        "rpgm": ("rpg maker", "rpg_managers", "rpg_core", "nw.js", "www/data"),
        "unity": ("unityengine", "unityplayer", "assembly-csharp", "il2cpp", "mono behaviour"),
        "media": ("vorbis", "ogg", "png", "jpeg", "webp", "mp4", "stego"),
    }
)
_MEDIA_EXTENSIONS = frozenset(MEDIA_PROFILE.file_extensions | frozenset((".bmp", ".flac", ".oga", ".opus", ".m4a", ".mov", ".avi", ".mkv", ".tif", ".tiff", ".ico", ".dds", ".tga")))
_MEDIA_TAGS = frozenset(MEDIA_PROFILE.tag_markers | frozenset(("media_asset", "image_asset", "audio_asset", "video_asset", "filetype_image", "filetype_audio", "filetype_video")))

def _engine_context_key(index: int) -> str:
    return "engine_context_key_" + int.__str__(index)


def _mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(value)
    return items if items is not None else ()


def _engine_text(value: object) -> str:
    """Project public engine text without caller-owned string hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="engine_context_text_missing",
        unsupported_reason="engine_context_text_rejected",
    )
    return text if reason == "" else ""


def _engine_text_lower(value: object) -> str:
    return _engine_text(value).lower()


def _engine_text_items(value: object) -> tuple[str, ...]:
    """Project public tag/event evidence without caller-owned iteration."""
    out: list[str] = []
    for item in no_hook_sequence_items(value):
        text = _engine_text(item).strip().lower()
        if text != "":
            out.append(text)
    return tuple(out)


def _mapping_snapshot_or_empty(value: Mapping[str, object] | None) -> dict[str, object]:
    """Detach exact owned mappings without caller-owned mapping hooks."""
    items = no_hook_mapping_items(value)
    if items is None:
        return {}
    out: dict[str, object] = {}
    for index, (key, item) in enumerate(items):
        key_text, reason = no_hook_text(
            key,
            missing_reason="engine_context_key_missing",
            unsupported_reason="engine_context_key_rejected",
        )
        if reason != "" or key_text == "":
            key_text = _engine_context_key(index)
        out[key_text] = item
    return out

def _iter_engine_profiles() -> object:
    """Return deterministic immutable engine profiles from private names."""
    return tuple(_PROFILE_BY_NAME[name] for name in _ENGINE_PROFILE_NAMES)


def _clamp(value: object) -> float:
    numeric, _reason = no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        maximum=1.0,
        reason="engine_context_numeric_rejected",
        non_finite_reason="engine_context_numeric_non_finite",
    )
    return numeric


def select_active_profile_engine(engine_context: Mapping[str, object] | None = None, threshold: float = 0.8) -> str:
    """Choose one bounded detection profile from an immutable engine context."""
    ctx = _mapping_snapshot_or_empty(engine_context)
    known = {engine: _clamp(dict.get(ctx, engine, 0.0)) for engine in _ENGINE_KEYS}
    best_engine = max(tuple(known), key=lambda engine: known[engine])
    threshold_value, _threshold_reason = no_hook_finite_float(
        threshold,
        default=0.8,
        minimum=0.0,
        maximum=1.0,
        reason="engine_context_threshold_rejected",
        non_finite_reason="engine_context_threshold_non_finite",
    )
    if dict.get(known, best_engine, 0.0) >= threshold_value:
        return best_engine
    return GENERIC_PROFILE.name


def infer_engine_context(tags: object, *, file_structure: object = None, strings_blob: object = "") -> Mapping[str, float]:
    """Return deterministic engine probabilities from explicit detection evidence only."""
    scores = dict.fromkeys(_ENGINE_KEYS, 0.0)
    scores["unknown"] = 0.1
    tags_l = set(_engine_text_items(tags))
    blob_l = _engine_text_lower(strings_blob)
    path_l = _engine_text_lower(file_structure).replace("\\", "/")
    ext_l = Path(path_l).suffix.lower()

    for profile in _iter_engine_profiles():
        engine = profile.name
        if ext_l and ext_l in profile.file_extensions:
            scores[engine] += 4.0
        if tags_l & profile.tag_markers:
            scores[engine] += 2.5
        if any(marker in path_l for marker in _ENGINE_PATH_MARKERS.get(engine, ())) :
            scores[engine] += 3.0
        if any(marker in blob_l for marker in _ENGINE_STRING_MARKERS.get(engine, ())) :
            scores[engine] += 3.5

    if ext_l in _MEDIA_EXTENSIONS:
        scores["media"] += 4.0
    if tags_l & _MEDIA_TAGS:
        scores["media"] += 2.5
    if "assets" in path_l and ext_l not in {".rpa", ".rvdata", ".rvdata2", ".rxdata"}:
        scores["unity"] += 0.75
    if "game/scripts" in path_l:
        scores["renpy"] += 2.0
    if "www/data" in path_l or "www/js" in path_l:
        scores["rpgm"] += 2.0

    score_items = _mapping_items(scores)
    total = sum(value for _key, value in score_items) + 1e-6
    return freeze_registry_value({key: _clamp(value / total) for key, value in score_items})


def engine_confidence_report(engine_context: Mapping[str, object] | None = None, *, path: object = None, tags: object = None, strings_blob: object = "") -> Mapping[str, object]:
    """Explain active profile selection without runtime/profile mutation."""
    ctx = _mapping_snapshot_or_empty(engine_context)
    active = select_active_profile_engine(ctx)
    confidence = _clamp(dict.get(ctx, active, 0.0))
    tagset = set(_engine_text_items(tags))
    text = _engine_text_lower(strings_blob)
    path_l = _engine_text_lower(path).replace("\\", "/")
    reasons: list[str] = []

    if active == "renpy" and (tagset & RENPY_PROFILE.tag_markers or any(marker in path_l for marker in ("renpy", ".rpy", ".rpa"))):
        reasons.append("renpy file/tag/path cues")
    if active == "unity" and (tagset & UNITY_PROFILE.tag_markers or any(marker in text or marker in path_l for marker in ("unityplayer", "gameassembly", "assembly-csharp"))):
        reasons.append("unity runtime/assembly cues")
    if active == "rpgm" and (tagset & RPGM_PROFILE.tag_markers or any(marker in path_l for marker in ("www/data", ".rvdata", ".rgss", ".rpgm"))):
        reasons.append("rpgm file/path cues")
    if active == "media" and (tagset & _MEDIA_TAGS or any(marker in path_l for marker in _MEDIA_EXTENSIONS)):
        reasons.append("media file/tag/path cues")
    if active == GENERIC_PROFILE.name:
        reasons.append("no confident specific engine; using generic profile")
    if not reasons:
        reasons.append("selected from bounded detection engine context")

    return freeze_registry_value(
        {
            "active_profile": active,
            "confidence": confidence,
            "baseline_suppression_allowed": active == GENERIC_PROFILE.name or confidence >= PLR2004N0_65,
            "reasons": tuple(reasons[:20]),
            "raw_context": freeze_registry_value({
                key: no_hook_materialize(value, reason_prefix="engine_context_raw", max_depth=4)
                for key, value in _mapping_items(ctx)
            }),
        }
    )


__all__ = ("engine_confidence_report", "infer_engine_context", "select_active_profile_engine")
