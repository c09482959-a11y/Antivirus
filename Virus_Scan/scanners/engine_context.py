"""Scanner-owned engine context inference for scanner gates."""
from __future__ import annotations

from pathlib import Path
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import path_runtime_owner
from Virus_Scan.scanners.config.loader import load_engine_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_contract_lower_token, scanner_contract_text
from Virus_Scan.utils.probability import safe_clamp

_ENGINE_POLICY = load_engine_policy_snapshot()


def _lower_tags(tags: object) -> set[str]:
    lowered: set[str] = set()
    for tag in no_hook_sequence_items(tags):
        text = scanner_contract_lower_token(tag, replacement="").strip()
        if text:
            lowered.add(text)
    return lowered


def _path_suffix(path_value: str) -> str:
    path_error = False
    suffix = ""
    try:
        suffix = Path(path_value).suffix.lower()
    except SCAN_CONTENT_ERRORS:
        path_error = True
    if path_error:
        return ""
    return suffix


def _mapping_value(mapping: object, key: str, replacement: object = ()) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return replacement
    for raw_key, raw_value in items:
        if type(raw_key) is str and str.__str__(raw_key) == key:
            return raw_value
    return replacement


def _cue_values(cues: Mapping[str, object], key: str) -> frozenset[str]:
    values = _mapping_value(cues, key, ())
    lowered: set[str] = set()
    for item in no_hook_sequence_items(values):
        text = scanner_contract_lower_token(item, replacement="")
        if text:
            lowered.add(text)
    return frozenset(lowered)


def _score_value(value: object) -> float:
    number, reason = no_hook_finite_float(value, default=0.0, allow_exact_text=False)
    return 0.0 if reason else number


def _normalized_scores(scores: dict[str, float]) -> dict[str, float]:
    items = no_hook_mapping_items(scores)
    if items is None:
        return {"unknown": 1.0}
    total = sum(_score_value(value) for _key, value in items) + 1e-06
    return {
        scanner_contract_text(key, replacement="unknown"): safe_clamp(_score_value(value) / total, 0.0, 1.0)
        for key, value in items
    }


def _engine_cue_score(
    cues: Mapping[str, object],
    tags: set[str],
    strings_blob: str,
    path_text: str,
    extension: str,
) -> float:
    score = 0.0
    if extension and extension in _cue_values(cues, "extensions"):
        score += 4.0
    if any(marker in path_text for marker in _cue_values(cues, "path_markers")):
        score += 3.0
    if any(marker in strings_blob for marker in _cue_values(cues, "string_markers")):
        score += 3.5
    if tags & _cue_values(cues, "tag_markers"):
        score += 2.5
    return score


def _apply_engine_path_scores(
    scores: dict[str, float],
    tags: set[str],
    path_text: str,
    extension: str,
) -> None:
    if extension in _ENGINE_POLICY.media_profile_extensions:
        scores["media"] += 4.0
    if tags & _ENGINE_POLICY.media_profile_tags:
        scores["media"] += 2.5
    if "assets" in path_text and extension not in {".rpa", ".rvdata", ".rvdata2", ".rxdata"}:
        scores["unity"] += 0.75
    if "game/scripts" in path_text:
        scores["renpy"] += 2.0
    if "www/data" in path_text or "www/js" in path_text:
        scores["rpgm"] += 2.0


def infer_engine_context(tags: object, file_structure: object = None, strings_blob: object = "") -> dict[str, float]:
    """Infer per-file engine context from scanner-owned immutable policy."""
    scores = {"unity": 0.0, "renpy": 0.0, "rpgm": 0.0, "media": 0.0, "unknown": 0.1}
    tags_l = _lower_tags(tags)
    blob_l = scanner_contract_lower_token(strings_blob, replacement="")
    path_l = scanner_contract_lower_token(file_structure, replacement="").replace("\\", "/")
    ext_l = _path_suffix(path_l)
    for engine, raw_cues in no_hook_mapping_items(_ENGINE_POLICY.engine_file_context_cues) or ():
        cues = raw_cues if no_hook_mapping_items(raw_cues) is not None else {}
        engine_key = scanner_contract_text(engine, replacement="unknown")
        cue_score = _engine_cue_score(cues, tags_l, blob_l, path_l, ext_l)
        if cue_score:
            scores[engine_key] = scores.get(engine_key, 0.0) + cue_score
    _apply_engine_path_scores(scores, tags_l, path_l, ext_l)
    return merge_engine_context_with_runtime_hint(_normalized_scores(scores))


def merge_engine_context_with_runtime_hint(engine_context: object) -> dict[str, float]:
    """Merge runtime hint using scanner-owned weights without importing routing."""
    ctx = {scanner_contract_text(key, replacement="unknown"): _score_value(value) for key, value in (no_hook_mapping_items(engine_context) or ())}
    snapshot = path_runtime_owner().snapshot()
    hint_ctx = {scanner_contract_text(key, replacement="unknown"): _score_value(value) for key, value in (no_hook_mapping_items(snapshot.scan_engine_hint_context) or ())}
    hint = scanner_contract_lower_token(snapshot.scan_engine_hint, replacement="auto")
    if hint in {"unity", "renpy", "rpgm", "media"}:
        known_keys = ("unity", "renpy", "rpgm", "media")
        known_max = max((_score_value(ctx.get(key, 0.0)) for key in known_keys))
        hint_conf = _score_value(hint_ctx.get(hint, 0.0))
        ambiguous_file = (
            known_max < _ENGINE_POLICY.engine_context_runtime_hint_ambiguous_threshold
            and hint_conf >= _ENGINE_POLICY.engine_context_runtime_hint_confidence_threshold
        )
        weight = (
            _ENGINE_POLICY.engine_context_runtime_hint_ambiguous_weight
            if ambiguous_file
            else _ENGINE_POLICY.engine_context_runtime_hint_weak_weight
        )
        if ambiguous_file:
            ctx["unknown"] = _score_value(ctx.get("unknown", 0.0)) * 0.1
        for key in ("unity", "renpy", "rpgm", "media", "unknown"):
            ctx[key] = _score_value(ctx.get(key, 0.0)) + weight * _score_value(hint_ctx.get(key, 0.0))
        return _normalized_scores(ctx)
    return ctx


__all__ = ("infer_engine_context", "merge_engine_context_with_runtime_hint")
