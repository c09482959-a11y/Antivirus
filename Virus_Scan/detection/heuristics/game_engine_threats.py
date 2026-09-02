"""Detection-owned game-engine threat semantic evaluator."""
from __future__ import annotations

from Virus_Scan.detection.heuristics.game_engine_common_rules import apply_common_game_engine_rules
from Virus_Scan.contracts.game_engine_threats import (
    GameThreatAccumulator,
    GameThreatHit,
    engine_from_path,
    strip_negated_behavior_phrases,
)
from Virus_Scan.detection.heuristics.game_engine_core import build_game_threat_context
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.detection.heuristics.game_engine_engine_rules import apply_engine_specific_game_engine_rules
from Virus_Scan.detection.heuristics.game_engine_metadata import apply_metadata_game_engine_rules


def _owned_threat_text(value: object, *, reason: str) -> str:
    if value is None:
        return ""
    text, failure = no_hook_text(
        value,
        missing_reason="missing_game_engine_threat_text",
        unsupported_reason=reason,
    )
    return "" if failure else text


def evaluate_game_engine_threats(text: str, *, path: str | None = None, engine: str | None = None) -> dict:
    low = strip_negated_behavior_phrases(_owned_threat_text(text, reason="unsafe_game_engine_threat_text_rejected"))
    engine_text = _owned_threat_text(engine, reason="unsafe_game_engine_threat_engine_rejected")
    eng = str.lower(engine_text or engine_from_path(path))
    accumulator = GameThreatAccumulator()
    context = build_game_threat_context(low, path)
    apply_common_game_engine_rules(low, eng, path, context, accumulator.add)
    apply_engine_specific_game_engine_rules(low, eng, path, context, accumulator.add)
    apply_metadata_game_engine_rules(low, context, accumulator.add)
    return accumulator.to_record(engine=eng, source=_owned_threat_text(path, reason="unsafe_game_engine_threat_path_rejected"))


__all__ = ("GameThreatHit", "evaluate_game_engine_threats")
