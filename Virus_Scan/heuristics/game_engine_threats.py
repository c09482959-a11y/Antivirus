"""Game-engine threat semantic evaluator.

Scanners provide text and routing context; this module returns canonical tags only.
The public evaluator remains the single API while term policy and bounded rule
families live in heuristics-owned helper modules.
"""
from __future__ import annotations

from Virus_Scan.heuristics.game_engine_threat_metadata_rules import add_behavior_metadata_rules
from Virus_Scan.heuristics.game_engine_threat_credential_rules import add_credential_and_loader_rules
from Virus_Scan.heuristics.game_engine_threat_rules import _EngineExecutionRequest, _add_engine_execution_rules
from Virus_Scan.contracts.game_engine_threats import (
    GameThreatAccumulator,
    GameThreatHit,
    engine_from_path,
    strip_negated_behavior_phrases,
)
from Virus_Scan.heuristics.no_hook import heuristic_lower, heuristic_text


def evaluate_game_engine_threats(text: str, *, path: str | None = None, engine: str | None = None) -> dict:
    path_text = heuristic_text(path)
    low = strip_negated_behavior_phrases(heuristic_text(text))
    eng = heuristic_lower(engine) or heuristic_lower(engine_from_path(path_text))
    accumulator = GameThreatAccumulator()
    store, _read, exfil, _exec_ctx = add_credential_and_loader_rules(low, eng, accumulator.add)
    _add_engine_execution_rules(
        _EngineExecutionRequest(
            low=low,
            path=path_text,
            engine=eng,
            store=store,
            exfil=exfil,
            add=accumulator.add,
        )
    )
    add_behavior_metadata_rules(low, accumulator.add)
    return accumulator.to_record(engine=eng, source=path_text)


__all__ = ("GameThreatHit", "evaluate_game_engine_threats")
