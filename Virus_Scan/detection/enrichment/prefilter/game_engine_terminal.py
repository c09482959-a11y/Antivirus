"""Game-engine terminal prefilter driven by canonical confirmed chains."""
from __future__ import annotations

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.models.detection_result import build_fast_suspicious_detection_result
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.heuristics.game_engine_threats import evaluate_game_engine_threats
from Virus_Scan.detection.attack.api import official_attack_fast_path_policy

_MINIMUM_TERMINAL_ANCHOR_FLOOR = 64.0


def _confirmed_terminal_floor(chain_evidence: object) -> float:
    decisions = getattr(chain_evidence, "decisions", ())
    if type(decisions) is not tuple:
        return 0.0
    return max(
        (
            decision.anchor_floor
            for decision in decisions
            if decision.status == "confirmed" and decision.scoreable
        ),
        default=0.0,
    )


def terminal_prefilter_result(
    *,
    path: object,
    text: str,
    meta: dict[str, object],
    reason: str,
    version: str,
    confidence: float,
    attack_hit: str,
) -> dict[str, object] | None:
    fast_path_allowed, fast_path_model_evidence = official_attack_fast_path_policy()
    if not fast_path_allowed:
        return None
    result = evaluate_game_engine_threats(text, path=str(path))
    evidence = normalize_tag_evidence(
        result.get("tags") or (),
        source_detector="game_engine_terminal",
        source_stage="prefilter",
    )
    chain_evidence = evaluate_chain_evidence(tags=evidence)
    floor = _confirmed_terminal_floor(chain_evidence)
    if floor < _MINIMUM_TERMINAL_ANCHOR_FLOOR:
        return None
    terminal = build_fast_suspicious_detection_result(
        path=path,
        score=floor,
        tags=list(evidence.tags),
        active_profile=result.get("engine") or "other",
        reason=reason,
        version=version,
        constraints=dict(meta, yara_active=False, yaralight_active=False, prefilter=True),
        heuristic_hits=[hit.get("family") for hit in result.get("hits") or ()],
        confidence=confidence,
        attack_hit=attack_hit,
        model_evidence=fast_path_model_evidence,
    )
    terminal["canonical_chain_evidence"] = chain_evidence.to_record()
    return terminal


__all__ = ("terminal_prefilter_result",)
