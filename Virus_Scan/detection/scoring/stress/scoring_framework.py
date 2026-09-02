"""Quantitative stress scoring contracts for UMIGE stress harnesses."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
)

SCORE_FIELDS = (
    'stability_score','determinism_score','orchestration_integrity_score','concurrency_resilience_score',
    'recovery_reliability_score','persistence_integrity_score','JSON_integrity_score','module_isolation_score',
    'state_consistency_score','retry_logic_score','backpressure_resilience_score','resource_efficiency_score',
    'fault_tolerance_score','classification_accuracy_score','chain_integrity_score','cleanup_reliability_score',
    'rollback_integrity_score','corruption_resistance_score','error_propagation_score','recovery_completeness_score',
)
_SCORE_FIELD_SET = frozenset(SCORE_FIELDS)

@dataclass(frozen=True, slots=True)
class ScorePenalty:
    field: str
    penalty: float
    subsystem: str
    reason: str
    trigger: str
    reproducibility: str = 'medium'
    blast_radius: str = 'local'


def clamp_score(value: float) -> float:
    numeric, _reason = no_hook_finite_float(
        value,
        default=0.0,
        reason="stress_score_numeric_rejected",
        non_finite_reason="stress_score_non_finite",
    )
    return round(max(0.0, min(10.0, numeric)), 3)


def _stress_float(value: object, *, default: float = 0.0) -> float:
    numeric, _reason = no_hook_finite_float(
        value,
        default=default,
        reason="stress_numeric_rejected",
        non_finite_reason="stress_non_finite",
    )
    return numeric


def _score_field(value: object) -> str:
    text = _score_field_text(value)
    return text if text in _SCORE_FIELD_SET else ""


def _score_field_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="stress_score_field_missing",
        unsupported_reason="stress_score_field_rejected",
    )
    if reason:
        return ""
    text = text.strip()
    return text


def _mapping_snapshot(value: object) -> dict[str, object]:
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return {}
    out: dict[str, object] = {}
    for key, item in items:
        field_name = _score_field(key)
        if field_name:
            out[field_name] = item
    return out


def _score_value(scores: object, field_name: str) -> float:
    return clamp_score(dict.get(_mapping_snapshot(scores), field_name, 10.0))


def _confidence_value(confidence: object, field_name: str) -> float:
    return round(max(0.0, min(1.0, _stress_float(dict.get(_mapping_snapshot(confidence), field_name, 0.92), default=0.92))), 3)


def _penalty_event_field(event: object) -> str:
    if type(event) is not ScorePenalty:
        return ""
    return _score_field(event.field)


def _penalty_event_penalty(event: object) -> float:
    if type(event) is not ScorePenalty:
        return 0.0
    return _stress_float(event.penalty)


def base_scores() -> dict[str, float]:
    return {field: 10.0 for field in SCORE_FIELDS}


def base_confidence(*, partial_async_observability: bool = True) -> dict[str, float]:
    conf = dict.fromkeys(SCORE_FIELDS, 0.92)
    if partial_async_observability:
        for score_field in ('concurrency_resilience_score','backpressure_resilience_score','orchestration_integrity_score'):
            conf[score_field] = 0.84
        for score_field in ('resource_efficiency_score','cleanup_reliability_score','rollback_integrity_score','recovery_completeness_score'):
            conf[score_field] = 0.86
    return conf

@dataclass
class IterationScoreProfile:
    scores: dict[str, float] = field(default_factory=base_scores)
    confidence: dict[str, float] = field(default_factory=base_confidence)
    events: list[ScorePenalty] = field(default_factory=list)

    def penalize(self, event: ScorePenalty) -> None:
        field_name = _penalty_event_field(event)
        if field_name == "":
            raw_field = event.field if type(event) is ScorePenalty else ""
            field_text = _score_field_text(raw_field) or "<unavailable>"
            raise KeyError("unknown score field: " + field_text)
        if type(self.scores) is not dict:
            self.scores = base_scores()
        if type(self.confidence) is not dict:
            self.confidence = base_confidence()
        penalty = _penalty_event_penalty(event)
        self.scores[field_name] = clamp_score(_score_value(self.scores, field_name) - penalty)
        confidence = _confidence_value(self.confidence, field_name)
        self.confidence[field_name] = max(0.45, round(confidence - min(0.25, penalty / 20.0), 3))
        self.events.append(event)

    def aggregate(self) -> float:
        score_values = tuple(_score_value(self.scores, field_name) for field_name in SCORE_FIELDS)
        worst = min(score_values)
        mean = sum(score_values) / max(1, len(score_values))
        return clamp_score(min(mean, worst + 1.75))

    def as_record_fields(self) -> dict[str, object]:
        return {
            'scores': {field_name: _score_value(self.scores, field_name) for field_name in SCORE_FIELDS},
            'confidence': {field_name: _confidence_value(self.confidence, field_name) for field_name in SCORE_FIELDS},
            'score_events': [asdict(event) for event in self.events],
            'aggregate_score': self.aggregate(),
        }
