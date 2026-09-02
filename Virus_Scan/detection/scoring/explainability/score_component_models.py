"""Immutable scoring explanation component records."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text, no_hook_type_name


def _component_text(value: object, default: str, reason: str) -> str:
    text, unavailable_reason = no_hook_text(
        value,
        missing_reason="missing_score_component_text",
        unsupported_reason=reason,
    )
    if unavailable_reason:
        return default
    stripped = text.strip()
    return stripped or default


def _component_field_reason(prefix: str, field_name: str, suffix: str = "") -> str:
    field_text, reason = no_hook_text(
        field_name,
        missing_reason="score_component_field_missing",
        unsupported_reason="score_component_field_rejected",
    )
    field = "field" if reason else field_text.strip()
    return prefix + field + suffix


def _component_float(value: object, field_name: str) -> float:
    metric, _reason = no_hook_finite_float(
        value,
        default=0.0,
        reason=_component_field_reason("unsafe_score_contribution_", field_name, "_rejected"),
        non_finite_reason=_component_field_reason("nonfinite_score_contribution_", field_name),
        allow_exact_text=True,
    )
    return metric


def _component_evidence_items(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if type(value) is tuple:
        items = tuple(value)
    elif type(value) is list:
        items = tuple(value)
    elif type(value) is set:
        items = tuple(sorted(set.__iter__(value), key=no_hook_type_name))
    elif type(value) is frozenset:
        items = tuple(sorted(frozenset.__iter__(value), key=no_hook_type_name))
    else:
        items = (value,)
    out: list[str] = []
    for item in items:
        text, reason = no_hook_text(
            item,
            missing_reason="missing_score_contribution_evidence_reference",
            unsupported_reason="unsupported_score_contribution_evidence_reference",
        )
        if reason:
            out.append(reason + ":" + no_hook_type_name(item))
        elif text:
            out.append(text)
    return tuple(out)


@dataclass(frozen=True)
class ScoreContribution:
    """Single reproducible score contribution with required audit context."""

    score_source: str
    weight: float
    raw_score: float
    weighted_score: float
    evidence_reference: tuple[str, ...]
    reason: str
    engine_context: str
    filetype_context: str
    confidence_impact: float
    malicious_contribution: float
    suspicious_contribution: float
    benign_contribution: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "score_source", _component_text(self.score_source, "", "unsafe_score_contribution_source_rejected"))
        object.__setattr__(self, "weight", _component_float(self.weight, "weight"))
        object.__setattr__(self, "raw_score", _component_float(self.raw_score, "raw_score"))
        object.__setattr__(self, "weighted_score", _component_float(self.weighted_score, "weighted_score"))
        object.__setattr__(self, "evidence_reference", _component_evidence_items(self.evidence_reference))
        object.__setattr__(self, "reason", _component_text(self.reason, "", "unsafe_score_contribution_reason_rejected"))
        object.__setattr__(self, "engine_context", _component_text(self.engine_context, "", "unsafe_score_contribution_engine_context_rejected"))
        object.__setattr__(self, "filetype_context", _component_text(self.filetype_context, "", "unsafe_score_contribution_filetype_context_rejected"))
        object.__setattr__(self, "confidence_impact", _component_float(self.confidence_impact, "confidence_impact"))
        object.__setattr__(self, "malicious_contribution", _component_float(self.malicious_contribution, "malicious_contribution"))
        object.__setattr__(self, "suspicious_contribution", _component_float(self.suspicious_contribution, "suspicious_contribution"))
        object.__setattr__(self, "benign_contribution", _component_float(self.benign_contribution, "benign_contribution"))

    def to_record(self) -> dict[str, object]:
        """Return a JSON/reporting-safe component record."""
        record = asdict(self)
        record["evidence_reference"] = list(self.evidence_reference)
        return record


__all__ = ("ScoreContribution",)
