"""Neutral immutable authorization contract for online model learning.

Profiles are the sole decision factory. Model owners import only this neutral
record and therefore do not depend on the profiles package or infer learning
eligibility from verdicts, tags, booleans, or replay flags.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Final

LEARNING_DECISION_SCHEMA_VERSION: Final[str] = "profiles_learning_decision_v3"
LEARNING_DISPOSITION_ACCEPTED: Final[str] = "accepted"
LEARNING_DISPOSITION_REJECTED: Final[str] = "rejected"
LEARNING_DISPOSITION_QUARANTINED: Final[str] = "quarantined"
LEARNING_AUTHORITY_PROFILE_GATE: Final[str] = "profiles_clean_gate"
LEARNING_AUTHORITY_EXTERNAL_MALICIOUS: Final[str] = "external_malicious_label"
CANONICAL_MODEL_TARGETS: Final[tuple[str, ...]] = (
    "profile",
    "markov",
    "temporal",
    "filetype",
    "clustering",
)
_VALID_DISPOSITIONS: Final[frozenset[str]] = frozenset({
    LEARNING_DISPOSITION_ACCEPTED,
    LEARNING_DISPOSITION_REJECTED,
    LEARNING_DISPOSITION_QUARANTINED,
})
_VALID_AUTHORITIES: Final[frozenset[str]] = frozenset({
    LEARNING_AUTHORITY_PROFILE_GATE,
    LEARNING_AUTHORITY_EXTERNAL_MALICIOUS,
})
_CLEAN_VERDICTS: Final[frozenset[str]] = frozenset({
    "benign", "clean", "benign_clean", "ok",
})
_MALICIOUS_VERDICTS: Final[frozenset[str]] = frozenset({
    "malicious", "confirmed_malicious",
})
_CLEAN_INTEGRITY_STATES: Final[frozenset[str]] = frozenset({
    "clean", "complete", "untracked",
})
_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")


def _text(value: object, default: str = "") -> str:
    return str.strip(value) if type(value) is str else default


def _finite_float(value: object, default: float = 0.0) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        return default
    number = float(value)
    return number if math.isfinite(number) else default


def _nonnegative_int(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _ordered_texts(values: object) -> tuple[str, ...]:
    if type(values) not in (tuple, list, set, frozenset):
        return ()
    normalized = {
        str.strip(value).lower()
        for value in values
        if type(value) is str and str.strip(value) != ""
    }
    return tuple(sorted(normalized))


def _replay_key_payload(
    *,
    observation_id: str,
    observation_digest: str,
    engine: str,
    context_identity: tuple[tuple[str, str], ...],
    verdict: str,
    risk: float,
    scan_integrity_state: str,
    dangerous_anchor_hits: tuple[str, ...],
    triage_block_hits: tuple[str, ...],
    disposition: str,
    permitted_model_targets: tuple[str, ...],
    authority: str,
    reason: str,
    gate_version: str,
    decision_ordinal: int,
    schema_version: str,
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "observation_id": observation_id,
        "observation_digest": observation_digest,
        "engine": engine,
        "context_identity": [list(item) for item in context_identity],
        "verdict": verdict,
        "risk": risk,
        "scan_integrity_state": scan_integrity_state,
        "dangerous_anchor_hits": list(dangerous_anchor_hits),
        "triage_block_hits": list(triage_block_hits),
        "disposition": disposition,
        "permitted_model_targets": list(permitted_model_targets),
        "authority": authority,
        "reason": reason,
        "gate_version": gate_version,
        "decision_ordinal": decision_ordinal,
    }


def make_replay_key(
    *,
    observation_id: str,
    observation_digest: str,
    engine: str,
    context_identity: tuple[tuple[str, str], ...],
    verdict: str,
    risk: float,
    scan_integrity_state: str,
    dangerous_anchor_hits: tuple[str, ...],
    triage_block_hits: tuple[str, ...],
    disposition: str,
    permitted_model_targets: tuple[str, ...],
    authority: str,
    reason: str,
    gate_version: str,
    decision_ordinal: int,
    schema_version: str = LEARNING_DECISION_SCHEMA_VERSION,
) -> str:
    """Return the digest of the complete immutable authorization record."""
    payload = _replay_key_payload(
        observation_id=observation_id,
        observation_digest=observation_digest,
        engine=engine,
        context_identity=context_identity,
        verdict=verdict,
        risk=risk,
        scan_integrity_state=scan_integrity_state,
        dangerous_anchor_hits=dangerous_anchor_hits,
        triage_block_hits=triage_block_hits,
        disposition=disposition,
        permitted_model_targets=permitted_model_targets,
        authority=authority,
        reason=reason,
        gate_version=gate_version,
        decision_ordinal=decision_ordinal,
        schema_version=schema_version,
    )
    raw = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class LearningDecision:
    """One immutable, digest-bound authorization record for one observation."""

    observation_id: str
    observation_digest: str
    engine: str
    context_identity: tuple[tuple[str, str], ...]
    verdict: str
    risk: float
    scan_integrity_state: str
    dangerous_anchor_hits: tuple[str, ...]
    triage_block_hits: tuple[str, ...]
    disposition: str
    permitted_model_targets: tuple[str, ...]
    authority: str
    reason: str
    gate_version: str
    decision_ordinal: int
    replay_key: str
    schema_version: str = LEARNING_DECISION_SCHEMA_VERSION

    def authorizes(self, target: object) -> bool:
        target_text = _text(target).lower()
        return (
            self.disposition == LEARNING_DISPOSITION_ACCEPTED
            and target_text in self.permitted_model_targets
        )

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "observation_digest": self.observation_digest,
            "engine": self.engine,
            "context_identity": [list(item) for item in self.context_identity],
            "verdict": self.verdict,
            "risk": self.risk,
            "scan_integrity_state": self.scan_integrity_state,
            "dangerous_anchor_hits": list(self.dangerous_anchor_hits),
            "triage_block_hits": list(self.triage_block_hits),
            "disposition": self.disposition,
            "permitted_model_targets": list(self.permitted_model_targets),
            "authority": self.authority,
            "reason": self.reason,
            "gate_version": self.gate_version,
            "decision_ordinal": self.decision_ordinal,
            "replay_key": self.replay_key,
        }

    @classmethod
    def from_record(cls, record: object) -> "LearningDecision":
        if type(record) is not dict:
            raise ValueError("learning decision must be an object")
        schema = _text(record.get("schema_version"))
        if schema != LEARNING_DECISION_SCHEMA_VERSION:
            raise ValueError("unsupported learning decision schema")
        disposition = _text(record.get("disposition")).lower()
        if disposition not in _VALID_DISPOSITIONS:
            raise ValueError("invalid learning disposition")
        raw_targets = record.get("permitted_model_targets", ())
        if type(raw_targets) not in (tuple, list):
            raise ValueError("invalid learning targets")
        targets = tuple(_text(target).lower() for target in raw_targets)
        if (
            len(set(targets)) != len(targets)
            or any(target not in CANONICAL_MODEL_TARGETS for target in targets)
        ):
            raise ValueError("invalid learning target")
        context_rows = record.get("context_identity", ())
        if type(context_rows) not in (tuple, list):
            raise ValueError("invalid learning context identity")
        context: list[tuple[str, str]] = []
        for row in context_rows:
            if type(row) not in (tuple, list) or len(row) != 2:
                raise ValueError("invalid learning context identity")
            key, value = _text(row[0]), _text(row[1])
            if key == "" or value == "":
                raise ValueError("invalid learning context identity")
            context.append((key, value))
        decision = cls(
            observation_id=_text(record.get("observation_id")),
            observation_digest=_text(record.get("observation_digest")),
            engine=_text(record.get("engine"), "other").lower() or "other",
            context_identity=tuple(sorted(context)),
            verdict=_text(record.get("verdict")).lower(),
            risk=_finite_float(record.get("risk")),
            scan_integrity_state=_text(record.get("scan_integrity_state")),
            dangerous_anchor_hits=_ordered_texts(record.get("dangerous_anchor_hits", ())),
            triage_block_hits=_ordered_texts(record.get("triage_block_hits", ())),
            disposition=disposition,
            permitted_model_targets=targets,
            authority=_text(record.get("authority")).lower(),
            reason=_text(record.get("reason"), "unspecified"),
            gate_version=_text(record.get("gate_version")),
            decision_ordinal=_nonnegative_int(record.get("decision_ordinal")),
            replay_key=_text(record.get("replay_key")),
        )
        decision.validate()
        return decision

    def validate(self) -> bool:
        if self.schema_version != LEARNING_DECISION_SCHEMA_VERSION:
            raise ValueError("unsupported learning decision schema")
        if (
            self.observation_id == ""
            or self.engine == ""
            or self.gate_version == ""
            or self.reason == ""
            or self.authority not in _VALID_AUTHORITIES
            or len(self.observation_digest) != 64
            or len(self.replay_key) != 64
            or any(char not in _HEX_DIGITS for char in self.observation_digest)
            or any(char not in _HEX_DIGITS for char in self.replay_key)
        ):
            raise ValueError("incomplete learning decision identity")
        if (
            type(self.risk) not in (int, float)
            or isinstance(self.risk, bool)
            or not math.isfinite(float(self.risk))
        ):
            raise ValueError("invalid learning decision risk")
        if self.context_identity != tuple(sorted(set(self.context_identity))):
            raise ValueError("non-canonical learning context identity")
        if any(
            type(row) is not tuple
            or len(row) != 2
            or type(row[0]) is not str
            or type(row[1]) is not str
            or row[0] == ""
            or row[1] == ""
            for row in self.context_identity
        ):
            raise ValueError("invalid learning context identity")
        if self.dangerous_anchor_hits != _ordered_texts(self.dangerous_anchor_hits):
            raise ValueError("non-canonical dangerous anchor evidence")
        if self.triage_block_hits != _ordered_texts(self.triage_block_hits):
            raise ValueError("non-canonical triage block evidence")
        canonical_targets = tuple(
            target for target in CANONICAL_MODEL_TARGETS
            if target in self.permitted_model_targets
        )
        if self.permitted_model_targets != canonical_targets:
            raise ValueError("non-canonical learning target order")
        expected = make_replay_key(
            observation_id=self.observation_id,
            observation_digest=self.observation_digest,
            engine=self.engine,
            context_identity=self.context_identity,
            verdict=self.verdict,
            risk=self.risk,
            scan_integrity_state=self.scan_integrity_state,
            dangerous_anchor_hits=self.dangerous_anchor_hits,
            triage_block_hits=self.triage_block_hits,
            disposition=self.disposition,
            permitted_model_targets=self.permitted_model_targets,
            authority=self.authority,
            reason=self.reason,
            gate_version=self.gate_version,
            decision_ordinal=self.decision_ordinal,
            schema_version=self.schema_version,
        )
        if expected != self.replay_key:
            raise ValueError("learning decision replay key mismatch")
        if self.disposition not in _VALID_DISPOSITIONS:
            raise ValueError("invalid learning disposition")
        if self.disposition != LEARNING_DISPOSITION_ACCEPTED and self.permitted_model_targets:
            raise ValueError("non-accepted decision cannot authorize targets")
        if self.disposition == LEARNING_DISPOSITION_ACCEPTED:
            if not self.context_identity:
                raise ValueError("accepted decision requires context identity")
            if self.scan_integrity_state not in _CLEAN_INTEGRITY_STATES:
                raise ValueError("degraded integrity cannot authorize learning")
            if not self.permitted_model_targets:
                raise ValueError("accepted decision requires at least one target")
            if self.authority == LEARNING_AUTHORITY_PROFILE_GATE:
                if self.dangerous_anchor_hits or self.triage_block_hits:
                    raise ValueError("unsafe evidence cannot authorize clean learning")
                if self.verdict not in _CLEAN_VERDICTS:
                    raise ValueError("non-clean verdict cannot authorize profile learning")
            elif self.authority == LEARNING_AUTHORITY_EXTERNAL_MALICIOUS:
                if self.verdict not in _MALICIOUS_VERDICTS:
                    raise ValueError("external malicious authority requires malicious verdict")
                if self.permitted_model_targets != ("clustering",):
                    raise ValueError("external malicious authority is clustering-only")
        return True


def learning_authorization_failure(decision: object, target: object) -> str | None:
    """Return an explicit reason when an exact decision cannot authorize target."""
    if type(decision) is not LearningDecision:
        return "learning_decision_required"
    try:
        decision.validate()
    except ValueError:
        return "learning_decision_invalid"
    target_text = _text(target).lower()
    if target_text not in CANONICAL_MODEL_TARGETS:
        return "learning_target_invalid"
    if not decision.authorizes(target_text):
        return "learning_target_not_authorized"
    return None


__all__ = (
    "CANONICAL_MODEL_TARGETS",
    "LEARNING_AUTHORITY_EXTERNAL_MALICIOUS",
    "LEARNING_AUTHORITY_PROFILE_GATE",
    "LEARNING_DECISION_SCHEMA_VERSION",
    "LEARNING_DISPOSITION_ACCEPTED",
    "LEARNING_DISPOSITION_QUARANTINED",
    "LEARNING_DISPOSITION_REJECTED",
    "LearningDecision",
    "learning_authorization_failure",
    "make_replay_key",
)
