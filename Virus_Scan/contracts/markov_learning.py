"""Immutable canonical contract for context-conditioned Markov learning.

Profiles remain the sole learning-decision factory.  The Markov owner converts
one validated profiles decision into this exact request, and runtime model state
applies the request atomically at most once.  No scanner verdict, replay flag, or
caller boolean can independently authorize mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Final

MARKOV_LEARNING_REQUEST_SCHEMA: Final[str] = "markov_learning_request_v2"
MARKOV_STATE_SCHEMA_VERSION: Final[int] = 2
MARKOV_MODEL_VERSION: Final[str] = "markov_contextual_dirichlet_v2"
MARKOV_SMOOTHING_NAME: Final[str] = "jeffreys_dirichlet"
MARKOV_SMOOTHING_ALPHA: Final[float] = 0.5
MARKOV_UNSEEN_BUCKET_COUNT: Final[int] = 1
MARKOV_MINIMUM_SUPPORT: Final[int] = 3

MARKOV_DISPOSITION_TRUSTED_BENIGN: Final[str] = "trusted_benign"
MARKOV_DISPOSITION_EXTERNALLY_LABELED_MALICIOUS: Final[str] = (
    "externally_labeled_malicious"
)
MARKOV_DISPOSITION_UNKNOWN: Final[str] = "unknown"
MARKOV_DISPOSITION_REJECTED: Final[str] = "rejected"
MARKOV_LEARNING_DISPOSITIONS: Final[frozenset[str]] = frozenset(
    {
        MARKOV_DISPOSITION_TRUSTED_BENIGN,
        MARKOV_DISPOSITION_EXTERNALLY_LABELED_MALICIOUS,
        MARKOV_DISPOSITION_UNKNOWN,
        MARKOV_DISPOSITION_REJECTED,
    }
)

MARKOV_CONTEXT_EXACT: Final[str] = "exact"
MARKOV_CONTEXT_ENGINE: Final[str] = "engine"
MARKOV_CONTEXT_GLOBAL: Final[str] = "global"
MARKOV_CONTEXT_LEVELS: Final[tuple[str, ...]] = (
    MARKOV_CONTEXT_EXACT,
    MARKOV_CONTEXT_ENGINE,
    MARKOV_CONTEXT_GLOBAL,
)

MARKOV_EVENT_KEY_TYPE: Final[str] = "markov_event_v2"
MARKOV_STAGE_KEY_TYPE: Final[str] = "markov_stage_v2"
MARKOV_CONTEXT_SUPPORT_KEY_TYPE: Final[str] = "markov_context_support_v2"
MARKOV_EVENT_VOCABULARY_KEY_TYPE: Final[str] = "markov_event_vocabulary_v2"
MARKOV_STAGE_VOCABULARY_KEY_TYPE: Final[str] = "markov_stage_vocabulary_v2"

_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _sha256_record(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise ValueError(field_name + " invalid")
    text = str.strip(str.__str__(value))
    if text == "":
        raise ValueError(field_name + " invalid")
    return text


def _canonical_context_identity(value: object) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple:
        raise ValueError("markov context identity invalid")
    rows: list[tuple[str, str]] = []
    for row in value:
        if type(row) is not tuple or len(row) != 2:
            raise ValueError("markov context identity invalid")
        key = _required_text(row[0], "markov context key")
        item = _required_text(row[1], "markov context value")
        rows.append((key, item))
    canonical = tuple(sorted(set(rows)))
    if canonical != value or not canonical:
        raise ValueError("markov context identity noncanonical")
    return canonical


def _canonical_flow(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValueError("markov behavior flow invalid")
    flow = tuple(_required_text(item, "markov behavior event") for item in value)
    if len(flow) < 2 or len(flow) > 32:
        raise ValueError("markov behavior flow invalid")
    if any(left == right for left, right in zip(flow, flow[1:], strict=False)):
        raise ValueError("markov behavior flow noncanonical")
    return flow


def _context_value(
    context_identity: tuple[tuple[str, str], ...], *names: str
) -> str:
    for name in names:
        for key, value in context_identity:
            if key == name and value != "":
                return value
    return ""


def _exact_context_key(
    context_identity: tuple[tuple[str, str], ...], engine: str
) -> str:
    preferred = _context_value(
        context_identity,
        "learning_baseline_key",
        "baseline_key",
        "contextual_baseline",
        "container_extension_baseline",
        "extension_baseline",
    )
    cohort = _context_value(
        context_identity,
        "effective_analysis_engine",
        "artifact_engine",
        "container_engine",
    )
    identity_digest = _sha256_record(context_identity)
    readable = preferred or cohort or engine
    return "exact:" + readable + ":" + identity_digest


def _engine_context_key(
    context_identity: tuple[tuple[str, str], ...], engine: str
) -> str:
    family = _context_value(
        context_identity,
        "container_engine",
        "artifact_engine",
        "effective_analysis_engine",
    )
    return "engine:" + (family or engine)


def _global_context_key() -> str:
    return "global:trusted_benign"


def markov_global_context_key() -> str:
    """Return the single canonical global benign context identity."""
    return _global_context_key()


def _flow_class(flow: tuple[str, ...]) -> str:
    return "flow:" + _sha256_record(flow)


def markov_context_levels(
    *, engine: str, context_identity: tuple[tuple[str, str], ...]
) -> tuple[tuple[str, str], ...]:
    """Return canonical exact -> engine -> global Markov query levels."""
    engine_text = _required_text(engine, "markov engine")
    context = _canonical_context_identity(context_identity)
    return (
        (MARKOV_CONTEXT_EXACT, _exact_context_key(context, engine_text)),
        (MARKOV_CONTEXT_ENGINE, _engine_context_key(context, engine_text)),
        (MARKOV_CONTEXT_GLOBAL, _global_context_key()),
    )


def markov_event_transition_key(
    *, context_key: str, previous_stage: str, source_event: str
) -> tuple[str, tuple[str, str, str]]:
    return (
        MARKOV_EVENT_KEY_TYPE,
        (
            _required_text(context_key, "markov context key"),
            _required_text(previous_stage, "markov previous stage"),
            _required_text(source_event, "markov source event"),
        ),
    )


def markov_stage_transition_key(
    *, context_key: str, previous_stage: str, behavior_flow: tuple[str, ...]
) -> tuple[str, tuple[str, str, str]]:
    flow = _canonical_flow(behavior_flow)
    return (
        MARKOV_STAGE_KEY_TYPE,
        (
            _required_text(context_key, "markov context key"),
            _required_text(previous_stage, "markov previous stage"),
            _flow_class(flow),
        ),
    )


def markov_context_support_key(context_key: str) -> tuple[str, str]:
    return (
        MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
        _required_text(context_key, "markov context key"),
    )


def markov_event_vocabulary_key(context_key: str) -> tuple[str, str]:
    return (
        MARKOV_EVENT_VOCABULARY_KEY_TYPE,
        _required_text(context_key, "markov context key"),
    )


def markov_stage_vocabulary_key(context_key: str) -> tuple[str, str]:
    return (
        MARKOV_STAGE_VOCABULARY_KEY_TYPE,
        _required_text(context_key, "markov context key"),
    )


@dataclass(frozen=True, slots=True)
class MarkovUpdateRequest:
    """One digest-bound, deterministic request for a benign Markov mutation."""

    observation_id: str
    observation_digest: str
    source_record_digest: str
    previous_stage: str
    current_stage: str
    behavior_flow: tuple[str, ...]
    engine: str
    context_identity: tuple[tuple[str, str], ...]
    learning_disposition: str
    disposition_provenance: str
    gate_version: str
    decision_ordinal: int
    replay_key: str
    schema_version: str = MARKOV_LEARNING_REQUEST_SCHEMA

    def validate(self) -> bool:
        if self.schema_version != MARKOV_LEARNING_REQUEST_SCHEMA:
            raise ValueError("unsupported markov learning request schema")
        for value, name in (
            (self.observation_id, "markov observation identity"),
            (self.previous_stage, "markov previous stage"),
            (self.current_stage, "markov current stage"),
            (self.engine, "markov engine"),
            (self.disposition_provenance, "markov disposition provenance"),
            (self.gate_version, "markov gate version"),
        ):
            _required_text(value, name)
        if self.previous_stage == "unknown" or self.current_stage == "unknown":
            raise ValueError("markov stage unavailable")
        for value, name in (
            (self.observation_digest, "markov observation digest"),
            (self.source_record_digest, "markov source record digest"),
            (self.replay_key, "markov replay key"),
        ):
            digest = _required_text(value, name)
            if len(digest) != 64 or any(char not in _HEX_DIGITS for char in digest):
                raise ValueError(name + " invalid")
        if self.source_record_digest != self.observation_digest:
            raise ValueError("markov source record digest mismatch")
        if type(self.decision_ordinal) is not int or self.decision_ordinal < 0:
            raise ValueError("markov decision ordinal invalid")
        _canonical_context_identity(self.context_identity)
        _canonical_flow(self.behavior_flow)
        if self.learning_disposition not in MARKOV_LEARNING_DISPOSITIONS:
            raise ValueError("markov learning disposition invalid")
        return True

    def context_levels(self) -> tuple[tuple[str, str], ...]:
        """Return deterministic exact -> engine -> global fallback identities."""
        self.validate()
        return markov_context_levels(
            engine=self.engine,
            context_identity=self.context_identity,
        )

    def event_transition_key(
        self, context_key: str, source_event: str
    ) -> tuple[str, tuple[str, str, str]]:
        self.validate()
        return markov_event_transition_key(
            context_key=context_key,
            previous_stage=self.previous_stage,
            source_event=source_event,
        )

    def stage_transition_key(
        self, context_key: str
    ) -> tuple[str, tuple[str, str, str]]:
        self.validate()
        return markov_stage_transition_key(
            context_key=context_key,
            previous_stage=self.previous_stage,
            behavior_flow=self.behavior_flow,
        )

    def context_support_key(self, context_key: str) -> tuple[str, str]:
        return markov_context_support_key(context_key)

    def event_vocabulary_key(self, context_key: str) -> tuple[str, str]:
        return markov_event_vocabulary_key(context_key)

    def stage_vocabulary_key(self, context_key: str) -> tuple[str, str]:
        return markov_stage_vocabulary_key(context_key)

    def flow_class(self) -> str:
        self.validate()
        return _flow_class(self.behavior_flow)


__all__ = (
    "MARKOV_CONTEXT_ENGINE",
    "MARKOV_CONTEXT_EXACT",
    "MARKOV_CONTEXT_GLOBAL",
    "MARKOV_CONTEXT_LEVELS",
    "MARKOV_CONTEXT_SUPPORT_KEY_TYPE",
    "MARKOV_DISPOSITION_EXTERNALLY_LABELED_MALICIOUS",
    "MARKOV_DISPOSITION_REJECTED",
    "MARKOV_DISPOSITION_TRUSTED_BENIGN",
    "MARKOV_DISPOSITION_UNKNOWN",
    "MARKOV_EVENT_KEY_TYPE",
    "MARKOV_EVENT_VOCABULARY_KEY_TYPE",
    "MARKOV_LEARNING_REQUEST_SCHEMA",
    "MARKOV_MINIMUM_SUPPORT",
    "MARKOV_MODEL_VERSION",
    "MARKOV_SMOOTHING_ALPHA",
    "MARKOV_SMOOTHING_NAME",
    "MARKOV_STAGE_KEY_TYPE",
    "MARKOV_STAGE_VOCABULARY_KEY_TYPE",
    "MARKOV_STATE_SCHEMA_VERSION",
    "MARKOV_UNSEEN_BUCKET_COUNT",
    "MarkovUpdateRequest",
    "markov_context_levels",
    "markov_context_support_key",
    "markov_event_transition_key",
    "markov_event_vocabulary_key",
    "markov_global_context_key",
    "markov_stage_transition_key",
    "markov_stage_vocabulary_key",
)
