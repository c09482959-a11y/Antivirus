"""Detection-owned publication request builder.

Scoring remains pure and detection does not mutate runtime graph/model state.
This module converts a finalized detection decision into immutable publication
requests that downstream JSON/replay/publication owners can record or consume.
"""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.profiles.selection import DETECTION_PROFILE_NAMES, canonical_profile_name
from Virus_Scan.detection.contracts.probability import safe_clamp


PublicationValue = object
PublicationRecord = dict[str, PublicationValue]


def _publication_text(value: PublicationValue, *, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="publication_text_missing",
        unsupported_reason="publication_text_rejected",
    )
    if reason:
        return default
    text = text.strip()
    return text or default


def _publication_float(value: PublicationValue) -> float:
    numeric, _reason = no_hook_finite_float(
        value,
        default=0.0,
        reason="publication_numeric_rejected",
        non_finite_reason="publication_non_finite_numeric",
    )
    return numeric


def _publication_probability(value: PublicationValue) -> float:
    return safe_clamp(_publication_float(value))


def _publication_score(value: PublicationValue) -> float:
    return safe_clamp(_publication_float(value), 0.0, 100.0)


def _publication_count(value: PublicationValue) -> int:
    numeric = _publication_float(value)
    if numeric < 0.0:
        return 0
    return int(numeric)


def _node_text(node: PublicationValue, path: PublicationValue) -> str:
    node_text = _publication_text(node)
    if node_text:
        return node_text
    path_text = _publication_text(path)
    return path_text or "<unknown>"


def _api_calls_from_result(api_result: PublicationValue) -> PublicationValue:
    items = no_hook_mapping_items(api_result)
    if items is None:
        return ()
    api_map = dict(items)
    return dict.get(api_map, "api_calls", ())


def _event_count(values: PublicationValue) -> int:
    return len(no_hook_sequence_items(values))


@dataclass(frozen=True)
class GraphPublicationRequest:
    node: PublicationValue
    risk: PublicationValue
    tags: PublicationValue

    def to_record(self) -> PublicationRecord:
        risk = _publication_probability(self.risk)
        return {
            "kind": "graph_publication",
            "node": _publication_text(self.node, default="<unknown>"),
            "risk": risk,
            "tags": list(_string_tuple(self.tags)),
        }


@dataclass(frozen=True)
class LearningPublicationRequest:
    engine: PublicationValue
    path: PublicationValue
    tags: PublicationValue
    score: PublicationValue
    classification: PublicationValue
    api_calls: PublicationValue
    ordered_event_count: PublicationValue
    behavior_flow: PublicationValue
    prev_stage: PublicationValue
    curr_stage: PublicationValue

    def to_record(self) -> PublicationRecord:
        score = _publication_score(self.score)
        return {
            "kind": "learning_publication",
            "engine": _publication_text(self.engine, default="other"),
            "path": _publication_text(self.path),
            "tags": list(_string_tuple(self.tags)),
            "score": score,
            "classification": _publication_text(self.classification, default="unknown"),
            "api_calls": list(_string_tuple(self.api_calls)),
            "ordered_event_count": _publication_count(self.ordered_event_count),
            "behavior_flow": list(_string_tuple(self.behavior_flow)),
            "prev_stage": _publication_text(self.prev_stage, default="unknown"),
            "curr_stage": _publication_text(self.curr_stage, default="unknown"),
        }


def _string_tuple(values: PublicationValue, *, limit: int = 128) -> tuple[str, ...]:
    out: list[str] = []
    source = values.tags if type(values) is TagEvidence else values
    for value in no_hook_sequence_items(source)[:limit]:
        text = _publication_text(value)
        if text:
            out.append(text)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class ScoredDetectionPublicationRequest:
    """Internal request for one immutable scored-detection publication record."""

    path: PublicationValue
    node: PublicationValue
    tags: PublicationValue
    score_val: PublicationValue
    classification: str
    active_profile: str
    strings_blob: PublicationValue
    api_result: PublicationValue
    ordered_events: PublicationValue
    behavior_flow: PublicationValue
    prev_stage: PublicationValue
    curr_stage: PublicationValue


def publish_scored_detection_state(
    request: ScoredDetectionPublicationRequest,
) -> PublicationRecord:
    """Return immutable graph/learning publication requests for JSON/replay."""
    _unused_strings_blob = request.strings_blob
    tag_tuple = _string_tuple(request.tags)
    score_number = _publication_float(request.score_val)
    score = _publication_probability(score_number / 100.0)
    graph_request = GraphPublicationRequest(
        node=_node_text(request.node, request.path),
        risk=score,
        tags=tag_tuple,
    )

    learning_record = None
    learning_summary = None
    ext_l = get_scan_extension(request.path)
    noise_exts = {".tmp", ".cache", ".pyc", ".pyo", ".yarc"}
    classification_text = _publication_text(request.classification, default="unknown")
    if classification_text not in ("error", "timeout") and ext_l not in noise_exts:
        engine_for_profile = canonical_profile_name(
            _publication_text(request.active_profile, default="other")
        )
        if engine_for_profile not in DETECTION_PROFILE_NAMES:
            engine_for_profile = "other"
        api_calls = _api_calls_from_result(request.api_result)
        validation = {
            "engine": engine_for_profile,
            "extension": ext_l,
            "publication_owner": "external_json_replay_publication",
            "learning_committed_inside_detection": False,
        }
        learning_summary = {"learned": False, "promoted": False, "reason": "external_publication_request", "validation": validation}
        learning_record = LearningPublicationRequest(
            engine=engine_for_profile,
            path=_publication_text(request.path),
            tags=tag_tuple,
            score=score_number,
            classification=classification_text,
            api_calls=_string_tuple(api_calls),
            ordered_event_count=_event_count(request.ordered_events),
            behavior_flow=_string_tuple(request.behavior_flow),
            prev_stage=_publication_text(request.prev_stage, default="unknown"),
            curr_stage=_publication_text(request.curr_stage, default="unknown"),
        ).to_record()

    return {
        "graph_published": False,
        "learning_published": False,
        "publication_owner": "external_json_replay_publication",
        "graph_publication_request": graph_request.to_record(),
        "learning_publication_request": learning_record,
        "learning": learning_summary,
        "failures": [],
    }


__all__ = (
    "GraphPublicationRequest",
    "LearningPublicationRequest",
    "ScoredDetectionPublicationRequest",
    "publish_scored_detection_state",
)
