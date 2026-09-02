"""Profiles-owned learning decision factory.

The immutable authorization record is neutral so downstream model owners do not
import profiles. Only this module evaluates normalized profile evidence and
constructs accepted, rejected, or quarantined decisions.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.models.contracts.learning_authority import (
    CANONICAL_MODEL_TARGETS,
    LEARNING_AUTHORITY_EXTERNAL_MALICIOUS,
    LEARNING_AUTHORITY_PROFILE_GATE,
    LEARNING_DISPOSITION_ACCEPTED,
    LEARNING_DISPOSITION_QUARANTINED,
    LEARNING_DISPOSITION_REJECTED,
    LearningDecision,
    make_replay_key,
)
from Virus_Scan.models.profiles.common import (
    profile_finite_float,
    profile_int,
    profile_mapping_get,
    profile_mapping_items,
    profile_safe_text,
)
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest


def _text(value: object, default: str = "") -> str:
    return profile_safe_text(value, replacement=default).strip()


def _ordered_texts(values: object) -> tuple[str, ...]:
    if type(values) is TagEvidence:
        values = values.tags
    if type(values) not in (tuple, list, set, frozenset):
        return ()
    out = {_text(value).lower() for value in values}
    out.discard("")
    return tuple(sorted(out))


def _sequence_texts(values: object) -> tuple[str, ...]:
    if type(values) not in (tuple, list):
        return ()
    return tuple(
        text for value in values if (text := _text(value).lower()) != ""
    )


def canonical_context_identity(validation: object) -> tuple[tuple[str, str], ...]:
    context = profile_mapping_get(validation, "contextual_engine_identity", {})
    items = profile_mapping_items(context)
    if items is None:
        return ()
    normalized: list[tuple[str, str]] = []
    for key, value in items:
        key_text = _text(key)
        if key_text == "":
            continue
        if type(value) is bool:
            value_text = "true" if value else "false"
        elif type(value) in (int, float) and not isinstance(value, bool):
            value_text = format(profile_finite_float(value, 0.0), ".17g")
        else:
            value_text = _text(value)
        if value_text != "":
            normalized.append((key_text, value_text))
    return tuple(sorted(normalized))


def _canonical_ordered_event_value(value: object) -> object:
    items = profile_mapping_items(value)
    if items is not None:
        rows: list[tuple[str, object]] = []
        for key, child in items:
            key_text = _text(key)
            if key_text == "":
                continue
            rows.append((key_text, _canonical_ordered_event_value(child)))
        rows.sort(key=lambda row: row[0])
        return {key: child for key, child in rows}
    if type(value) in (tuple, list):
        return [_canonical_ordered_event_value(child) for child in value]
    if type(value) is str:
        return str.__str__(value)
    if type(value) is bool or type(value) is int or value is None:
        return value
    if type(value) is float:
        return value if math.isfinite(value) else "nonfinite"
    return {"unavailable_type": no_hook_type_name(value)}


def _canonical_ordered_events(values: object) -> tuple[object, ...]:
    if type(values) not in (tuple, list):
        return ()
    return tuple(_canonical_ordered_event_value(value) for value in values)


def _canonical_json(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )



def content_sha256_for_path(file_path: object) -> str:
    """Return verified content identity without treating a path as content truth."""
    path_text = _text(file_path)
    if path_text == "":
        return ""
    digest = hashlib.sha256()
    try:
        with Path(path_text).open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()

def observation_digest(
    *,
    engine: object,
    file_path: object,
    content_sha256: object = None,
    verdict: object,
    risk: object,
    tags: object,
    yara_hits: object,
    behavior_flow: object,
    ordered_events: object,
    previous_stage: object,
    current_stage: object,
    scan_integrity: object,
    context_identity: object,
) -> str:
    """Return the canonical SHA-256 digest for normalized learning evidence."""
    integrity_items = profile_mapping_items(scan_integrity)
    integrity = {}
    if integrity_items is not None:
        for key, value in integrity_items:
            key_text = _text(key)
            if key_text == "":
                continue
            if type(value) in (str, int, float, bool) or value is None:
                if type(value) is float and not math.isfinite(value):
                    integrity[key_text] = "nonfinite"
                else:
                    integrity[key_text] = value
            else:
                integrity[key_text] = _text(value, "unsupported")
    verified_content = (
        _text(content_sha256).lower()
        if type(content_sha256) is str
        else content_sha256_for_path(file_path)
    )
    if len(verified_content) != 64 or any(
        character not in "0123456789abcdef" for character in verified_content
    ):
        verified_content = ""
    payload = {
        "engine": _text(engine, "other").lower() or "other",
        "content_identity": (
            "sha256:" + verified_content
            if verified_content
            else "unavailable_path:" + _text(file_path)
        ),
        "verdict": _text(verdict).lower(),
        "risk": profile_finite_float(risk, 0.0),
        "tags": _ordered_texts(tags),
        "yara_hits": _ordered_texts(yara_hits),
        "behavior_flow": _sequence_texts(behavior_flow),
        "ordered_events": _canonical_ordered_events(ordered_events),
        "previous_stage": _text(previous_stage, "unknown") or "unknown",
        "current_stage": _text(current_stage, "unknown") or "unknown",
        "scan_integrity": integrity,
        "context_identity": tuple(context_identity) if type(context_identity) is tuple else (),
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def build_learning_decision(
    request: ProfileLearningGateRequest,
    *,
    observation_id: object,
    yara_hits: object,
    behavior_flow: object,
    previous_stage: object,
    current_stage: object,
    learning_allowed: bool,
    reason: object,
    validation: object,
    gate_version: object,
    decision_ordinal: object = 0,
) -> LearningDecision:
    """Build and validate the sole profiles-owned learning decision."""
    engine_text = _text(request.engine, "other").lower() or "other"
    verdict_text = _text(request.verdict).lower()
    context = canonical_context_identity(validation)
    dangerous = _ordered_texts(profile_mapping_get(validation, "dangerous_anchor_hits", ()))
    triage = _ordered_texts(profile_mapping_get(validation, "triage_block_hits", ()))
    integrity_items = profile_mapping_items(request.scan_integrity)
    if integrity_items is None or len(tuple(integrity_items)) == 0:
        integrity_state = "untracked"
    elif profile_mapping_get(request.scan_integrity, "allow_learning") is False:
        integrity_state = "degraded"
    elif any(
        profile_mapping_get(request.scan_integrity, key) is True
        for key in ("file_failed", "scan_incomplete", "had_degraded_stage")
    ):
        integrity_state = "degraded"
    else:
        integrity_state = "complete"
    safe = (
        learning_allowed is True
        and verdict_text in {"benign", "clean", "benign_clean", "ok"}
        and not dangerous
        and not triage
        and integrity_state in {"untracked", "complete"}
        and bool(context)
    )
    if safe:
        disposition = LEARNING_DISPOSITION_ACCEPTED
        targets = ("profile", "clustering")
        normalized_flow = _sequence_texts(behavior_flow)
        if normalized_flow:
            targets += ("temporal", "filetype")
        if len(normalized_flow) >= 2:
            targets += ("markov",)
        targets = tuple(target for target in CANONICAL_MODEL_TARGETS if target in targets)
    elif dangerous or triage or integrity_state == "degraded" or not context:
        disposition = LEARNING_DISPOSITION_QUARANTINED
        targets = ()
    else:
        disposition = LEARNING_DISPOSITION_REJECTED
        targets = ()
    digest = observation_digest(
        engine=engine_text,
        file_path=request.file_path,
        content_sha256=content_sha256_for_path(request.file_path),
        verdict=verdict_text,
        risk=request.risk,
        tags=request.tags,
        yara_hits=yara_hits,
        behavior_flow=behavior_flow,
        ordered_events=request.ordered_events,
        previous_stage=previous_stage,
        current_stage=current_stage,
        scan_integrity=request.scan_integrity,
        context_identity=context,
    )
    observation_text = _text(observation_id) or digest
    ordinal = max(0, profile_int(decision_ordinal, 0))
    gate_text = _text(gate_version, "profiles_learning_gate")
    risk_value = profile_finite_float(request.risk, 0.0)
    if dangerous:
        reason_text = "dangerous_anchor_learning_blocked"
    elif triage:
        reason_text = "triage_learning_blocked"
    elif integrity_state == "degraded":
        reason_text = "scan_integrity_degraded"
    elif not context:
        reason_text = "learning_context_unavailable"
    else:
        reason_text = _text(reason, "unspecified")
    replay_key = make_replay_key(
        observation_id=observation_text,
        observation_digest=digest,
        engine=engine_text,
        context_identity=context,
        verdict=verdict_text,
        risk=risk_value,
        scan_integrity_state=integrity_state,
        dangerous_anchor_hits=dangerous,
        triage_block_hits=triage,
        disposition=disposition,
        permitted_model_targets=targets,
        authority=LEARNING_AUTHORITY_PROFILE_GATE,
        reason=reason_text,
        gate_version=gate_text,
        decision_ordinal=ordinal,
    )
    decision = LearningDecision(
        observation_id=observation_text,
        observation_digest=digest,
        engine=engine_text,
        context_identity=context,
        verdict=verdict_text,
        risk=risk_value,
        scan_integrity_state=integrity_state,
        dangerous_anchor_hits=dangerous,
        triage_block_hits=triage,
        disposition=disposition,
        permitted_model_targets=targets,
        authority=LEARNING_AUTHORITY_PROFILE_GATE,
        reason=reason_text,
        gate_version=gate_text,
        decision_ordinal=ordinal,
        replay_key=replay_key,
    )
    decision.validate()
    return decision


def build_external_malicious_clustering_decision(
    *,
    observation_id: object,
    observation_digest_value: object,
    engine: object,
    context_identity: object,
    label_source: object,
    decision_ordinal: object = 0,
    verdict: object = "confirmed_malicious",
    risk: object = 1.0,
    scan_integrity_state: object = "complete",
) -> LearningDecision:
    """Build one externally verified, clustering-only malicious authority record."""
    observation_text = _text(observation_id)
    digest_text = _text(observation_digest_value).lower()
    engine_text = _text(engine, "other").lower() or "other"
    source_text = _text(label_source).lower()
    verdict_text = _text(verdict).lower()
    integrity_text = _text(scan_integrity_state).lower()
    if type(context_identity) not in (tuple, list):
        raise ValueError("external malicious context identity required")
    context_rows: list[tuple[str, str]] = []
    for row in context_identity:
        if type(row) not in (tuple, list) or len(row) != 2:
            raise ValueError("external malicious context identity invalid")
        key, value = _text(row[0]), _text(row[1])
        if key == "" or value == "":
            raise ValueError("external malicious context identity invalid")
        context_rows.append((key, value))
    if source_text == "":
        raise ValueError("external malicious label source required")
    context = tuple(sorted(set((*context_rows, ("external_label_source", source_text)))))
    ordinal = max(0, profile_int(decision_ordinal, 0))
    risk_value = profile_finite_float(risk, 1.0)
    reason_text = "external_malicious_label:" + source_text
    replay_key = make_replay_key(
        observation_id=observation_text,
        observation_digest=digest_text,
        engine=engine_text,
        context_identity=context,
        verdict=verdict_text,
        risk=risk_value,
        scan_integrity_state=integrity_text,
        dangerous_anchor_hits=(),
        triage_block_hits=(),
        disposition=LEARNING_DISPOSITION_ACCEPTED,
        permitted_model_targets=("clustering",),
        authority=LEARNING_AUTHORITY_EXTERNAL_MALICIOUS,
        reason=reason_text,
        gate_version="external_malicious_label_gate_v1",
        decision_ordinal=ordinal,
    )
    decision = LearningDecision(
        observation_id=observation_text,
        observation_digest=digest_text,
        engine=engine_text,
        context_identity=context,
        verdict=verdict_text,
        risk=risk_value,
        scan_integrity_state=integrity_text,
        dangerous_anchor_hits=(),
        triage_block_hits=(),
        disposition=LEARNING_DISPOSITION_ACCEPTED,
        permitted_model_targets=("clustering",),
        authority=LEARNING_AUTHORITY_EXTERNAL_MALICIOUS,
        reason=reason_text,
        gate_version="external_malicious_label_gate_v1",
        decision_ordinal=ordinal,
        replay_key=replay_key,
    )
    decision.validate()
    return decision


__all__ = (
    "content_sha256_for_path",
    "build_external_malicious_clustering_decision",
    "build_learning_decision",
    "canonical_context_identity",
    "observation_digest",
)
