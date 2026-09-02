from __future__ import annotations

import cProfile
import hashlib
import json
import os
from pathlib import Path
import pstats

from Virus_Scan.contracts.chain_evidence import ChainEvent
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.detection.api.chain_evaluation import (
    evaluate_chain_evidence_generation,
)
from Virus_Scan.detection.chains.execution.compiled_registry import (
    COMPILED_CHAIN_REGISTRY,
    COMPILED_CHAIN_REGISTRY_DIGEST,
    COMPILED_CHAIN_REGISTRY_VERSION,
    build_chain_event_index,
)
from Virus_Scan.detection.chains.execution.matching import (
    evaluate_chain_rule,
    evaluate_chain_rules,
)
from Virus_Scan.detection.registries.chain_registry import (
    CANONICAL_CHAIN_RULES,
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
)
from Virus_Scan.orchestration.scan_session import (
    build_scan_session_snapshot,
    validate_scan_session_runtime,
)
from Virus_Scan.storage import sqlite_lifecycle

_EXPECTED_PHASE14_CASE_DIGEST = "e53426f3783f23845ba879b6920cf176e86745e2cabb0d9ebb489c141bce7b21"
_EXPECTED_PHASE14_RICH_DIGEST = "e6de20afa1ba1e9f9b1ea20006de8901ca6a7c94a5332e5c0d92c2cbb133874e"


def _event(
    term: str,
    ordinal: int,
    *,
    source: str,
    root: str,
    group: str = "phase14",
    platform: str = "windows",
    modality: str = "static_structure",
    timestamp: float | None = None,
) -> ChainEvent:
    evidence_id = "chain_ev_" + hashlib.sha256(
        f"{term}:{ordinal}:{root}".encode("utf-8")
    ).hexdigest()[:32]
    return ChainEvent(
        evidence_id=evidence_id,
        root_evidence_id=root,
        term=term,
        source=source,
        ordinal=ordinal,
        timestamp=timestamp,
        correlation_group=group,
        evidence_kind="observed",
        polarity="positive",
        observation_id="obs_" + hashlib.sha256(evidence_id.encode("utf-8")).hexdigest()[:40],
        modality=modality,
        platform=platform,
        actor_identity="actor_phase14",
        target_identity="target_phase14",
        artifact_identity="artifact_phase14",
        process_identity="process_phase14",
        host_identity="host_phase14",
        connection_identity="connection_phase14",
        source_location=ObservationSourceLocation(
            "fixture", locator="phase14", event_id=evidence_id,
        ),
        timing_provenance=(
            "runtime_observed" if source == "timeline_observation" else "static_control_flow"
        ),
        integrity_status="verified",
        directness="direct",
    )


def _full_events(rule: object) -> tuple[ChainEvent, ...]:
    source = "timeline_observation" if rule.match_mode == "ordered" else "tag_evidence"
    platform = rule.required_platforms[0] if rule.required_platforms else "windows"
    modality = rule.required_modalities[0] if rule.required_modalities else "static_structure"
    return tuple(
        _event(
            step.alternatives[0],
            index,
            source=source,
            root=f"obs_root_{rule.chain_id}_{index}",
            group="group_" + rule.chain_id,
            platform=platform,
            modality=modality,
            timestamp=float(index) if source == "timeline_observation" else None,
        )
        for index, step in enumerate(rule.steps)
    )


def _decision_record(decision: object) -> object:
    return None if decision is None else decision.to_record()


def _phase14_cases() -> tuple[dict[str, object], ...]:
    cases: list[dict[str, object]] = []
    for rule in CANONICAL_CHAIN_RULES:
        full = _full_events(rule)
        cases.append({
            "case_id": rule.chain_id + ":full",
            "rule_id": rule.chain_id,
            "events": tuple(event.to_record() for event in full),
            "decision": _decision_record(evaluate_chain_rule(rule, full)),
        })
        required = tuple(index for index, step in enumerate(rule.steps) if not step.optional)
        if len(required) >= 3:
            omitted = required[-1]
            partial = tuple(event for index, event in enumerate(full) if index != omitted)
            cases.append({
                "case_id": rule.chain_id + ":partial",
                "rule_id": rule.chain_id,
                "events": tuple(event.to_record() for event in partial),
                "decision": _decision_record(evaluate_chain_rule(rule, partial)),
            })
        if rule.forbidden_evidence:
            forbidden = (*full, _event(
                rule.forbidden_evidence[0],
                len(full),
                source="tag_evidence",
                root=f"obs_root_{rule.chain_id}_forbidden",
                group="group_" + rule.chain_id,
            ))
            cases.append({
                "case_id": rule.chain_id + ":forbidden",
                "rule_id": rule.chain_id,
                "events": tuple(event.to_record() for event in forbidden),
                "decision": _decision_record(evaluate_chain_rule(rule, forbidden)),
            })
        same_root = tuple(
            _event(
                event.term,
                event.ordinal,
                source=event.source,
                root="obs_root_shared_" + rule.chain_id,
                group=event.correlation_group,
                platform=event.platform,
                modality=event.modality,
                timestamp=event.timestamp,
            )
            for event in full
        )
        cases.append({
            "case_id": rule.chain_id + ":same_root",
            "rule_id": rule.chain_id,
            "events": tuple(event.to_record() for event in same_root),
            "decision": _decision_record(evaluate_chain_rule(rule, same_root)),
        })
    return tuple(cases)


def _rich_events() -> tuple[ChainEvent, ...]:
    terms: list[str] = []
    for rule in CANONICAL_CHAIN_RULES:
        for step in rule.steps:
            for alternative in step.alternatives:
                if alternative not in terms:
                    terms.append(alternative)
    return tuple(
        _event(
            term,
            index,
            source="tag_evidence",
            root=f"obs_rich_root_{index}",
            group="rich_group",
        )
        for index, term in enumerate(terms)
    )


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def test_phase14_compiled_registry_is_exactly_bound_to_all_source_rules() -> None:
    registry = COMPILED_CHAIN_REGISTRY
    assert registry.source_version == CHAIN_REGISTRY_VERSION
    assert registry.source_digest == CHAIN_REGISTRY_DIGEST
    assert registry.version == COMPILED_CHAIN_REGISTRY_VERSION
    assert registry.digest == COMPILED_CHAIN_REGISTRY_DIGEST
    assert len(registry.rules) == len(CANONICAL_CHAIN_RULES) == 164
    assert tuple(rule.chain_id for rule in registry.rules) == tuple(
        rule.chain_id for rule in CANONICAL_CHAIN_RULES
    )
    assert all(rule.steps for rule in registry.rules)
    assert all(step.digest for rule in registry.rules for step in rule.steps)
    assert registry.rule_ids_by_mode["anchor"]
    assert registry.rule_ids_by_mode["ordered"]
    assert registry.rule_ids_by_mode["unordered"]


def test_phase14_all_585_rule_cases_and_rich_decisions_are_semantically_exact() -> None:
    cases = _phase14_cases()
    assert len(cases) == 585
    assert _digest(cases) == _EXPECTED_PHASE14_CASE_DIGEST

    decisions = evaluate_chain_rules(CANONICAL_CHAIN_RULES, _rich_events())
    assert len(decisions) == 163
    assert _digest(tuple(decision.to_record() for decision in decisions)) == _EXPECTED_PHASE14_RICH_DIGEST


def test_phase14_generation_event_index_tokenizes_once_and_prunes_unreachable_rules() -> None:
    rich = _rich_events()
    index = build_chain_event_index(rich, COMPILED_CHAIN_REGISTRY.rules)
    assert len(index.indexed_events) == len(rich)
    assert len(index.candidate_rule_ids) == 164
    assert all(item.tokens for item in index.indexed_events)

    sparse = (_event("network_download", 0, source="timeline", root="one"),)
    sparse_index = build_chain_event_index(sparse, COMPILED_CHAIN_REGISTRY.rules)
    assert 0 < len(sparse_index.candidate_rule_ids) < 164


def test_phase14_profile_eliminates_per_rule_retokenization() -> None:
    profile = cProfile.Profile()
    rich = _rich_events()
    profile.enable()
    for _ in range(3):
        evaluate_chain_rules(CANONICAL_CHAIN_RULES, rich)
    profile.disable()
    stats = pstats.Stats(profile)
    token_calls = sum(
        total_calls
        for (_filename, _line, name), (_primitive, total_calls, _self, _cumulative, _callers)
        in stats.stats.items()
        if name == "tokenize_chain_term"
    )
    legacy_token_calls = sum(
        total_calls
        for (_filename, _line, name), (_primitive, total_calls, _self, _cumulative, _callers)
        in stats.stats.items()
        if name in {"_tokens", "_term_matches"}
    )
    assert token_calls == len(rich) * 3
    assert legacy_token_calls == 0


def test_phase14_incremental_generation_reuses_only_unaffected_rules() -> None:
    selected = ("execution.certutil_download", "execution.certutil_download_decode")
    initial = evaluate_chain_evidence_generation(
        ordered_events=(
            {"event": "certutil", "timestamp": 1.0},
            {"event": "network_download", "timestamp": 2.0},
        ),
        rule_ids=selected,
    )
    incremental = evaluate_chain_evidence_generation(
        ordered_events=(
            {"event": "certutil", "timestamp": 1.0},
            {"event": "network_download", "timestamp": 2.0},
            {"event": "decode", "timestamp": 3.0},
        ),
        rule_ids=selected,
        previous_generation=initial,
    )
    complete = evaluate_chain_evidence_generation(
        ordered_events=(
            {"event": "certutil", "timestamp": 1.0},
            {"event": "network_download", "timestamp": 2.0},
            {"event": "decode", "timestamp": 3.0},
        ),
        rule_ids=selected,
    )
    assert incremental.evidence.to_record() == complete.evidence.to_record()
    assert incremental.reused_rule_ids == ("execution.certutil_download",)
    assert incremental.evaluated_rule_ids == ("execution.certutil_download_decode",)
    assert incremental.full_recompute_reason == ""


def test_phase14_forbidden_evidence_invalidates_and_blocks_the_affected_rule() -> None:
    selected = ("admin_share_propagation_chain",)
    base_events = (
        {"event": "credential_access"},
        {"event": "admin_share_access"},
        {"event": "remote_service_creation"},
        {"event": "process_exec"},
    )
    initial = evaluate_chain_evidence_generation(api_calls=base_events, rule_ids=selected)
    blocked = evaluate_chain_evidence_generation(
        api_calls=(*base_events, {"event": "suppression", "evidence_kind": "suppression"}),
        rule_ids=selected,
        previous_generation=initial,
    )
    complete = evaluate_chain_evidence_generation(
        api_calls=(*base_events, {"event": "suppression", "evidence_kind": "suppression"}),
        rule_ids=selected,
    )
    assert blocked.evidence.to_record() == complete.evidence.to_record()
    assert blocked.evaluated_rule_ids == selected
    assert blocked.reused_rule_ids == ()
    assert blocked.evidence.decisions[0].status == "blocked"
    assert blocked.evidence.decisions[0].scoreable is False


def test_phase14_non_monotonic_generation_forces_complete_recomputation() -> None:
    selected = ("execution.download_execute",)
    initial = evaluate_chain_evidence_generation(
        ordered_events=(
            {"event": "network_download", "timestamp": 1.0},
            {"event": "process_exec", "timestamp": 2.0},
        ),
        rule_ids=selected,
    )
    reduced = evaluate_chain_evidence_generation(
        ordered_events=({"event": "process_exec", "timestamp": 2.0},),
        rule_ids=selected,
        previous_generation=initial,
    )
    complete = evaluate_chain_evidence_generation(
        ordered_events=({"event": "process_exec", "timestamp": 2.0},),
        rule_ids=selected,
    )
    assert reduced.full_recompute_reason == "non_monotonic_evidence"
    assert reduced.evaluated_rule_ids == selected
    assert reduced.reused_rule_ids == ()
    assert reduced.evidence.to_record() == complete.evidence.to_record()


def test_phase14_scan_session_binds_and_validates_compiled_matcher_identity(
    tmp_path: Path,
) -> None:
    previous_base_dir = os.environ.get("UMIGE_BASE_DIR")
    os.environ["UMIGE_BASE_DIR"] = str(tmp_path / "runtime")
    try:
        snapshot = build_scan_session_snapshot(
            compiled_rules=None,
            yara_enabled=False,
            scan_mode="serial",
            worker_count=1,
        )
        matcher = next(
            item for item in snapshot.subsystem_states if item.name == "chain_matcher"
        )
        assert matcher.state == "available"
        assert matcher.identity_digest == COMPILED_CHAIN_REGISTRY_DIGEST
        assert matcher.reason == ""
        assert validate_scan_session_runtime(snapshot) is snapshot
    finally:
        sqlite_lifecycle().close()
        if previous_base_dir is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous_base_dir
