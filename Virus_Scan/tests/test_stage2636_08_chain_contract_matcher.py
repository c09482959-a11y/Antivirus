from __future__ import annotations

import pytest

from Virus_Scan.contracts.chain_evidence import ChainEvent, ChainRule, ChainStep
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.detection.chains.execution.matching import evaluate_chain_rule


def _rule(
    *,
    chain_id: str = "test_chain",
    match_mode: str = "ordered",
    terms: tuple[str, ...] = ("download", "execute"),
    minimum_distinct_roots: int = 2,
    forbidden: tuple[str, ...] = (),
    maximum_time_gap: float | None = None,
) -> ChainRule:
    return ChainRule(
        chain_id=chain_id,
        version="v1",
        family="test",
        match_mode=match_mode,
        steps=tuple(ChainStep((term,)) for term in terms),
        minimum_distinct_roots=minimum_distinct_roots,
        confidence=0.9,
        operational_severity=70.0,
        score_points=20.0,
        anchor_floor=60.0,
        forbidden_evidence=forbidden,
        maximum_time_gap=maximum_time_gap,
        correlation_group="test",
    )


def _event(
    term: str,
    ordinal: int,
    *,
    source: str = "timeline_observation",
    root: str | None = None,
    evidence_id: str | None = None,
    timestamp: float | None = None,
    group: str = "",
    kind: str = "observed",
    polarity: str = "positive",
    unavailable_reason: str = "",
) -> ChainEvent:
    identity = evidence_id or f"ev_{ordinal}_{term}"
    root_id = root or f"obs_fixture_{ordinal}_{term}"
    if not root_id.startswith("obs_"):
        root_id = "obs_" + root_id.replace(":", "_")
    observation_id = "obs_event_" + identity.replace(":", "_")
    return ChainEvent(
        evidence_id=identity,
        root_evidence_id=root_id,
        term=term,
        source=source,
        ordinal=ordinal,
        timestamp=timestamp,
        correlation_group=group,
        evidence_kind=kind,
        polarity=polarity,
        unavailable_reason=unavailable_reason,
        observation_id=observation_id,
        artifact_identity="artifact:chain-contract-fixture",
        source_location=ObservationSourceLocation(
            "fixture_event", locator="chain-contract", event_id=identity,
        ),
        integrity_status="verified",
        directness="direct",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("confidence", 1.1),
        ("operational_severity", -1.0),
        ("score_points", float("nan")),
        ("anchor_floor", 101.0),
        ("minimum_distinct_roots", 0),
        ("maximum_time_gap", -1.0),
    ),
)
def test_chain_rule_rejects_invalid_policy_ranges(field: str, value: object) -> None:
    kwargs = {
        "chain_id": "invalid_policy",
        "version": "v1",
        "family": "test",
        "match_mode": "ordered",
        "steps": (ChainStep(("download",)), ChainStep(("execute",))),
        "minimum_distinct_roots": 2,
        "confidence": 0.9,
        "operational_severity": 70.0,
        "score_points": 20.0,
        "anchor_floor": 60.0,
        "maximum_time_gap": 10.0,
    }
    kwargs[field] = value
    with pytest.raises(ValueError):
        ChainRule(**kwargs)


def test_api_sequence_is_synthetic_candidate_not_confirmed_order() -> None:
    decision = evaluate_chain_rule(
        _rule(),
        (
            _event("download", 0, source="api_calls"),
            _event("execute", 1, source="api_calls"),
        ),
    )
    assert decision is not None
    assert decision.status == "candidate"
    assert decision.candidate.order_class == "synthetic_order"


def test_observed_timeline_with_verified_timing_is_confirmed() -> None:
    decision = evaluate_chain_rule(
        _rule(maximum_time_gap=5.0),
        (
            _event("download", 0, timestamp=10.0),
            _event("execute", 1, timestamp=12.0),
        ),
    )
    assert decision is not None
    assert decision.status == "confirmed"
    assert decision.candidate.order_class == "observed_order"


def test_timed_rule_without_timestamps_remains_candidate() -> None:
    decision = evaluate_chain_rule(
        _rule(maximum_time_gap=5.0),
        (_event("download", 0), _event("execute", 1)),
    )
    assert decision is not None
    assert decision.status == "candidate"
    assert decision.candidate.order_class == "observed_order"


def test_anchor_requires_same_nonempty_correlation_group_for_causal_link() -> None:
    rule = _rule(match_mode="anchor")
    ungrouped = evaluate_chain_rule(
        rule,
        (_event("download", 0, group="shared"), _event("execute", 1, group="")),
    )
    linked = evaluate_chain_rule(
        rule,
        (_event("download", 0, group="shared"), _event("execute", 1, group="shared")),
    )
    assert ungrouped is not None and ungrouped.status == "candidate"
    assert ungrouped.candidate.order_class == "unordered_correlation"
    assert linked is not None and linked.status == "confirmed"
    assert linked.candidate.order_class == "causal_link"


def test_negative_or_suppression_evidence_cannot_satisfy_positive_step() -> None:
    rule = _rule()
    for event in (
        _event("download", 0, polarity="negative"),
        _event("download", 0, kind="suppression"),
        _event("download", 0, unavailable_reason="source_unavailable"),
    ):
        decision = evaluate_chain_rule(rule, (event, _event("execute", 1)))
        assert decision is None


def test_forbidden_context_blocks_only_a_meaningful_match() -> None:
    rule = _rule(forbidden=("benign_updater",))
    forbidden = _event("benign_updater", 2, polarity="negative", kind="suppression")
    assert evaluate_chain_rule(rule, (forbidden,)) is None
    decision = evaluate_chain_rule(
        rule,
        (_event("download", 0), _event("execute", 1), forbidden),
    )
    assert decision is not None
    assert decision.status == "blocked"
    assert not decision.scoreable


def test_partial_requires_two_distinct_roots() -> None:
    rule = _rule(terms=("download", "write", "execute"), minimum_distinct_roots=3)
    one = evaluate_chain_rule(rule, (_event("download", 0),))
    two_same_root = evaluate_chain_rule(
        rule,
        (
            _event("download", 0, root="obs_same"),
            _event("write", 1, root="obs_same"),
        ),
    )
    two = evaluate_chain_rule(rule, (_event("download", 0), _event("write", 1)))
    assert one is None
    assert two_same_root is None
    assert two is not None and two.status == "partial"


def test_ordered_best_match_uses_earliest_deterministic_evidence() -> None:
    decision = evaluate_chain_rule(
        _rule(),
        (
            _event("download", 0, evidence_id="z_download"),
            _event("download", 0, evidence_id="a_download"),
            _event("execute", 1, evidence_id="execute"),
        ),
    )
    assert decision is not None
    assert decision.candidate.matched_steps[0].event.evidence_id == "a_download"


def test_chain_event_rejects_nonfinite_or_non_numeric_timestamp() -> None:
    for value in (float("nan"), float("inf"), "12.0", True):
        with pytest.raises(ValueError, match="chain_event_timestamp_invalid"):
            _event("download", 0, timestamp=value)  # type: ignore[arg-type]


def test_mapping_event_publishes_malformed_timestamp_failure() -> None:
    evidence = evaluate_chain_evidence(
        ordered_events=(
            {"event": "network_download", "timestamp": "invalid"},
            {"event": "process_exec", "timestamp": 2.0},
        ),
        match_modes=("ordered",),
    )
    assert any(
        failure.get("reason") == "chain_event_timestamp_invalid"
        for failure in evidence.failures
    )
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "execution.download_execute"
    )
    assert decision.status == "candidate"
    assert decision.anchor_floor == 0.0
