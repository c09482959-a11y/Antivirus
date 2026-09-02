from __future__ import annotations

from Virus_Scan.contracts.temporal_accumulator import TemporalAccumulatorState
from Virus_Scan.runtime.temporal_state import TemporalStateOwner
from Virus_Scan.tests.support.temporal_v5 import temporal_v5_event, temporal_v5_request


def _state(belief: float, support: int) -> TemporalAccumulatorState:
    return TemporalAccumulatorState(
        prior_belief=belief,
        current_observation=belief,
        observation_confidence=1.0,
        elapsed_evidence_time=0.0,
        posterior_belief=belief,
        support=support,
        maturity=1.0,
        last_evidence_timestamp=None,
        unavailable_reason=None,
    )


def _commit(
    owner: TemporalStateOwner, node: str, *, belief: float,
    decision_ordinal: int,
) -> None:
    event = temporal_v5_event(
        event_id=node + ":event", source_evidence_id=node + ":root",
        behavior_id="download", stage="runtime", source_ordinal=0,
    )
    assert owner.commit_request(temporal_v5_request(
        node_id=node, events=(event,), accumulator_state=_state(belief, 2),
        decision_ordinal=decision_ordinal,
    )) is True


def _retained_keys(owner: TemporalStateOwner) -> tuple[str, ...]:
    return tuple(owner.to_record()["nodes"])


def test_stage1346_temporal_retention_tie_breaks_by_canonical_node_key_not_insertion_order():
    nodes = (
        "stage1346-temporal-zeta",
        "stage1346-temporal-alpha",
        "stage1346-temporal-mid",
    )
    first = TemporalStateOwner()
    for node in nodes:
        _commit(first, node, belief=0.5, decision_ordinal=7)
    first.prune_for_retention(max_nodes=2, max_history_per_node=25)

    second = TemporalStateOwner()
    for node in reversed(nodes):
        _commit(second, node, belief=0.5, decision_ordinal=7)
    second.prune_for_retention(max_nodes=2, max_history_per_node=25)

    expected = (
        "stage1346-temporal-alpha",
        "stage1346-temporal-mid",
    )
    assert _retained_keys(first) == expected
    assert _retained_keys(second) == expected


def test_stage1346_temporal_retention_prefers_higher_belief_then_newer_ordinal_before_key_tie():
    owner = TemporalStateOwner()
    _commit(
        owner, "stage1346-temporal-low-belief-new",
        belief=0.25, decision_ordinal=50,
    )
    _commit(
        owner, "stage1346-temporal-high-belief-old",
        belief=0.9, decision_ordinal=1,
    )
    _commit(
        owner, "stage1346-temporal-high-belief-new-b",
        belief=0.9, decision_ordinal=9,
    )
    _commit(
        owner, "stage1346-temporal-high-belief-new-a",
        belief=0.9, decision_ordinal=9,
    )

    owner.prune_for_retention(max_nodes=2, max_history_per_node=25)

    assert _retained_keys(owner) == (
        "stage1346-temporal-high-belief-new-a",
        "stage1346-temporal-high-belief-new-b",
    )
