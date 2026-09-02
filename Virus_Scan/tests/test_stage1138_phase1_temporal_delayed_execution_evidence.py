from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_runtime_chain_event, physical_tag_evidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.models.temporal.validation import compute_temporal_validation


def test_stage1138_observed_download_execution_is_owned_by_canonical_chain_evaluator() -> None:
    unrooted = evaluate_chain_evidence(
        ordered_events=(
            {"time": 100.0, "tag": "network_download"},
            {"time": 145.0, "tag": "process_exec"},
        ),
        match_modes=("ordered",),
    )
    unrooted_decision = next(
        decision for decision in unrooted.decisions
        if decision.candidate.chain_id == "execution.download_execute"
    )
    assert unrooted_decision.status == "candidate"
    assert unrooted_decision.scoreable is False
    assert "physical_root_unavailable" in unrooted_decision.candidate.unmet_requirements

    evidence = evaluate_chain_evidence(
        ordered_events=(
            physical_runtime_chain_event(
                "network_download", 100.0, 0, source_detector="stage1138_runtime_fixture",
            ),
            physical_runtime_chain_event(
                "process_exec", 145.0, 1, source_detector="stage1138_runtime_fixture",
            ),
        ),
        match_modes=("ordered",),
    )
    assert "execution.download_execute" in {decision.candidate.chain_id for decision in evidence.confirmed}
    assert all(decision.candidate.order_class == "observed_order" for decision in evidence.confirmed)
    assert all(decision.candidate.physically_rooted for decision in evidence.confirmed)


def test_stage1138_reverse_order_cannot_confirm_download_execution_chain() -> None:
    evidence = evaluate_chain_evidence(
        ordered_events=(
            {"time": 100.0, "tag": "process_exec"},
            {"time": 145.0, "tag": "network_download"},
        ),
        match_modes=("ordered",),
        rule_ids=("execution.download_execute",),
    )

    assert evidence.confirmed == ()


def test_stage1138_temporal_validation_publishes_chain_record_without_rescoring_it() -> None:
    result = compute_temporal_validation(
        "stage1138-node",
        tags=physical_tag_evidence(("network_download", "process_exec"), source_detector="stage1138"),
        prev_stage="asset",
        curr_stage="runtime",
        markov={"transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0, "sequence_anomaly": 0.0},
    )

    assert "execution.download_execute" in result["chain_identities"]
    assert result["chain_score_contribution"] == 0.0
    assert all(record["status"] in {"confirmed", "candidate", "partial", "blocked"} for record in result["chain_records"])
