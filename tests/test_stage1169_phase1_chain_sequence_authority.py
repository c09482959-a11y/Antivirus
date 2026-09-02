from pathlib import Path

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence


def test_stage1169_only_canonical_chain_evaluator_owns_sequence_matching() -> None:
    assert not Path("Virus_Scan/detection/scoring/weighting/chain_sequence.py").exists()
    assert Path("Virus_Scan/detection/chains/execution/matching.py").exists()
    assert Path("Virus_Scan/detection/chains/execution/anchors.py").exists()


def test_stage1169_canonical_evaluator_preserves_ordered_sources_and_partial_state() -> None:
    timeline = evaluate_chain_evidence(
        ordered_events=["decode payload", "spawn process"],
        match_modes=("ordered",),
    )
    assert all(decision.candidate.order_class in {"observed_order", "partial"} for decision in timeline.decisions)
    api = evaluate_chain_evidence(
        api_calls=["InternetOpenUrl", "CreateProcess"],
        match_modes=("ordered",),
    )
    assert any(decision.candidate.order_class == "synthetic_order" for decision in api.decisions)
