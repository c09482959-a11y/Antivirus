from __future__ import annotations

from Virus_Scan.detection.tags.heuristics.vocabulary import canonical_tag_name as detection_canonical_tag_name
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.utils.tagging import canonical_tag_name as neutral_canonical_tag_name


def test_stage1451_profile_api_has_no_parallel_chain_classifier() -> None:
    assert "classify_chain_match" not in profile_api.__all__
    assert "detect_profile_chains" not in profile_api.__all__
    assert not hasattr(profile_api, "classify_chain_match")
    assert not hasattr(profile_api, "detect_profile_chains")
    assert neutral_canonical_tag_name("base64_decode") == "payload_decode_candidate"
    assert detection_canonical_tag_name("base64_decode") == neutral_canonical_tag_name("base64_decode")


def test_stage1451_canonical_chain_evaluator_owns_signal_matching() -> None:
    evidence = evaluate_chain_evidence(
        tags=("payload_decode_candidate", "process_exec"),
        match_modes=("anchor", "unordered"),
    )
    assert all(decision.candidate.chain_id for decision in evidence.decisions)
    assert not hasattr(profile_api, "_profile_signal_matches")
