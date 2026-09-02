from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan import chains as root_chains
from Virus_Scan.detection.chains.composite import attack_authority, behavior_mapping
from Virus_Scan.detection.chains.execution import anchors
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_runtime_chain_event, physical_tag_evidence




def test_stage950_root_chain_exports_are_canonical_public_contracts() -> None:
    assert root_chains.chain_expected_behavior_mapping is behavior_mapping.chain_expected_behavior_mapping
    assert root_chains.has_concrete_attack_chain is attack_authority.has_concrete_attack_chain
    assert root_chains.high_gate_attack_chain_details is attack_authority.high_gate_attack_chain_details
    assert root_chains.evaluate_chain_evidence is anchors.evaluate_chain_evidence
    assert "evaluate_chain_evidence" in root_chains.__all__
    assert "detect_explicit_behavior_anchors" not in root_chains.__all__


def test_stage950_chain_identity_is_exact_and_legacy_alias_owners_are_absent() -> None:
    assert "normalize_chain_hits" not in root_chains.__all__
    assert not hasattr(root_chains, "normalize_chain_hits")
    assert not Path("Virus_Scan/detection/chains/composite/normalization.py").exists()
    assert not Path("Virus_Scan/detection/chains/composite/family_policy.py").exists()
    assert not Path("Virus_Scan/detection/registries/chain_family_defaults.py").exists()


def test_stage950_expected_behavior_mapping_is_explainable_and_fail_closed_for_unknown_chains() -> None:
    rule = root_chains.chain_rule("anchor:download_execute_chain")
    assert rule is not None
    download = root_chains.chain_expected_behavior_mapping(rule)
    assert download["chain"] == "anchor:download_execute_chain"
    assert download["role"] == "download_execute"
    assert "network/download" in download["expected_behavior"]
    assert download["pattern"][0] == ("network_download",)
    assert "process_exec" in download["pattern"][1]
    assert download["requires_concrete_behavior"] is True
    assert download["scoreable_without_linked_evidence"] is False
    with pytest.raises(TypeError, match="canonical_chain_rule_required"):
        root_chains.chain_expected_behavior_mapping("unknown_chain")


def test_stage950_ordered_timeline_and_api_calls_preserve_observed_sources() -> None:
    api = root_chains.evaluate_chain_evidence(
        api_calls=["OpenProcess", "WriteProcessMemory", "CreateRemoteThread"],
        match_modes=("ordered",),
    )
    timeline = root_chains.evaluate_chain_evidence(
        ordered_events=[
            {"event": "network_download", "timestamp": 1.0},
            {"event": "CreateProcess", "timestamp": 2.0},
        ],
        match_modes=("ordered",),
    )
    api_ids = {decision.candidate.chain_id for decision in api.candidates}
    timeline_ids = {decision.candidate.chain_id for decision in timeline.candidates}
    assert "execution.openprocess_writeprocessmemory_createremotethread" in api_ids
    assert all(decision.candidate.order_class == "synthetic_order" for decision in api.candidates)
    assert all(not decision.scoreable for decision in api.candidates)
    assert all("physical_root_unavailable" in decision.candidate.unmet_requirements for decision in api.candidates)
    assert {"execution.download_before_execution", "execution.download_execute"} <= timeline_ids
    assert all(decision.candidate.order_class == "observed_order" for decision in timeline.candidates)
    assert all(not decision.scoreable for decision in timeline.candidates)
    assert all("physical_root_unavailable" in decision.candidate.unmet_requirements for decision in timeline.candidates)

    rooted = root_chains.evaluate_chain_evidence(
        ordered_events=[
            physical_runtime_chain_event("network_download", 1.0, 0, source_detector="stage950_host_fixture"),
            physical_runtime_chain_event("CreateProcess", 2.0, 1, source_detector="stage950_host_fixture"),
        ],
        match_modes=("ordered",),
    )
    rooted_ids = {decision.candidate.chain_id for decision in rooted.confirmed}
    assert {"execution.download_before_execution", "execution.download_execute"} <= rooted_ids
    assert all(decision.candidate.physically_rooted for decision in rooted.confirmed)


def test_stage950_high_gate_rejects_unordered_cooccurrence_and_accepts_observed_api_order() -> None:
    unordered = root_chains.evaluate_chain_evidence(
        tags=physical_tag_evidence(("network_download", "process_exec"), source_detector="stage950"),
    )
    assert root_chains.has_concrete_attack_chain(unordered) is False
    allowed, details = root_chains.high_gate_attack_chain_details(unordered)
    assert allowed is False
    assert details == []
    ordered = root_chains.evaluate_chain_evidence(
        ordered_events=[
            physical_runtime_chain_event("VirtualAllocEx", 1.0, 0, source_detector="stage950_host_fixture"),
            physical_runtime_chain_event("WriteProcessMemory", 2.0, 1, source_detector="stage950_host_fixture"),
            physical_runtime_chain_event("CreateRemoteThread", 3.0, 2, source_detector="stage950_host_fixture"),
        ]
    )
    ordered_allowed, ordered_details = root_chains.high_gate_attack_chain_details(ordered)
    assert ordered_allowed is True
    assert "execution.virtualallocex_writeprocessmemory_createremotethread" in ordered_details


def test_stage950_chain_evidence_publication_is_bounded_and_provenance_rich() -> None:
    evidence = root_chains.evaluate_chain_evidence(
        tags=physical_tag_evidence(("memory_write", "thread_execution"), source_detector="stage950"),
        ordered_events=[
            physical_runtime_chain_event("WriteProcessMemory", 1.0, 0, source_detector="stage950_host_fixture"),
            physical_runtime_chain_event("CreateRemoteThread", 2.0, 1, source_detector="stage950_host_fixture"),
        ],
    )
    record = evidence.to_record()
    assert record["registry_version"] == root_chains.CHAIN_REGISTRY_VERSION
    assert record["registry_digest"] == root_chains.CHAIN_REGISTRY_DIGEST
    assert record["degraded"] is False
    process_injection = next(
        decision for decision in evidence.decisions
        if decision.candidate.chain_id == "anchor:api_process_injection"
    )
    assert process_injection.status == "confirmed"
    assert process_injection.anchor_floor == 48.0
    assert len(process_injection.candidate.distinct_root_ids) == 2
