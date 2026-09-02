from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.chains.composite.attack_authority import has_concrete_attack_chain
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_runtime_chain_event


class HostileApiCalls:
    touched = 0

    def __iter__(self):
        HostileApiCalls.touched += 1
        raise RuntimeError("api call iteration must not execute")


class HostileApiCallItem:
    touched = 0

    def __str__(self):
        HostileApiCallItem.touched += 1
        raise RuntimeError("api call text must not execute")

    def __repr__(self):
        HostileApiCallItem.touched += 1
        raise RuntimeError("api call repr must not execute")


class HostileOrderedEvents:
    touched = 0

    def __iter__(self):
        HostileOrderedEvents.touched += 1
        raise RuntimeError("ordered event iteration must not execute")


def test_stage1671_attack_authority_rejects_hostile_api_call_container_without_iteration() -> None:
    HostileApiCalls.touched = 0

    result = has_concrete_attack_chain(evaluate_chain_evidence(tags=(), api_calls=HostileApiCalls(), ordered_events=()))

    assert result is False
    assert HostileApiCalls.touched == 0


def test_stage1671_attack_authority_rejects_hostile_api_call_items_without_text_hooks() -> None:
    HostileApiCallItem.touched = 0

    result = has_concrete_attack_chain(evaluate_chain_evidence(tags=(), api_calls=[HostileApiCallItem()], ordered_events=()))

    assert result is False
    assert HostileApiCallItem.touched == 0


def test_stage1671_attack_authority_requires_observed_timestamped_order() -> None:
    synthetic = evaluate_chain_evidence(
        tags=(),
        api_calls=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        ordered_events=(),
    )
    assert has_concrete_attack_chain(synthetic) is False

    unrooted = evaluate_chain_evidence(
        ordered_events=[
            {"event": "VirtualAllocEx", "timestamp": 1.0, "target_identity": "process:4242", "process_identity": "process:4242", "platform": "windows", "modality": "host_telemetry", "directness": "direct"},
            {"event": "WriteProcessMemory", "timestamp": 2.0, "target_identity": "process:4242", "process_identity": "process:4242", "platform": "windows", "modality": "host_telemetry", "directness": "direct"},
            {"event": "CreateRemoteThread", "timestamp": 3.0, "target_identity": "process:4242", "process_identity": "process:4242", "platform": "windows", "modality": "host_telemetry", "directness": "direct"},
        ],
    )
    assert has_concrete_attack_chain(unrooted) is False
    assert any(
        "physical_root_unavailable" in decision.candidate.unmet_requirements
        for decision in unrooted.decisions
    )

    observed = evaluate_chain_evidence(
        ordered_events=[
            physical_runtime_chain_event("VirtualAllocEx", 1.0, 0, source_detector="stage1671_host_fixture"),
            physical_runtime_chain_event("WriteProcessMemory", 2.0, 1, source_detector="stage1671_host_fixture"),
            physical_runtime_chain_event("CreateRemoteThread", 3.0, 2, source_detector="stage1671_host_fixture"),
        ],
    )
    assert has_concrete_attack_chain(observed) is True

VIRUS_SCAN_ROOT = Path(__file__).resolve().parents[1]
ATTACK_AUTHORITY_PATH = VIRUS_SCAN_ROOT / "detection" / "chains" / "composite" / "attack_authority.py"
CHAIN_MATCHING_PATH = VIRUS_SCAN_ROOT / "detection" / "chains" / "execution" / "matching.py"


def test_stage1671_attack_authority_no_hook_patterns_stay_removed_from_production_paths() -> None:
    attack_source = ATTACK_AUTHORITY_PATH.read_text(encoding="utf-8")
    chain_source = CHAIN_MATCHING_PATH.read_text(encoding="utf-8")

    assert "str(value)" not in attack_source
    assert "iter(api_calls)" not in attack_source
    assert "iter(value)" not in chain_source
    assert "for item in iterator" not in chain_source
