"""Phase 16: controlled artifact mutations must move canonical authority causally."""
from __future__ import annotations

from contextlib import contextmanager
import inspect
import os
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.yara_alignment import YARA_OBSERVATION_ALIGNMENTS
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.evidence.artifact_session import ArtifactEvidenceSession
from Virus_Scan.detection.evidence.yara_assimilation import assimilate_reviewed_yara_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.runtime.api import release_yara_runtime, yara_rules_state
from Virus_Scan.scanners.static_program_analysis import analyze_python_renpy_snapshot
from Virus_Scan.scanners.static_program_analysis.native_elf_x86_64_frontend import (
    analyze_native_elf_x86_64_snapshot,
)
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.stress.artifact_attack_projection import (
    artifact_attack_expectations,
    artifact_behavior_satisfied,
)
from Virus_Scan.stress.artifact_evidence_oracle import derive_artifact_evidence_truth
from Virus_Scan.stress.artifact_evidence_oracle_validator import validate_artifact_evidence_truth
from Virus_Scan.stress.attack_synthetic_templates import SYNTHETIC_ATTACK_CHALLENGE_PAIRS
from Virus_Scan.stress.static_semantic_binary_fixtures import build_semantic_elf64_x86_64_fixture
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_contract_repository,
    attack_mapping_evidence_fixture,
)
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.loader import load_yaralight_rules
from Virus_Scan.yara.match import yara_scan

_INJECTION_CHAIN = "static.artifact.virtualallocex_writeprocessmemory_createremotethread"
_POWERSHELL_CHAIN = "static.artifact.encoded_powershell_launch"
_YARA_RULE = "GCTI_Cobaltstrike_Resources_Template_X64_Ps1_V3_0_To_V4_X_Excluding_3_12_3_13"
_CORE_SHA256 = "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f"

_POSITIVE = (
    "import ctypes\n"
    "kernel32 = ctypes.windll.kernel32\n"
    "process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n"
    "kernel32.WriteProcessMemory(process, remote, b'abc', 3, None)\n"
    "kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n"
)
_WRONG_TARGET = (
    "import ctypes\n"
    "kernel32 = ctypes.windll.kernel32\n"
    "first = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "second = kernel32.OpenProcess(0x1F0FFF, False, 5678)\n"
    "remote = kernel32.VirtualAllocEx(first, None, 4096, 0x3000, 0x40)\n"
    "kernel32.WriteProcessMemory(second, remote, b'abc', 3, None)\n"
    "kernel32.CreateRemoteThread(first, None, 0, remote, None, 0, None)\n"
)
_DISCONNECTED = (
    "import ctypes\n"
    "kernel32 = ctypes.windll.kernel32\n"
    "process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n"
    "other = 12345\n"
    "kernel32.WriteProcessMemory(process, other, b'abc', 3, None)\n"
    "kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n"
)
_UNCALLED = (
    "import ctypes\n"
    "def inject():\n"
    "    kernel32 = ctypes.windll.kernel32\n"
    "    process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "    remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n"
    "    kernel32.WriteProcessMemory(process, remote, b'abc', 3, None)\n"
    "    kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n"
)
_DOCUMENTATION = '"""VirtualAllocEx WriteProcessMemory CreateRemoteThread documentation only."""\n'


@contextmanager
def _isolated_static_runtime(tmp_path: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    runtime_root = tmp_path / "runtime"
    sqlite_lifecycle().close()
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
    try:
        yield runtime_root
    finally:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def _t1055_case(runtime_root: Path, name: str, source: str):
    target = runtime_root / (name + ".py")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    payload = target.read_bytes()
    truth = derive_artifact_evidence_truth(name, target.name, payload)
    expectations = artifact_attack_expectations(truth, ("T1055",))
    validation = validate_artifact_evidence_truth(name, target.name, payload, truth, expectations)
    snapshot = build_artifact_read_snapshot(target)
    outcome = scan_file_by_type(
        str(target),
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=snapshot,
    )
    analysis = analyze_python_renpy_snapshot(snapshot).analysis
    chains = evaluate_chain_evidence(
        tags=outcome.tag_evidence,
        static_program_analyses=(analysis,),
    )
    mapping = map_attack_evidence(
        attack_contract_repository(),
        attack_mapping_evidence_fixture(outcome.tag_evidence, chains),
    )
    chain = next(
        (item for item in chains.decisions if item.candidate.chain_id == _INJECTION_CHAIN),
        None,
    )
    decision = next(item for item in mapping.decisions if item.technique_id == "T1055")
    return truth, validation, chain, decision


def test_phase16_t1055_physical_mutations_move_oracle_chain_and_mapping_together(
    tmp_path: Path,
) -> None:
    cases = (
        ("positive", _POSITIVE, True, "confirmed", "candidate"),
        (
            "missing_write",
            _POSITIVE.replace("kernel32.WriteProcessMemory(process, remote, b'abc', 3, None)\n", ""),
            False,
            "partial",
            "rejected",
        ),
        (
            "missing_thread",
            _POSITIVE.replace("kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n", ""),
            False,
            "partial",
            "rejected",
        ),
        ("wrong_target", _WRONG_TARGET, False, "candidate", "rejected"),
        ("disconnected", _DISCONNECTED, False, "candidate", "rejected"),
        ("uncalled", _UNCALLED, False, "candidate", "rejected"),
        ("documentation", _DOCUMENTATION, False, None, "rejected"),
    )
    with _isolated_static_runtime(tmp_path) as runtime_root:
        for name, source, expected_truth, expected_chain, expected_mapping in cases:
            truth, validation, chain, decision = _t1055_case(runtime_root, name, source)
            assert validation["agreement"] is True
            assert artifact_behavior_satisfied(truth, "T1055") is expected_truth
            assert (None if chain is None else chain.status) == expected_chain
            assert decision.status == expected_mapping
            if expected_mapping == "rejected":
                assert decision.rejection_reason == "insufficient_implementation_evidence"

    wrong_truth = derive_artifact_evidence_truth("wrong", "wrong.py", _WRONG_TARGET.encode())
    wrong_relation = next(
        item for item in wrong_truth.flow
        if item.source_operation_kind == "memory_allocate"
        and item.sink_operation_kind == "memory_write"
    )
    assert wrong_relation.connected is True
    assert wrong_relation.same_resource is False
    disconnected_truth = derive_artifact_evidence_truth(
        "disconnected", "disconnected.py", _DISCONNECTED.encode(),
    )
    disconnected_relation = next(
        item for item in disconnected_truth.flow
        if item.source_operation_kind == "memory_allocate"
        and item.sink_operation_kind == "memory_write"
    )
    assert disconnected_relation.connected is False
    assert disconnected_relation.same_resource is True


def test_phase16_native_elf_causal_mutations_move_oracle_and_production_together(
    tmp_path: Path,
) -> None:
    variants = (
        "import_flow_positive", "calls_unreachable", "wrong_target_identity",
        "no_value_flow", "wrong_sink", "unresolved_indirect",
        "syscall_flow_positive", "adjacent_syscall",
    )
    evidence = {}
    for variant in variants:
        payload = build_semantic_elf64_x86_64_fixture(
            variant, identity_marker="UMIGE_STATIC_SEMANTIC:phase16-" + variant,
        )
        truth = derive_artifact_evidence_truth(variant, variant + ".elf", payload)
        assert validate_artifact_evidence_truth(
            variant, variant + ".elf", payload, truth, (),
        )["agreement"] is True
        target = tmp_path / (variant + ".elf")
        target.write_bytes(payload)
        analysis = analyze_native_elf_x86_64_snapshot(
            build_artifact_read_snapshot(target),
        ).analysis
        evidence[variant] = (truth, analysis)

    positive_truth, positive = evidence["import_flow_positive"]
    assert any(item.connected for item in positive_truth.flow)
    assert any(item.edge_kind == "source_to_sink" for item in positive.flow_edges)

    unreachable_truth, unreachable = evidence["calls_unreachable"]
    assert not any(
        item.operation_kind == "network_send"
        and item.reachability_state == "entrypoint_reachable"
        for item in unreachable_truth.reachability
    )
    assert "network_send" not in {item.operation_kind for item in unreachable.operations}

    wrong_truth, wrong = evidence["wrong_target_identity"]
    assert set(positive_truth.operation_kinds) == set(wrong_truth.operation_kinds)
    assert set(positive_truth.resource_identities) != set(wrong_truth.resource_identities)
    positive_send = next(item for item in positive.operations if item.operation_kind == "network_send")
    wrong_send = next(item for item in wrong.operations if item.operation_kind == "network_send")
    assert positive_send.target_resource_identity != wrong_send.target_resource_identity

    no_flow_truth, no_flow = evidence["no_value_flow"]
    assert any(item.connected is False for item in no_flow_truth.flow)
    assert not any(item.edge_kind == "source_to_sink" for item in no_flow.flow_edges)

    wrong_sink_truth, wrong_sink = evidence["wrong_sink"]
    assert "network_send" not in set(wrong_sink_truth.operation_kinds)
    assert "network_send" not in {item.operation_kind for item in wrong_sink.operations}

    unresolved_truth, unresolved = evidence["unresolved_indirect"]
    assert unresolved_truth.evidence_completeness == "partial"
    assert unresolved.parser_status == "partial"

    syscall_truth, syscall = evidence["syscall_flow_positive"]
    assert any(item.connected for item in syscall_truth.flow)
    assert any(item.edge_kind == "source_to_sink" for item in syscall.flow_edges)

    adjacent_truth, adjacent = evidence["adjacent_syscall"]
    assert "network_send" not in set(adjacent_truth.operation_kinds)
    assert "network_send" not in {item.operation_kind for item in adjacent.operations}


def test_phase16_real_reviewed_yara_cannot_rescue_missing_static_causality(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    pair = next(
        item for item in SYNTHETIC_ATTACK_CHALLENGE_PAIRS
        if item.challenge_id == "t1059_001_reviewed_yara_corroboration"
    )
    alignment = next(
        item for item in YARA_OBSERVATION_ALIGNMENTS
        if item.package_kind == "core" and item.rule_name == _YARA_RULE
    )
    config = YaraConfig(light_expected_sha256=_CORE_SHA256)
    try:
        loaded = load_yaralight_rules(
            str(root / "Yara" / "yara-forge-rules-core.zip"),
            auto_download=False,
            use_cache=False,
            config=config,
            allow_cache_write=False,
        )
        assert loaded.load_result.ready is True
        for side, fixture in (
            ("positive", pair.positive_fixture),
            ("control", pair.control_fixture),
        ):
            payload = render_static_semantic_artifact(
                "phase16-yara-" + side, fixture.renderer_specification,
            )
            target = tmp_path / (side + ".ps1")
            target.write_bytes(payload)
            scan = yara_scan(target, compiled_rules=yara_rules_state().light_snapshot())
            assert any(item.rule_identity.rule_name == _YARA_RULE for item in scan.hits)
            tags = assimilate_reviewed_yara_evidence(
                normalize_tag_evidence(()),
                scan,
                platform="windows",
                repository_digest=alignment.repository_digest,
            )
            chains = evaluate_chain_evidence(tags=tags)
            weak = next(
                item for item in chains.decisions
                if item.candidate.chain_id == "anchor:encoded_powershell_weak"
            )
            assert weak.status == "confirmed"
            assert _POWERSHELL_CHAIN not in chains.hits
            evidence = ArtifactEvidenceSession(
                artifact_read_snapshot=build_artifact_read_snapshot(target),
                static_program_analyses=(),
                yara_scan_result=scan,
            ).provisional_evidence(tag_evidence=tags, chain_evidence=chains)
            mapping = map_attack_evidence(attack_contract_repository(), evidence)
            decision = next(
                item for item in mapping.decisions if item.technique_id == "T1059.001"
            )
            assert decision.status == "rejected"
            assert decision.rejection_reason == "insufficient_implementation_evidence"
    finally:
        release_yara_runtime()


def test_phase16_model_context_has_no_attack_mapping_rescue_channel() -> None:
    signature = inspect.signature(map_attack_evidence)
    assert tuple(signature.parameters) == ("snapshot", "evidence")
    source = inspect.getsource(map_attack_evidence)
    assert "ModelContextSnapshot" not in source
    assert "model_context" not in source
    assert "candidate_retrieval" not in source
