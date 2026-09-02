"""Phase 17 repository-bound static artifact ATT&CK mapping gates."""
from __future__ import annotations

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_mapping_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture

from contextlib import contextmanager
from functools import cache
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.detection.attack.admission import (
    attack_technique_admission_index,
    attack_technique_admission_manifest,
)
from Virus_Scan.detection.attack.alignment import TAG_STIX_ALIGNMENT_SPECS
from Virus_Scan.detection.attack.api import (
    official_attack_probability_evidence,
    serialize_official_attack_probability_evidence,
)
from Virus_Scan.detection.attack.capabilities import SCANNER_CAPABILITIES
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.publication import (
    parse_official_attack_probability_evidence,
)
from Virus_Scan.detection.attack.release_validation import validate_attack_release
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
    CHAIN_RULE_INDEX,
)
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_from_args
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.runtime.api import release_mitre_runtime
from Virus_Scan.scanners.static_program_analysis import analyze_python_renpy_snapshot
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_MITRE_BUNDLE = _REPOSITORY_ROOT / "Mitre" / "enterprise-attack.json"
_MITRE_SHA256 = "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3"
_MITRE_DATASET = "9c27a5d97ad9328c845f3114351104d54cffc71b"
_MITRE_REPOSITORY_DIGEST = "96da129230304ea566cfa7dc7f0bf94da7f6b01bb41fad810943ff1d98a840b3"
_INJECTION_CHAIN = "static.artifact.virtualallocex_writeprocessmemory_createremotethread"
_POWERSHELL_CHAIN = "static.artifact.encoded_powershell_launch"

_INJECTION_SOURCE = (
    "import ctypes\n"
    "kernel32 = ctypes.windll.kernel32\n"
    "process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n"
    "kernel32.WriteProcessMemory(process, remote, b'abc', 3, None)\n"
    "kernel32.VirtualProtectEx(process, remote, 4096, 0x20, None)\n"
    "kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n"
)
_POWERSHELL_SOURCE = (
    "import subprocess\n"
    "subprocess.run(['powershell.exe', '-EncodedCommand', 'QQBBAEEA'])\n"
)
_UNCALLED_SOURCE = (
    "import ctypes\n"
    "def inject():\n"
    "    kernel32 = ctypes.windll.kernel32\n"
    "    process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "    remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n"
    "    kernel32.WriteProcessMemory(process, remote, b'abc', 3, None)\n"
    "    kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n"
)
_DISCONNECTED_SOURCE = (
    "import ctypes\n"
    "kernel32 = ctypes.windll.kernel32\n"
    "first = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n"
    "second = kernel32.OpenProcess(0x1F0FFF, False, 5678)\n"
    "remote = kernel32.VirtualAllocEx(first, None, 4096, 0x3000, 0x40)\n"
    "kernel32.WriteProcessMemory(second, remote, b'abc', 3, None)\n"
    "kernel32.CreateRemoteThread(first, None, 0, remote, None, 0, None)\n"
)
_DOCUMENTATION_SOURCE = (
    '"""VirtualAllocEx WriteProcessMemory CreateRemoteThread and '
    'powershell -EncodedCommand are documentation only."""\n'
)


@cache
def _repository():
    payload = _MITRE_BUNDLE.read_bytes()
    identity = git_blob_sha1_bytes(payload)
    return import_stix_bundle(
        payload,
        dataset_version=identity,
        source_ref="stage2636.11020-phase17-packaged-repository",
        expected_git_blob_sha1=identity,
        computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(payload),
    )


@contextmanager
def _isolated_runtime(tmp_path: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    release_mitre_runtime()
    sqlite_lifecycle().close()
    runtime_root = tmp_path / "runtime"
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    try:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
        yield runtime_root
    finally:
        release_mitre_runtime()
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def _scan(runtime_root: Path, name: str, source: str):
    target = runtime_root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    snapshot = build_artifact_read_snapshot(target)
    outcome = scan_file_by_type(
        str(target),
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=snapshot,
    )
    static_analysis = analyze_python_renpy_snapshot(snapshot).analysis
    chains = evaluate_chain_evidence(
        tags=outcome.tag_evidence,
        static_program_analyses=(static_analysis,),
    )
    mapping = map_attack_evidence(_repository(), attack_mapping_evidence_fixture(outcome.tag_evidence, chains))
    return target, outcome, chains, mapping


def _chain(chains, chain_id: str):
    return next(item for item in chains.decisions if item.to_record()["chain_id"] == chain_id)


def _decision(mapping, technique_id: str):
    return next(item for item in mapping.decisions if item.technique_id == technique_id)


def test_phase17_repository_capability_alignment_and_release_are_exact() -> None:
    payload = _MITRE_BUNDLE.read_bytes()
    repository = _repository()
    assert sha256_bytes(payload) == _MITRE_SHA256
    assert repository.version.dataset_version == _MITRE_DATASET
    assert repository.digest == _MITRE_REPOSITORY_DIGEST

    static_capability = next(
        item for item in SCANNER_CAPABILITIES
        if item.producer_id == "python_renpy_static_analysis"
    )
    assert len(SCANNER_CAPABILITIES) == 5
    assert static_capability.capability_state == "production_reachable"
    assert static_capability.supported_modalities == ("static_control_flow",)
    assert static_capability.supported_platforms == ("windows",)
    assert static_capability.limitation_reasons == ()

    static_alignments = tuple(
        item for item in TAG_STIX_ALIGNMENT_SPECS
        if item.producer_ids == ("python_renpy_static_analysis",)
    )
    assert len(TAG_STIX_ALIGNMENT_SPECS) == 43
    assert len(static_alignments) == 7
    assert all(item.alignment_state == "context_only" for item in static_alignments)
    assert all(item.data_component_ids == () for item in static_alignments)
    assert {item.tag_id for item in static_alignments} == set(
        static_capability.observable_tag_ids
    )

    admissions = attack_technique_admission_index(repository)
    for technique_id in ("T1055", "T1059.001"):
        record = admissions[technique_id]
        assert record.official_identity_state == "official_active_repository_bound"
        assert record.repository_digest == repository.digest
        assert record.dataset_version == repository.version.dataset_version
        assert record.strategy_ids
        assert record.analytic_ids
        assert record.required_data_component_ids
        assert record.requirement_digest_set
        assert "official_runtime_data_components_not_satisfied_by_static_artifact" in (
            record.unresolved_limitations
        )
        assert record.confirmed_reachable_chain_ids == ()
        assert record.calibration_status == "unavailable"
    assert admissions["T1562.001"].official_identity_state == (
        "official_revoked_repository_bound"
    )
    assert attack_technique_admission_manifest(repository)["confirmed_reachable_count"] == 0

    release = validate_attack_release(repository)
    assert release.valid is True
    assert release.issue_codes == ()
    assert release.alignment_count == 43
    assert release.capability_count == 5
    assert release.chain_count == 164
    assert release.confirmed_enabled_technique_ids == ()
    assert release.confirmed_reachable_technique_ids == ()


def test_phase17_static_injection_is_confirmed_artifact_chain_but_zero_authority(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path) as runtime_root:
        _target, outcome, chains, mapping = _scan(
            runtime_root, "injection.py", _INJECTION_SOURCE,
        )

        assert {
            "static_virtual_alloc_ex_operation",
            "static_write_process_memory_operation",
            "static_virtual_protect_ex_operation",
            "static_create_remote_thread_operation",
        }.issubset(outcome.tag_evidence.tags)
        chain = _chain(chains, _INJECTION_CHAIN)
        chain_record = chain.to_record()
        assert chain_record["status"] == "confirmed"
        assert chain_record["order_class"] == "static_control_flow"
        assert chain_record["scoreable"] is False
        assert chain_record["score_points"] == 0.0
        events = tuple(step["event"] for step in chain_record["matched_steps"])
        assert tuple(event["ordinal"] for event in events) == (1, 2, 4)
        assert len({event["actor_identity"] for event in events}) == 1
        assert len({event["target_identity"] for event in events}) == 1
        assert all(event["platform"] == "windows" for event in events)
        assert all(event["modality"] == "static_control_flow" for event in events)
        assert all(event["process_identity"] == "" for event in events)

        decision = _decision(mapping, "T1055")
        assert decision.status == "candidate"
        assert decision.claim_scopes == ("artifact_implementation",)
        assert decision.execution_observed is False
        assert decision.evidence_types == ("chain:confirmed:local_artifact",)
        assert decision.observed_data_component_ids == ()
        assert decision.probability == 0.0
        assert decision.probability_unavailable_reason == "candidate_not_scoreable"
        assert mapping.probability == 0.0
        assert not any(item.status == "confirmed" for item in mapping.decisions)


def test_phase17_encoded_powershell_list_command_is_windows_static_artifact_only(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path) as runtime_root:
        target, outcome, chains, mapping = _scan(
            runtime_root, "encoded_powershell.py", _POWERSHELL_SOURCE,
        )
        analysis = analyze_python_renpy_snapshot(
            build_artifact_read_snapshot(target),
        ).analysis
        launch = next(
            item for item in analysis.operations
            if item.operation_kind == "process_launch"
        )
        assert launch.platform == "windows"
        assert type(launch.resolved_arguments["arg0"]) is tuple
        assert "static_encoded_powershell_launch_operation" in outcome.tag_evidence.tags

        chain = _chain(chains, _POWERSHELL_CHAIN).to_record()
        assert chain["status"] == "confirmed"
        assert chain["scoreable"] is False
        event = chain["matched_steps"][0]["event"]
        assert event["platform"] == "windows"
        assert event["modality"] == "static_control_flow"
        assert event["process_identity"] == ""

        decision = _decision(mapping, "T1059.001")
        assert decision.status == "candidate"
        assert decision.claim_scopes == ("artifact_implementation",)
        assert decision.execution_observed is False
        assert decision.probability == 0.0
        assert decision.probability_unavailable_reason == "candidate_not_scoreable"


def test_phase17_hard_negatives_cannot_create_attack_candidates(tmp_path: Path) -> None:
    cases = (
        ("documentation.py", _DOCUMENTATION_SOURCE, None),
        ("uncalled.py", _UNCALLED_SOURCE, "minimum_direct_observations_unsatisfied"),
        ("disconnected.py", _DISCONNECTED_SOURCE, "same_target_mismatch"),
    )
    with _isolated_runtime(tmp_path) as runtime_root:
        for name, source, expected_unmet in cases:
            _target, outcome, chains, mapping = _scan(runtime_root, name, source)
            static_decisions = tuple(
                item.to_record()
                for item in chains.decisions
                if item.to_record()["chain_id"].startswith("static.artifact.")
            )
            if expected_unmet is None:
                assert "static_virtual_alloc_ex_operation" not in outcome.tag_evidence.tags
                assert "static_encoded_powershell_launch_operation" not in outcome.tag_evidence.tags
                assert static_decisions == ()
            else:
                injection = next(
                    item for item in static_decisions
                    if item["chain_id"] == _INJECTION_CHAIN
                )
                assert injection["status"] == "candidate"
                assert expected_unmet in injection["unmet_requirements"]
            decision = _decision(mapping, "T1055")
            assert decision.status == "rejected"
            assert decision.rejection_reason == "insufficient_implementation_evidence"
            assert decision.execution_observed is False
            assert decision.probability == 0.0


def test_phase17_publication_round_trip_preserves_static_execution_false(
    tmp_path: Path,
) -> None:
    with _isolated_runtime(tmp_path) as runtime_root:
        _target, outcome, chains, _mapping = _scan(
            runtime_root, "published_injection.py", _INJECTION_SOURCE,
        )
        payload = _MITRE_BUNDLE.read_bytes()
        mitre_root = runtime_root / "Mitre"
        mitre_root.mkdir(parents=True, exist_ok=True)
        (mitre_root / f"enterprise-attack-v{_MITRE_DATASET}.json").write_bytes(payload)
        runtime = initialize_mitre_from_args(SimpleNamespace(
            no_mitre=False,
            mitre_config=None,
            mitre_force_refresh=False,
            mitre_no_download=True,
            mitre_api_url=None,
            mitre_ref=None,
        ))
        assert runtime.available is True
        assert runtime.repository is not None
        assert runtime.repository.digest == _MITRE_REPOSITORY_DIGEST
        evidence = official_attack_probability_evidence(current_attack_mapping_fixture(outcome.tag_evidence, chains))
        encoded = serialize_official_attack_probability_evidence(evidence)
        published = parse_official_attack_probability_evidence(encoded)
        candidate = next(
            item for item in published["candidate"] if item["technique_id"] == "T1055"
        )
        assert published["ready"] is True
        assert published["probability"] == 0.0
        assert published["technique_ids_claimed"] is False
        assert candidate["claim_scopes"] == ("artifact_implementation",)
        assert candidate["execution_observed"] is False

        forged = json.loads(encoded)
        forged_candidate = next(
            item for item in forged["candidate"] if item["technique_id"] == "T1055"
        )
        forged_candidate["execution_observed"] = True
        with pytest.raises((TypeError, ValueError)):
            parse_official_attack_probability_evidence(json.dumps(forged))


def test_phase17_static_chain_registry_identity_is_current_and_non_scoreable() -> None:
    assert CHAIN_REGISTRY_VERSION == "stage2636_11020_chain_registry_v5"
    assert len(CHAIN_REGISTRY_DIGEST) == 64
    injection = CHAIN_RULE_INDEX[_INJECTION_CHAIN]
    powershell = CHAIN_RULE_INDEX[_POWERSHELL_CHAIN]
    assert injection.match_mode == "ordered"
    assert injection.same_actor is True
    assert injection.same_target is True
    assert injection.same_artifact is True
    assert injection.same_process is False
    assert injection.required_modalities == ("static_control_flow",)
    assert injection.scoreable is False
    assert powershell.match_mode == "anchor"
    assert powershell.same_artifact is True
    assert powershell.same_process is False
    assert powershell.required_modalities == ("static_control_flow",)
    assert powershell.scoreable is False
