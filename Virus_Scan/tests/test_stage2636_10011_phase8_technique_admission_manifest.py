"""Stage2636.10011 Phase 8 truthful eight-technique admission records."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from Virus_Scan.detection.attack.admission import (
    AttackTechniqueAdmissionRecord,
    attack_technique_admission_index,
    attack_technique_admission_manifest,
    build_attack_technique_admission_records,
)
from Virus_Scan.detection.attack.capabilities import (
    SCANNER_CAPABILITIES,
    ScannerCapabilitySpec,
    scanner_capability_manifest,
)
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.repository import technique_by_id
from Virus_Scan.tests.test_stage2636_10011_attack_stix_defensive_contracts import _snapshot


class _HostileText(str):
    def __str__(self) -> str:
        raise AssertionError("hostile text hook executed")


_EXPECTED_STATES = {
    "T1003": "candidate_only",
    "T1021": "candidate_only",
    "T1041": "unsupported_by_sensors",
    "T1055": "candidate_only",
    "T1059": "unsupported_by_sensors",
    "T1059.001": "candidate_only",
    "T1105": "candidate_only",
    "T1562.001": "retired",
}


def _records():
    return build_attack_technique_admission_records(_snapshot())


def _index():
    return attack_technique_admission_index(_snapshot())


def _manifest():
    return attack_technique_admission_manifest(_snapshot())


def test_all_eight_policies_have_one_matching_machine_readable_admission_record() -> None:
    assert len(_records()) == 8
    assert set(_index()) == set(_EXPECTED_STATES)
    assert {
        policy.technique_id for policy in ATTACK_TECHNIQUE_POLICIES
    } == set(_EXPECTED_STATES)
    assert {
        item.technique_id: item.admission_state
        for item in _records()
    } == _EXPECTED_STATES


def test_no_current_record_overclaims_official_binding_reachability_or_calibration() -> None:
    snapshot = _snapshot()
    for record in build_attack_technique_admission_records(snapshot):
        technique = technique_by_id(snapshot, record.technique_id)
        expected_identity = (
            "official_missing_repository_bound"
            if technique is None
            else "official_revoked_repository_bound"
            if technique.revoked or technique.deprecated
            else "official_active_repository_bound"
        )
        assert record.official_identity_state == expected_identity
        assert record.repository_digest == snapshot.digest
        assert record.dataset_version == snapshot.version.dataset_version
        if record.official_identity_state == "official_active_repository_bound":
            assert record.strategy_ids
            assert record.analytic_ids
            assert record.required_data_component_ids
            assert record.requirement_digest_set
        elif record.official_identity_state == "official_missing_repository_bound":
            assert record.strategy_ids == ()
            assert record.analytic_ids == ()
            assert record.required_data_component_ids == ()
            assert record.requirement_digest_set == ()
        assert record.confirmed_reachable_chain_ids == ()
        assert record.end_to_end_fixture_ids == ()
        assert record.evaluation_manifest_digest == ""
        assert record.calibration_status == "unavailable"
        assert "live_repository_requirement_digest_unavailable" not in record.unresolved_limitations


def test_candidate_records_publish_real_producers_and_required_fields() -> None:
    candidate_records = tuple(
        item
        for item in _records()
        if item.admission_state == "candidate_only"
    )
    assert len(candidate_records) == 5
    for record in candidate_records:
        assert record.implementation_ids
        assert record.chain_ids
        assert record.scanner_producer_ids
        assert record.required_observation_fields
        assert record.term_reachable_chain_ids
    static_records = {
        item.technique_id: item
        for item in candidate_records
        if item.technique_id in {"T1055", "T1059.001"}
    }
    assert set(static_records) == {"T1055", "T1059.001"}
    assert all(
        item.scanner_producer_ids == ("python_renpy_static_analysis",)
        for item in static_records.values()
    )
    assert all(
        "platform_not_emitted" not in item.unresolved_limitations
        for item in static_records.values()
    )
    assert all(
        "platform_not_emitted" in item.unresolved_limitations
        for item in candidate_records
        if item.technique_id in {"T1003", "T1021", "T1105"}
    )


def test_unsupported_records_have_no_local_sensor_or_chain_claim() -> None:
    for technique_id in ("T1041", "T1059"):
        record = _index()[technique_id]
        assert record.admission_state == "unsupported_by_sensors"
        assert record.scanner_producer_ids == ()
        assert record.chain_ids == ()
        assert record.term_reachable_chain_ids == ()
        assert "local_sensor_implementation_unavailable" in record.unresolved_limitations


def test_capability_source_paths_and_tag_claims_are_present_in_actual_source() -> None:
    root = Path.cwd()
    for capability in SCANNER_CAPABILITIES:
        source_paths = tuple(root / item for item in capability.source_paths)
        assert all(path.is_file() for path in source_paths)
        source = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)
        if capability.producer_id != "python_renpy_static_analysis":
            assert all(tag in source for tag in capability.observable_tag_ids)
            assert capability.capability_state == "partial"
            assert capability.supported_platforms == ()
            assert capability.limitation_reasons
        else:
            assert capability.capability_state == "production_reachable"
            assert capability.supported_platforms == ("windows",)
            assert capability.limitation_reasons == ()


def test_broad_reporting_tags_are_not_technique_admission_inputs() -> None:
    broad = {
        "credential_access",
        "defense_evasion",
        "lateral_movement",
        "network_exfiltration",
        "process_injection",
        "script_execution",
    }
    capability_tags = {
        tag for capability in SCANNER_CAPABILITIES for tag in capability.observable_tag_ids
    }
    assert broad.isdisjoint(capability_tags)
    assert all(not hasattr(policy, "tag_ids") for policy in ATTACK_TECHNIQUE_POLICIES)


def test_process_injection_record_uses_exact_static_artifact_chain() -> None:
    record = _index()["T1055"]
    expected = (
        "static.artifact.virtualallocex_writeprocessmemory_createremotethread",
    )
    assert record.chain_ids == expected
    assert record.term_reachable_chain_ids == expected
    assert record.scanner_producer_ids == ("python_renpy_static_analysis",)
    assert record.supported_platforms == ("windows",)
    assert "process_identity" not in record.required_observation_fields
    assert {
        "actor_identity",
        "artifact_identity",
        "directness",
        "integrity_status",
        "target_identity",
        "timing_provenance",
    } == set(record.required_observation_fields)
    assert "one_or_more_chain_term_sets_unreachable" not in record.unresolved_limitations


def test_security_tool_record_is_retired_after_live_repository_revocation() -> None:
    record = _index()["T1562.001"]
    assert "defender_tamper_execution_chain" in record.chain_ids
    assert record.term_reachable_chain_ids == ()
    assert record.admission_state == "retired"
    assert record.scanner_producer_ids == ()
    assert "official_technique_revoked_in_bound_repository" in (
        record.unresolved_limitations
    )


def test_manifests_are_cross_process_deterministic() -> None:
    code = (
        "import json; "
        "from Virus_Scan.detection.attack.capabilities import scanner_capability_manifest; "
        "from Virus_Scan.detection.attack.admission import attack_technique_admission_manifest; "
        "from Virus_Scan.tests.test_stage2636_10011_attack_stix_defensive_contracts import _snapshot; "
        "print(json.dumps([scanner_capability_manifest()['digest'], "
        "attack_technique_admission_manifest(_snapshot())['digest']]))"
    )
    values = []
    for seed in ("1", "17", "101"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        values.append(completed.stdout.strip())
    assert len(set(values)) == 1
    assert json.loads(values[0]) == [
        scanner_capability_manifest()["digest"],
        _manifest()["digest"],
    ]


def test_capability_and_admission_contracts_reject_hostile_or_false_claims() -> None:
    with pytest.raises(TypeError, match="producer"):
        ScannerCapabilitySpec(
            "scanner.test", _HostileText("producer"), ("source.py",),
            ("powershell_exec",), ("static_string",), (),
            ("artifact_identity",), "partial", ("platform_not_emitted",),
        )
    with pytest.raises(ValueError, match="unvalidated_reachability"):
        AttackTechniqueAdmissionRecord(
            "T1003",
            "b" * 64,
            "a" * 40,
            "official_active_repository_bound",
            ("local.t1003.lsass_dump",),
            (),
            (),
            (),
            (),
            ("windows",),
            ("static_control_flow",),
            ("target_identity",),
            ("full_analysis_string_scanner",),
            ("anchor:api_lsass_minidump",),
            ("anchor:api_lsass_minidump",),
            ("anchor:api_lsass_minidump",),
            (),
            "candidate_only",
            "",
            "unavailable",
            ("not_validated",),
        )


def test_manifest_counts_are_honest() -> None:
    capability_manifest = scanner_capability_manifest()
    admission_manifest = _manifest()
    assert capability_manifest["capability_count"] == 5
    assert capability_manifest["production_reachable_count"] == 1
    assert admission_manifest["record_count"] == 8
    assert admission_manifest["candidate_only_count"] == 5
    assert admission_manifest["unsupported_count"] == 2
    assert admission_manifest["retired_count"] == 1
    assert admission_manifest["confirmed_reachable_count"] == 0
