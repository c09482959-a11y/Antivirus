from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from Virus_Scan.detection.attack.admission import attack_technique_admission_manifest
from Virus_Scan.detection.attack.alignment import (
    TagStixAlignmentSpec,
    tag_stix_alignment_manifest,
)
from Virus_Scan.detection.attack.capabilities import (
    ScannerCapabilitySpec,
    scanner_capability_manifest,
)
from Virus_Scan.detection.attack.gap_analysis import build_attack_capability_gap_report
from Virus_Scan.detection.attack.implementations import AttackAnalyticImplementationSpec
from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.tests.test_stage2636_10011_attack_stix_defensive_contracts import (
    _bundle,
    _snapshot,
)


def _capability(*, fields: tuple[str, ...] | None = None) -> ScannerCapabilitySpec:
    return ScannerCapabilitySpec(
        capability_id="test.phase9.process_access",
        producer_id="test_phase9_process_access",
        source_paths=("Virus_Scan/tests/test_stage2636_10011_phase9_gap_analysis.py",),
        observable_tag_ids=("lsass_access",),
        supported_modalities=("static_structure",),
        supported_platforms=("Windows",),
        emitted_observation_fields=(
            ("artifact_identity", "modality", "producer_id")
            if fields is None else fields
        ),
        capability_state="production_reachable",
        limitation_reasons=(),
    )


def _alignment(snapshot, *, state: str = "exact", digest: str | None = None,
               fields: tuple[str, ...] | None = None) -> TagStixAlignmentSpec:
    return TagStixAlignmentSpec(
        tag_id="lsass_access",
        data_component_ids=("DC0001",),
        supported_modalities=("static_structure",),
        supported_platforms=("Windows",),
        required_observation_fields=(
            ("artifact_identity", "modality", "producer_id")
            if fields is None else fields
        ),
        producer_ids=("test_phase9_process_access",),
        alignment_state=state,
        dataset_requirement_digest=(
            snapshot.analytic_requirement_digest_by_id["AN0001"]
            if digest is None else digest
        ),
    )


def _official_implementation(snapshot, *, digest: str | None = None):
    return AttackAnalyticImplementationSpec(
        implementation_id="official.t1003.an0001",
        technique_id="T1003",
        strategy_id="DET0001",
        analytic_id="AN0001",
        chain_ids=("anchor:api_lsass_minidump",),
        required_data_component_ids=("DC0001",),
        support_mode="exact_official",
        claim_scope="artifact_implementation",
        platforms=("windows",),
        required_modalities=("static_structure",),
        requirement_digest=(
            snapshot.analytic_requirement_digest_by_id["AN0001"]
            if digest is None else digest
        ),
        evaluation_manifest_digest="",
        admission_state="candidate_only",
    )


def test_current_reviewed_policy_is_unsupported_without_active_alignments() -> None:
    snapshot = _snapshot()
    before = (
        scanner_capability_manifest(),
        tag_stix_alignment_manifest(),
        tuple(item.to_record() for item in ATTACK_TECHNIQUE_POLICIES),
        attack_technique_admission_manifest(snapshot),
    )
    report = build_attack_capability_gap_report(snapshot)
    after = (
        scanner_capability_manifest(),
        tag_stix_alignment_manifest(),
        tuple(item.to_record() for item in ATTACK_TECHNIQUE_POLICIES),
        attack_technique_admission_manifest(snapshot),
    )
    assert before == after
    assert report.active_alignment_count == 0
    assert report.exact_count == 0
    assert report.partial_count == 0
    assert report.unsupported_count == 1
    record = report.analytics[0]
    assert record.classification == "unsupported"
    assert record.required_data_component_ids == ("DC0001",)
    assert record.required_platforms == ("Windows",)
    assert record.mutable_fields == ("TargetImage",)
    assert record.missing_data_component_ids == ("DC0001",)
    assert record.draft_observation_ids == ("draft.observation.an0001.dc0001",)
    assert record.draft_chain_id == "draft.chain.t1003.det0001.an0001"
    assert all(item.binding_state == "unbound" for item in report.implementation_bindings)


def test_active_analytic_without_strategy_binding_is_reported_explicitly() -> None:
    objects = json.loads(_bundle())["objects"]
    analytic = deepcopy(next(
        item for item in objects if item["type"] == "x-mitre-analytic"
    ))
    analytic["id"] = "x-mitre-analytic--00000009-0000-4000-8000-000000000009"
    analytic["external_references"][0]["external_id"] = "AN0002"
    objects.append(analytic)
    snapshot = _snapshot(json.dumps({
        "type": "bundle",
        "id": "bundle--00000004-0000-4000-8000-000000000004",
        "objects": objects,
    }, sort_keys=True).encode())
    report = build_attack_capability_gap_report(snapshot)
    assert report.active_analytic_count == 2
    assert len(report.analytics) == 2
    orphan = next(item for item in report.analytics if item.analytic_id == "AN0002")
    assert orphan.technique_id == ""
    assert orphan.strategy_id == ""
    assert orphan.classification == "unsupported"
    assert orphan.draft_chain_id == "draft.chain.unbound.an0002"
    assert "official_analytic_unbound_to_active_strategy" in orphan.limitations


def test_exact_reviewed_alignment_requires_complete_capability() -> None:
    snapshot = _snapshot()
    report = build_attack_capability_gap_report(
        snapshot,
        alignments=(_alignment(snapshot),),
        capabilities=(_capability(),),
    )
    record = report.analytics[0]
    assert report.exact_count == 1
    assert record.classification == "exact"
    assert record.matched_tag_ids == ("lsass_access",)
    assert record.matched_producer_ids == ("test_phase9_process_access",)
    assert record.missing_data_component_ids == ()
    assert record.limitations == ()


def test_partial_and_missing_requirements_are_explicit() -> None:
    snapshot = _snapshot()
    partial = build_attack_capability_gap_report(
        snapshot,
        alignments=(_alignment(snapshot, state="partial"),),
        capabilities=(_capability(),),
    ).analytics[0]
    assert partial.classification == "partial"
    assert "exact_alignment_coverage_incomplete" in partial.limitations

    missing = build_attack_capability_gap_report(
        snapshot,
        alignments=(_alignment(
            snapshot,
            fields=("artifact_identity", "modality", "producer_id", "target_identity"),
        ),),
        capabilities=(_capability(),),
    ).analytics[0]
    assert missing.classification == "partial"
    assert missing.missing_observation_fields == ("target_identity",)
    assert "required_observation_fields_unavailable" in missing.limitations


def test_requirement_digest_drift_is_partial_and_binding_is_stale() -> None:
    snapshot = _snapshot()
    report = build_attack_capability_gap_report(
        snapshot,
        alignments=(_alignment(snapshot, digest="0" * 64),),
        capabilities=(_capability(),),
        implementations=(_official_implementation(snapshot, digest="0" * 64),),
    )
    assert report.analytics[0].classification == "partial"
    assert "dataset_requirement_digest_mismatch" in report.analytics[0].limitations
    binding = report.implementation_bindings[0]
    assert binding.binding_state == "stale"
    assert binding.reasons == ("requirement_digest_changed",)


def test_current_official_binding_is_reported_without_activation() -> None:
    snapshot = _snapshot()
    report = build_attack_capability_gap_report(
        snapshot,
        alignments=(_alignment(snapshot),),
        capabilities=(_capability(),),
        implementations=(_official_implementation(snapshot),),
    )
    binding = report.implementation_bindings[0]
    assert binding.binding_state == "current"
    assert binding.reasons == ()
    assert report.to_record()["classification_counts"] == {
        "exact": 1, "partial": 0, "unsupported": 0,
    }


def test_gap_report_is_deterministic_in_process_and_subprocess() -> None:
    snapshot = _snapshot()
    first = build_attack_capability_gap_report(snapshot)
    second = build_attack_capability_gap_report(snapshot)
    assert first.to_record() == second.to_record()
    code = (
        "from Virus_Scan.tests.test_stage2636_10011_attack_stix_defensive_contracts "
        "import _snapshot; from Virus_Scan.detection.attack.gap_analysis import "
        "build_attack_capability_gap_report as build; print(build(_snapshot()).report_digest)"
    )
    outputs = tuple(subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip() for _ in range(2))
    assert outputs == (first.report_digest, first.report_digest)


def test_gap_analyzer_rejects_foreign_sequence_owners_without_iteration() -> None:
    class TrapTuple(tuple):
        called = False

        def __iter__(self):
            type(self).called = True
            raise AssertionError("hook executed")

    hostile = TrapTuple(())
    with pytest.raises(TypeError, match="alignments_invalid"):
        build_attack_capability_gap_report(_snapshot(), alignments=hostile)
    assert TrapTuple.called is False
    with pytest.raises(TypeError, match="repository_required"):
        build_attack_capability_gap_report(object())


def test_gap_report_rejects_foreign_record_owner_without_len_hook() -> None:
    class TrapRecords:
        called = False

        def __len__(self):
            type(self).called = True
            raise AssertionError("hook executed")

    report = build_attack_capability_gap_report(_snapshot())
    hostile = TrapRecords()
    with pytest.raises(TypeError, match="analytics_invalid"):
        replace(report, analytics=hostile)
    assert TrapRecords.called is False


def test_offline_cli_reads_external_bundle_and_emits_deterministic_report(tmp_path: Path) -> None:
    payload = _bundle()
    identity = git_blob_sha1_bytes(payload)
    bundle_path = tmp_path / "enterprise-attack.json"
    output_path = tmp_path / "gap-report.json"
    bundle_path.write_bytes(payload)
    command = [
        sys.executable,
        "-m",
        "tools.evaluation.analyze_mitre_attack_capability_gaps",
        str(bundle_path),
        "--expected-git-blob-sha1",
        identity,
        "--source-ref",
        "phase9-cli-fixture",
        "--output",
        str(output_path),
    ]
    subprocess.run(command, check=True, timeout=30)
    first = output_path.read_bytes()
    subprocess.run(command, check=True, timeout=30)
    assert output_path.read_bytes() == first
    report = json.loads(first)
    assert report["repository_counts"]["active_analytics"] == 1
    assert report["classification_counts"] == {
        "exact": 0, "partial": 0, "unsupported": 1,
    }
    assert report["analytics"][0]["draft_chain_id"] == "draft.chain.t1003.det0001.an0001"
