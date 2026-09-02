"""Phase 11 reviewed source-bound candidate YARA alignment registry."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import zipfile

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.contracts.yara_hits import YaraHit, YaraRuleIdentity, YaraScanResult
from Virus_Scan.detection.attack.yara_alignment import (
    YARA_OBSERVATION_ALIGNMENT_DIGEST,
    YARA_OBSERVATION_ALIGNMENTS,
    project_yara_observations,
)

_EXPECTED_SOURCE_DIGESTS = {
    "core": "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f",
    "extended": "756bd295a87603d78f1c879ecb7d217c91c1bcb03461c34e604fa20a4a0acae5",
}
_EXPECTED_IMPLEMENTATIONS = {
    "local.t1003.lsass_dump",
    "local.t1055.process_injection",
    "local.t1059.001.encoded_powershell",
}
_EXPECTED_RULES = {
    "DITEKSHEN_INDICATOR_TOOL_PWS_LSASS_Createminidump",
    "GCTI_Cobaltstrike_Resources_Template_X86_Vba_V3_8_To_V4_X",
    "GCTI_Cobaltstrike_Resources_Template_X64_Ps1_V3_0_To_V4_X_Excluding_3_12_3_13",
}


def _result_for_alignment(spec) -> YaraScanResult:
    cache_digest = "8" * 64
    artifact_identity = "content_sha256:" + "9" * 64
    identity = YaraRuleIdentity(
        package_kind=spec.package_kind,
        rule_source_digest=spec.rule_source_digest,
        compiled_cache_digest=cache_digest,
        rule_catalog_digest=spec.rule_catalog_digest,
        source_member=spec.source_member,
        compiler_namespace=spec.compiler_namespace,
        rule_name=spec.rule_name,
        metadata_id=spec.metadata_id,
        logic_hash=spec.logic_hash,
        semantic_metadata_digest=spec.semantic_metadata_digest,
        rule_tags=spec.rule_tags,
    )
    location = ObservationSourceLocation(
        "yara_match", locator="sample.bin", event_id=identity.digest,
    )
    root = "obs_" + canonical_json_sha256({
        "artifact_identity": artifact_identity,
        "rule_identity_digest": identity.digest,
        "source_location": location.to_record(),
    })
    hit = YaraHit(
        rule_identity=identity,
        root_observation_id=root,
        integrity_status="verified",
        source_trust="official_verified",
        release_id=1,
        release_tag="reviewed-test",
        compile_policy_version="stage2636_11008_test_compile_policy",
        artifact_identity=artifact_identity,
        source_location=location,
    )
    return YaraScanResult(
        status="complete",
        scan_pass_id="yscan_" + canonical_json_sha256({
            "artifact_identity": artifact_identity,
            "package_kind": spec.package_kind,
            "rule_identity": identity.digest,
        }),
        physical_target_identity=artifact_identity,
        package_kind=spec.package_kind,
        rule_source_digest=spec.rule_source_digest,
        compiled_cache_digest=cache_digest,
        rule_catalog_digest=spec.rule_catalog_digest,
        hits=(hit,),
        total_match_count=1,
        retained_match_count=1,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
    )


def test_registry_contains_only_exact_candidate_alignments() -> None:
    assert len(YARA_OBSERVATION_ALIGNMENTS) == 6
    assert len(YARA_OBSERVATION_ALIGNMENT_DIGEST) == 64
    assert {item.package_kind for item in YARA_OBSERVATION_ALIGNMENTS} == {"core", "extended"}
    assert {item.rule_name for item in YARA_OBSERVATION_ALIGNMENTS} == _EXPECTED_RULES
    assert {
        item.implementation_ids[0] for item in YARA_OBSERVATION_ALIGNMENTS
    } == _EXPECTED_IMPLEMENTATIONS
    assert all(item.admission_state == "candidate_only" for item in YARA_OBSERVATION_ALIGNMENTS)
    assert all(item.external_evaluation_manifest_digest == "" for item in YARA_OBSERVATION_ALIGNMENTS)
    assert all(item.claim_scope == "artifact_implementation" for item in YARA_OBSERVATION_ALIGNMENTS)
    assert all(item.modality == "yara_match" for item in YARA_OBSERVATION_ALIGNMENTS)
    assert all(item.repository_digest == "96da129230304ea566cfa7dc7f0bf94da7f6b01bb41fad810943ff1d98a840b3" for item in YARA_OBSERVATION_ALIGNMENTS)
    assert not any(
        item.implementation_ids[0] in {
            "local.t1021.admin_smb", "local.t1105.download_execute",
        }
        for item in YARA_OBSERVATION_ALIGNMENTS
    )


def test_registry_is_bound_to_the_supplied_archive_bytes_and_rule_declarations() -> None:
    root = Path(__file__).resolve().parents[2]
    for package_kind, expected_digest in _EXPECTED_SOURCE_DIGESTS.items():
        archive_path = root / "Yara" / f"yara-forge-rules-{package_kind}.zip"
        payload = archive_path.read_bytes()
        assert sha256(payload).hexdigest() == expected_digest
        with zipfile.ZipFile(archive_path) as archive:
            members = tuple(info for info in archive.infolist() if not info.is_dir())
            assert len(members) == 1
            source = archive.read(members[0]).decode("utf-8")
        for rule_name in _EXPECTED_RULES:
            assert f"rule {rule_name}" in source
        package_specs = tuple(
            item for item in YARA_OBSERVATION_ALIGNMENTS
            if item.package_kind == package_kind
        )
        assert {item.rule_source_digest for item in package_specs} == {expected_digest}
        assert {item.source_member for item in package_specs} == {members[0].filename}


def test_each_reviewed_rule_projects_candidate_context_only() -> None:
    for spec in YARA_OBSERVATION_ALIGNMENTS:
        result = _result_for_alignment(spec)
        observations = project_yara_observations(
            result,
            alignments=YARA_OBSERVATION_ALIGNMENTS,
            platform="windows",
            repository_digest=spec.repository_digest,
        )
        assert len(observations) == 1
        observation = observations[0]
        assert observation.tag == spec.tag_id
        assert observation.directness == "context"
        assert observation.confidence == 0.0
        assert observation.root_observation_id == result.hits[0].root_observation_id
        assert observation.evidence["alignment_state"] == "candidate_only"
        assert observation.evidence["implementation_ids"] == spec.implementation_ids


def test_registry_drift_fails_closed_without_name_fallback() -> None:
    spec = YARA_OBSERVATION_ALIGNMENTS[0]
    result = _result_for_alignment(spec)
    hit = result.hits[0]
    changed_identity = YaraRuleIdentity(
        package_kind=hit.rule_identity.package_kind,
        rule_source_digest=hit.rule_identity.rule_source_digest,
        compiled_cache_digest=hit.rule_identity.compiled_cache_digest,
        rule_catalog_digest=hit.rule_identity.rule_catalog_digest,
        source_member=hit.rule_identity.source_member,
        compiler_namespace=hit.rule_identity.compiler_namespace,
        rule_name=hit.rule_identity.rule_name,
        metadata_id=hit.rule_identity.metadata_id,
        logic_hash="0" * 64,
        semantic_metadata_digest=hit.rule_identity.semantic_metadata_digest,
        rule_tags=hit.rule_identity.rule_tags,
    )
    changed_hit = YaraHit(
        rule_identity=changed_identity,
        root_observation_id=hit.root_observation_id,
        integrity_status=hit.integrity_status,
        source_trust=hit.source_trust,
        release_id=hit.release_id,
        release_tag=hit.release_tag,
        compile_policy_version=hit.compile_policy_version,
        artifact_identity=hit.artifact_identity,
        source_location=hit.source_location,
    )
    changed_result = YaraScanResult(
        status="complete",
        scan_pass_id=result.scan_pass_id,
        physical_target_identity=result.physical_target_identity,
        package_kind=result.package_kind,
        rule_source_digest=result.rule_source_digest,
        compiled_cache_digest=result.compiled_cache_digest,
        rule_catalog_digest=result.rule_catalog_digest,
        hits=(changed_hit,),
        total_match_count=1,
        retained_match_count=1,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
    )
    assert project_yara_observations(
        changed_result,
        alignments=YARA_OBSERVATION_ALIGNMENTS,
        platform="windows",
        repository_digest=spec.repository_digest,
    ) == ()
