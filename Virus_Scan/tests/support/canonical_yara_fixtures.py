"""Canonical physical YARA fixtures for current-schema tests."""
from __future__ import annotations

from hashlib import sha256

from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.contracts.yara_hits import YaraHit, YaraRuleIdentity, YaraScanResult
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID,
    attack_analytic_implementation_manifest,
)
from Virus_Scan.detection.attack.mapping.registry import attack_technique_policy_manifest
from Virus_Scan.detection.attack.yara_alignment import YaraObservationAlignmentSpec
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_inputs import (
    AttackIntelligenceYaraFamilyAlignment,
)


def canonical_test_yara_result(
    *,
    rule_name: str = "stage2636_exfiltration",
    verified: bool = True,
    package_kind: str = "custom",
    source_digest: str = "a" * 64,
    cache_digest: str = "b" * 64,
    catalog_digest: str = "d" * 64,
    source_member: str = "rules/test.yar",
    namespace: str = "ns_test",
    metadata_id: str = "stage2636-test-rule",
    logic_hash: str = "e" * 64,
    artifact_digest: str = "c" * 64,
) -> YaraScanResult:
    """Return one exact physical scan result with no semantic fields."""
    identity = YaraRuleIdentity(
        package_kind=package_kind if verified else "unavailable",
        rule_source_digest=source_digest if verified else "",
        compiled_cache_digest=cache_digest if verified else "",
        rule_catalog_digest=catalog_digest if verified else "",
        source_member=source_member if verified else "",
        compiler_namespace=namespace if verified else "",
        rule_name=rule_name,
        metadata_id=metadata_id,
        logic_hash=logic_hash,
        semantic_metadata_digest="f" * 64,
        rule_tags=("stage2636_test",),
    )
    artifact_identity = "content_sha256:" + artifact_digest
    location = ObservationSourceLocation(
        "yara_match", locator="sample.bin", event_id=identity.digest,
    )
    root = "obs_" + sha256(
        (artifact_identity + identity.digest).encode("utf-8")
    ).hexdigest()
    hit = YaraHit(
        rule_identity=identity,
        root_observation_id=root,
        integrity_status="verified" if verified else "unverified",
        source_trust="custom_verified" if verified else "custom_unverified",
        release_id=0,
        release_tag="",
        compile_policy_version="stage2636_test_compile_policy_v1",
        artifact_identity=artifact_identity,
        source_location=location,
        unavailable_reason="" if verified else "yara_execution_provenance_unverified",
    )
    return YaraScanResult(
        status="complete",
        scan_pass_id="yscan_" + sha256((root + identity.digest).encode("utf-8")).hexdigest(),
        physical_target_identity=artifact_identity,
        package_kind=package_kind if verified else "unavailable",
        rule_source_digest=source_digest if verified else "",
        compiled_cache_digest=cache_digest if verified else "",
        rule_catalog_digest=catalog_digest if verified else "",
        hits=(hit,),
        total_match_count=1,
        retained_match_count=1,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
    )


def canonical_test_yara_no_match_result() -> YaraScanResult:
    """Return a verified complete no-match result."""
    return YaraScanResult(
        status="complete_no_match",
        scan_pass_id="yscan_" + "9" * 64,
        physical_target_identity="content_sha256:" + "c" * 64,
        package_kind="custom",
        rule_source_digest="a" * 64,
        compiled_cache_digest="b" * 64,
        rule_catalog_digest="d" * 64,
        hits=(),
        total_match_count=0,
        retained_match_count=0,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
    )


def candidate_mitre_alignment(
    hit: YaraHit,
    *,
    alignment_id: str = "stage2636.test.encoded_powershell",
    tag_id: str = "encoded_powershell",
    implementation_id: str = "local.t1059.001.encoded_powershell",
    repository_digest: str = "4" * 64,
) -> YaraObservationAlignmentSpec:
    identity = hit.rule_identity
    return YaraObservationAlignmentSpec(
        alignment_id=alignment_id,
        package_kind=identity.package_kind,
        rule_source_digest=identity.rule_source_digest,
        rule_catalog_digest=identity.rule_catalog_digest,
        source_member=identity.source_member,
        compiler_namespace=identity.compiler_namespace,
        rule_name=identity.rule_name,
        metadata_id=identity.metadata_id,
        logic_hash=identity.logic_hash,
        semantic_metadata_digest=identity.semantic_metadata_digest,
        rule_tags=identity.rule_tags,
        rule_identity_schema_version=identity.schema_version,
        required_match_detail_fields=(),
        tag_id=tag_id,
        implementation_ids=(implementation_id,),
        platforms=("windows",),
        modality="yara_match",
        claim_scope="artifact_implementation",
        requirement_digests=tuple(filter(None, (
            ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[implementation_id].requirement_digest,
        ))),
        implementation_manifest_digest=attack_analytic_implementation_manifest()["digest"],
        policy_digest=attack_technique_policy_manifest()["digest"],
        repository_digest=repository_digest,
        admission_state="candidate_only",
        external_evaluation_manifest_digest="",
        interpretation_provenance="reviewed_stage2636_test_alignment",
    )


def family_alignment(
    hit: YaraHit,
    *,
    family: str = "exfiltration",
) -> AttackIntelligenceYaraFamilyAlignment:
    identity = hit.rule_identity
    return AttackIntelligenceYaraFamilyAlignment(
        family=family,
        package_kind=identity.package_kind,
        rule_source_digest=identity.rule_source_digest,
        rule_catalog_digest=identity.rule_catalog_digest,
        source_member=identity.source_member,
        compiler_namespace=identity.compiler_namespace,
        rule_name=identity.rule_name,
        metadata_id=identity.metadata_id,
        logic_hash=identity.logic_hash,
        interpretation_provenance="reviewed_stage2636_test_family_alignment",
    )


__all__ = (
    "candidate_mitre_alignment",
    "canonical_test_yara_no_match_result",
    "canonical_test_yara_result",
    "family_alignment",
)
