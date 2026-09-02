"""Reviewed source-bound YARA interpretation for canonical ATT&CK observations.

The YARA subsystem owns physical matches and scan execution.  This module owns
only reviewed semantic alignments and never loads, compiles, or scans rules.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.detection_observation import DetectionObservation
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.contracts.yara_hits import (
    YaraHit,
    YARA_RULE_IDENTITY_SCHEMA_VERSION,
    YaraRuleIdentity,
    canonical_yara_scan_result,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID,
    attack_analytic_implementation_manifest,
)
from Virus_Scan.detection.attack.mapping.registry import (
    ATTACK_TECHNIQUE_POLICY_BY_ID,
    attack_technique_policy_manifest,
)
from Virus_Scan.detection.attack.validation import exact_hex, exact_text_tuple, ordered_text_tuple
from Virus_Scan.detection.registries.tag_taxonomy_registry import TAG_DEFINITION_BY_ID

YARA_OBSERVATION_ALIGNMENT_VERSION = "stage2636_11008_yara_observation_alignment_v1"
_YARA_ALIGNMENT_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_YARA_ALIGNMENT_STATES = frozenset({"candidate_only", "confirmed_enabled", "retired"})
_YARA_PACKAGES = frozenset({"core", "extended", "custom"})
_MAX_YARA_ALIGNMENTS = 512
_ALLOWED_MATCH_DETAIL_FIELDS = frozenset({
    "match_offsets", "matched_string_identifiers", "matched_string_count",
})
_STATIC_IMPLEMENTATION_MODALITIES = frozenset({
    "static_string", "static_structure", "static_control_flow", "yara_match",
})


def _platforms(value: object) -> tuple[str, ...]:
    raw = exact_text_tuple(value, "yara_alignment_platforms_invalid", maximum_items=16)
    items = tuple(item.strip().casefold() for item in raw)
    if not items or any(not item for item in items) or items != tuple(sorted(set(items))):
        raise ValueError("yara_alignment_platforms_invalid")
    return items


def _implementations(value: object) -> tuple[tuple[str, ...], tuple[object, ...]]:
    identifiers = ordered_text_tuple(
        value, "yara_alignment_implementations_invalid", maximum_items=16
    )
    implementations = tuple(ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID.get(item) for item in identifiers)
    if not identifiers or any(item is None for item in implementations):
        raise ValueError("yara_alignment_implementation_missing")
    return identifiers, implementations


def _admission(
    state_value: object,
    evaluation_value: object,
    implementations: tuple[object, ...],
) -> tuple[str, str]:
    state = exact_bounded_text(state_value, "yara_alignment_admission_invalid", maximum=32)
    if state not in _YARA_ALIGNMENT_STATES:
        raise ValueError("yara_alignment_admission_invalid")
    if state == "confirmed_enabled":
        evaluation = exact_hex(
            evaluation_value, "yara_alignment_evaluation_digest_invalid", length=64
        )
        if any(
            item.admission_state != "confirmed_enabled"
            or item.evaluation_manifest_digest != evaluation
            for item in implementations
        ):
            raise ValueError("yara_alignment_confirmed_implementation_required")
        return state, evaluation
    if type(evaluation_value) is not str or evaluation_value:
        raise ValueError("yara_alignment_inactive_evaluation_digest_invalid")
    if state == "candidate_only" and any(
        item.admission_state != "candidate_only" for item in implementations
    ):
        raise ValueError("yara_alignment_candidate_implementation_required")
    return state, ""


def _digest_tuple(value: object, reason: str) -> tuple[str, ...]:
    raw = exact_text_tuple(value, reason, maximum_items=32)
    digests = tuple(exact_hex(item, reason, length=64) for item in raw)
    if digests != tuple(sorted(set(digests))):
        raise ValueError(reason)
    return digests


@dataclass(frozen=True, slots=True)
class YaraObservationAlignmentSpec:
    """One reviewed exact-rule alignment to one atomic observation."""

    alignment_id: str
    package_kind: str
    rule_source_digest: str
    rule_catalog_digest: str
    source_member: str
    compiler_namespace: str
    rule_name: str
    metadata_id: str
    logic_hash: str
    semantic_metadata_digest: str
    rule_tags: tuple[str, ...]
    rule_identity_schema_version: str
    required_match_detail_fields: tuple[str, ...]
    tag_id: str
    implementation_ids: tuple[str, ...]
    platforms: tuple[str, ...]
    modality: str
    claim_scope: str
    requirement_digests: tuple[str, ...]
    implementation_manifest_digest: str
    policy_digest: str
    repository_digest: str
    admission_state: str
    external_evaluation_manifest_digest: str
    interpretation_provenance: str
    version: str = YARA_OBSERVATION_ALIGNMENT_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraObservationAlignmentSpec:
            raise TypeError("yara_alignment_owner_invalid")
        alignment_id = exact_bounded_text(self.alignment_id, "yara_alignment_id_invalid", maximum=128)
        if _YARA_ALIGNMENT_ID.fullmatch(alignment_id) is None:
            raise ValueError("yara_alignment_id_invalid")
        package_kind = exact_bounded_text(
            self.package_kind, "yara_alignment_package_invalid", maximum=32
        )
        if package_kind not in _YARA_PACKAGES:
            raise ValueError("yara_alignment_package_invalid")
        source_digest = exact_hex(
            self.rule_source_digest, "yara_alignment_source_digest_invalid", length=64
        )
        catalog_digest = exact_hex(
            self.rule_catalog_digest, "yara_alignment_catalog_digest_invalid", length=64
        )
        source_member = exact_bounded_text(
            self.source_member, "yara_alignment_source_member_invalid", maximum=4096
        )
        namespace = exact_bounded_text(
            self.compiler_namespace, "yara_alignment_namespace_invalid", maximum=160
        )
        rule_name = exact_bounded_text(self.rule_name, "yara_alignment_rule_name_invalid", maximum=160)
        metadata_id = exact_bounded_text(
            self.metadata_id, "yara_alignment_metadata_id_invalid", maximum=160, allow_blank=True
        )
        logic_hash = exact_hex(self.logic_hash, "yara_alignment_logic_hash_invalid", length=64)
        metadata_digest = exact_hex(
            self.semantic_metadata_digest,
            "yara_alignment_semantic_metadata_digest_invalid",
            length=64,
        )
        rule_tags = exact_text_tuple(
            self.rule_tags, "yara_alignment_rule_tags_invalid", maximum_items=32,
        )
        if rule_tags != tuple(sorted(set(rule_tags))):
            raise ValueError("yara_alignment_rule_tags_invalid")
        identity_schema = exact_bounded_text(
            self.rule_identity_schema_version,
            "yara_alignment_rule_identity_schema_invalid",
            maximum=128,
        )
        if identity_schema != YARA_RULE_IDENTITY_SCHEMA_VERSION:
            raise ValueError("yara_alignment_rule_identity_schema_invalid")
        match_details = exact_text_tuple(
            self.required_match_detail_fields,
            "yara_alignment_match_detail_fields_invalid",
            maximum_items=16,
        )
        if (
            match_details != tuple(sorted(set(match_details)))
            or any(item not in _ALLOWED_MATCH_DETAIL_FIELDS for item in match_details)
        ):
            raise ValueError("yara_alignment_match_detail_fields_invalid")
        tag_id = exact_bounded_text(self.tag_id, "yara_alignment_tag_id_invalid", maximum=160)
        definition = TAG_DEFINITION_BY_ID.get(tag_id)
        if definition is None or definition.tag_class != "atomic_observation":
            raise ValueError("yara_alignment_atomic_tag_required")
        implementation_ids, implementations = _implementations(self.implementation_ids)
        techniques = {item.technique_id for item in implementations}
        if len(techniques) != 1:
            raise ValueError("yara_alignment_implementation_technique_mismatch")
        technique_id = next(iter(techniques))
        policy = ATTACK_TECHNIQUE_POLICY_BY_ID.get(technique_id)
        if policy is None or any(item not in policy.implementation_ids for item in implementation_ids):
            raise ValueError("yara_alignment_policy_implementation_mismatch")
        platforms = _platforms(self.platforms)
        if any(not set(platforms).issubset(set(item.platforms)) for item in implementations):
            raise ValueError("yara_alignment_platform_implementation_mismatch")
        modality = exact_bounded_text(self.modality, "yara_alignment_modality_invalid", maximum=64)
        if modality != "yara_match":
            raise ValueError("yara_alignment_modality_invalid")
        if any(not (_STATIC_IMPLEMENTATION_MODALITIES & set(item.required_modalities)) for item in implementations):
            raise ValueError("yara_alignment_static_implementation_required")
        claim_scope = exact_bounded_text(
            self.claim_scope, "yara_alignment_claim_scope_invalid", maximum=64
        )
        if (
            claim_scope != "artifact_implementation"
            or any(item.claim_scope != claim_scope for item in implementations)
            or claim_scope not in policy.supported_claim_scopes
        ):
            raise ValueError("yara_alignment_claim_scope_invalid")
        requirement_digests = _digest_tuple(
            self.requirement_digests, "yara_alignment_requirement_digests_invalid"
        )
        expected_requirements = tuple(sorted({
            item.requirement_digest for item in implementations if item.requirement_digest
        }))
        if requirement_digests != expected_requirements:
            raise ValueError("yara_alignment_requirement_digests_mismatch")
        implementation_manifest_digest = exact_hex(
            self.implementation_manifest_digest,
            "yara_alignment_implementation_manifest_digest_invalid",
            length=64,
        )
        if implementation_manifest_digest != attack_analytic_implementation_manifest()["digest"]:
            raise ValueError("yara_alignment_implementation_manifest_digest_mismatch")
        policy_digest = exact_hex(self.policy_digest, "yara_alignment_policy_digest_invalid", length=64)
        if policy_digest != attack_technique_policy_manifest()["digest"]:
            raise ValueError("yara_alignment_policy_digest_mismatch")
        repository_digest = exact_hex(
            self.repository_digest, "yara_alignment_repository_digest_invalid", length=64
        )
        admission_state, evaluation = _admission(
            self.admission_state, self.external_evaluation_manifest_digest, implementations
        )
        if admission_state == "candidate_only" and policy.admission_state != "candidate_only":
            raise ValueError("yara_alignment_candidate_policy_required")
        if admission_state == "confirmed_enabled" and policy.admission_state not in {
            "confirmed_enabled", "production_mature",
        }:
            raise ValueError("yara_alignment_confirmed_policy_required")
        if admission_state == "retired" and policy.admission_state != "retired":
            raise ValueError("yara_alignment_retired_policy_required")
        provenance = exact_bounded_text(
            self.interpretation_provenance,
            "yara_alignment_interpretation_provenance_invalid",
            maximum=1024,
        )
        version = exact_bounded_text(self.version, "yara_alignment_version_invalid", maximum=128)
        for name, value in (
            ("alignment_id", alignment_id),
            ("package_kind", package_kind),
            ("rule_source_digest", source_digest),
            ("rule_catalog_digest", catalog_digest),
            ("source_member", source_member),
            ("compiler_namespace", namespace),
            ("rule_name", rule_name),
            ("metadata_id", metadata_id),
            ("logic_hash", logic_hash),
            ("semantic_metadata_digest", metadata_digest),
            ("rule_tags", rule_tags),
            ("rule_identity_schema_version", identity_schema),
            ("required_match_detail_fields", match_details),
            ("tag_id", tag_id),
            ("implementation_ids", implementation_ids),
            ("platforms", platforms),
            ("modality", modality),
            ("claim_scope", claim_scope),
            ("requirement_digests", requirement_digests),
            ("implementation_manifest_digest", implementation_manifest_digest),
            ("policy_digest", policy_digest),
            ("repository_digest", repository_digest),
            ("admission_state", admission_state),
            ("external_evaluation_manifest_digest", evaluation),
            ("interpretation_provenance", provenance),
            ("version", version),
        ):
            object.__setattr__(self, name, value)

    @property
    def rule_key(self) -> tuple[str, ...]:
        return (
            self.package_kind,
            self.rule_source_digest,
            self.rule_catalog_digest,
            self.source_member,
            self.compiler_namespace,
            self.rule_name,
            self.metadata_id,
            self.logic_hash,
            self.semantic_metadata_digest,
            self.rule_identity_schema_version,
            *self.rule_tags,
        )

    def to_record(self) -> dict[str, object]:
        return {
            "admission_state": self.admission_state,
            "alignment_id": self.alignment_id,
            "claim_scope": self.claim_scope,
            "compiler_namespace": self.compiler_namespace,
            "external_evaluation_manifest_digest": self.external_evaluation_manifest_digest,
            "implementation_ids": self.implementation_ids,
            "implementation_manifest_digest": self.implementation_manifest_digest,
            "interpretation_provenance": self.interpretation_provenance,
            "logic_hash": self.logic_hash,
            "metadata_id": self.metadata_id,
            "required_match_detail_fields": self.required_match_detail_fields,
            "rule_identity_schema_version": self.rule_identity_schema_version,
            "rule_tags": self.rule_tags,
            "semantic_metadata_digest": self.semantic_metadata_digest,
            "modality": self.modality,
            "package_kind": self.package_kind,
            "platforms": self.platforms,
            "policy_digest": self.policy_digest,
            "repository_digest": self.repository_digest,
            "requirement_digests": self.requirement_digests,
            "rule_catalog_digest": self.rule_catalog_digest,
            "rule_name": self.rule_name,
            "rule_source_digest": self.rule_source_digest,
            "source_member": self.source_member,
            "tag_id": self.tag_id,
            "version": self.version,
        }


def _identity_key(identity: YaraRuleIdentity) -> tuple[str, ...]:
    return (
        identity.package_kind,
        identity.rule_source_digest,
        identity.rule_catalog_digest,
        identity.source_member,
        identity.compiler_namespace,
        identity.rule_name,
        identity.metadata_id,
        identity.logic_hash,
        identity.semantic_metadata_digest,
        identity.schema_version,
        *identity.rule_tags,
    )


def _alignment_indexes(
    alignments: object,
) -> tuple[Mapping[str, YaraObservationAlignmentSpec], Mapping[tuple[str, ...], YaraObservationAlignmentSpec]]:
    if (
        type(alignments) is not tuple
        or len(alignments) > _MAX_YARA_ALIGNMENTS
        or any(type(item) is not YaraObservationAlignmentSpec for item in alignments)
    ):
        raise TypeError("yara_alignment_registry_invalid")
    by_id: dict[str, YaraObservationAlignmentSpec] = {}
    by_rule: dict[tuple[str, ...], YaraObservationAlignmentSpec] = {}
    for spec in alignments:
        if spec.alignment_id in by_id:
            raise ValueError("yara_alignment_duplicate_id")
        if spec.rule_key in by_rule:
            raise ValueError("yara_alignment_duplicate_rule_identity")
        by_id[spec.alignment_id] = spec
        by_rule[spec.rule_key] = spec
    return MappingProxyType(by_id), MappingProxyType(by_rule)


def _alignment_digest(alignments: tuple[YaraObservationAlignmentSpec, ...]) -> str:
    return canonical_json_sha256(tuple(spec.to_record() for spec in alignments))


_SUPPLIED_ATTACK_REPOSITORY_DIGEST = "96da129230304ea566cfa7dc7f0bf94da7f6b01bb41fad810943ff1d98a840b3"
_SUPPLIED_YARA_PACKAGES = MappingProxyType({
    "core": MappingProxyType({
        "rule_source_digest": "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f",
        "rule_catalog_digest": "a5360c9ccd1bc4803b0da5de555364f51273410ef4af5b8dd5bef7834fe52508",
        "source_member": "packages/core/yara-rules-core.yar",
        "compiler_namespace": "packages_core_yara_rules_core_yar_a51c1668e9486045",
    }),
    "extended": MappingProxyType({
        "rule_source_digest": "756bd295a87603d78f1c879ecb7d217c91c1bcb03461c34e604fa20a4a0acae5",
        "rule_catalog_digest": "ea131c65b3538c939be9ba2c4642298fc4653c9500eb2b6fe73cc69a92e48015",
        "source_member": "packages/extended/yara-rules-extended.yar",
        "compiler_namespace": "packages_extended_yara_rules_extended_yar_b217f4b9da68fb5b",
    }),
})
_REVIEWED_RULES = (
    (
        "ditekshen_indicator_tool_pws_lsass_createminidump",
        "DITEKSHEN_INDICATOR_TOOL_PWS_LSASS_Createminidump",
        "0d8642d1-2ed9-5270-a54a-6ba788026f5f",
        "577ccc783554363c0bed80d9642e8a0f107fc2ec66d84f76b9556aa3506c86c0",
        "9d7dc6364f9eeb5d3d3f081f7de16d24e10c2769664669ac687dec258ac86249",
        ("FILE",),
        "credential_dump_attempt",
        "local.t1003.lsass_dump",
        "Reviewed PE rule requires multiple explicit LSASS dump-tool artifacts; candidate static context only.",
    ),
    (
        "gcti_cobaltstrike_resources_template_x86_vba_v3_8_to_v4_x",
        "GCTI_Cobaltstrike_Resources_Template_X86_Vba_V3_8_To_V4_X",
        "11c7758e-93b2-5fe3-873d-b98de579d2b4",
        "7114515477d82651806eccef34f599f6ffd4614f987dee29417ac6ef7a1a1c38",
        "4714984533400171f25ad5692ab5085cbe3274f5197f001996e7ffd67b4b5c61",
        (),
        "writeprocessmemory",
        "local.t1055.process_injection",
        "Reviewed VBA template requires ordered process-injection API declarations and use; candidate static context only.",
    ),
    (
        "gcti_cobaltstrike_resources_template_x64_ps1_v3_0_to_v4_x",
        "GCTI_Cobaltstrike_Resources_Template_X64_Ps1_V3_0_To_V4_X_Excluding_3_12_3_13",
        "5a808113-aacb-56ca-b3ec-166c73c54b85",
        "80823b8590004686ebd83958cad16094ea2f6958a837d87934507531a00df77a",
        "dc2de8e93ad47bc947282d0429b57a1687fad8de32615abf8c663e6fde08771a",
        (),
        "encoded_powershell",
        "local.t1059.001.encoded_powershell",
        "Reviewed PowerShell template requires Base64 decode and in-memory assembly markers; candidate static context only.",
    ),
)


def _reviewed_candidate_alignment(
    package_kind: str,
    reviewed_rule: tuple[object, ...],
) -> YaraObservationAlignmentSpec:
    package = _SUPPLIED_YARA_PACKAGES[package_kind]
    (
        alignment_suffix, rule_name, metadata_id, logic_hash,
        metadata_digest, rule_tags, tag_id, implementation_id, rationale,
    ) = reviewed_rule
    implementation = ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[implementation_id]
    return YaraObservationAlignmentSpec(
        alignment_id=f"stage2636.11008.{package_kind}.{alignment_suffix}",
        package_kind=package_kind,
        rule_source_digest=package["rule_source_digest"],
        rule_catalog_digest=package["rule_catalog_digest"],
        source_member=package["source_member"],
        compiler_namespace=package["compiler_namespace"],
        rule_name=rule_name,
        metadata_id=metadata_id,
        logic_hash=logic_hash,
        semantic_metadata_digest=metadata_digest,
        rule_tags=rule_tags,
        rule_identity_schema_version=YARA_RULE_IDENTITY_SCHEMA_VERSION,
        required_match_detail_fields=(),
        tag_id=tag_id,
        implementation_ids=(implementation_id,),
        platforms=("windows",),
        modality="yara_match",
        claim_scope="artifact_implementation",
        requirement_digests=tuple(filter(None, (implementation.requirement_digest,))),
        implementation_manifest_digest=attack_analytic_implementation_manifest()["digest"],
        policy_digest=attack_technique_policy_manifest()["digest"],
        repository_digest=_SUPPLIED_ATTACK_REPOSITORY_DIGEST,
        admission_state="candidate_only",
        external_evaluation_manifest_digest="",
        interpretation_provenance=rationale,
    )


YARA_OBSERVATION_ALIGNMENTS: tuple[YaraObservationAlignmentSpec, ...] = tuple(
    _reviewed_candidate_alignment(package_kind, reviewed_rule)
    for package_kind in ("core", "extended")
    for reviewed_rule in _REVIEWED_RULES
)
YARA_OBSERVATION_ALIGNMENT_BY_ID, YARA_OBSERVATION_ALIGNMENT_BY_RULE_IDENTITY = (
    _alignment_indexes(YARA_OBSERVATION_ALIGNMENTS)
)
YARA_OBSERVATION_ALIGNMENT_DIGEST = _alignment_digest(YARA_OBSERVATION_ALIGNMENTS)


def canonical_yara_alignment_platform(tags: object) -> str:
    """Return one explicit platform from canonical tag evidence or fail closed."""
    if type(tags) is not TagEvidence:
        raise TypeError("yara_alignment_platform_evidence_required")
    platforms = {
        record.platform.strip().casefold()
        for record in tags.records
        if type(record.platform) is str and record.platform.strip()
    }
    return next(iter(platforms)) if len(platforms) == 1 else ""


def _observation(
    hit: YaraHit, spec: YaraObservationAlignmentSpec, platform: str,
    *, alignment_digest: str,
) -> DetectionObservation:
    confirmed = spec.admission_state == "confirmed_enabled"
    evidence = {
        "alignment_digest": alignment_digest,
        "alignment_id": spec.alignment_id,
        "alignment_state": spec.admission_state,
        "claim_scope": spec.claim_scope,
        "implementation_ids": spec.implementation_ids,
        "implementation_manifest_digest": spec.implementation_manifest_digest,
        "modality": spec.modality,
        "policy_digest": spec.policy_digest,
        "repository_digest": spec.repository_digest,
        "requirement_digests": spec.requirement_digests,
        "rule_identity_schema_version": spec.rule_identity_schema_version,
        "physical_yara_hit": hit.to_record(),
    }
    return DetectionObservation.create(
        tag=spec.tag_id,
        producer_id="yara_alignment",
        stage_id="yara_observation_projection",
        modality="yara_match",
        platform=platform,
        artifact_identity=hit.artifact_identity,
        source_location=hit.source_location,
        timing_provenance="not_observed",
        integrity_status="verified",
        directness="direct" if confirmed else "context",
        confidence=1.0 if confirmed else 0.0,
        root_observation_id=hit.root_observation_id,
        evidence=evidence,
    )


def project_yara_observations(
    scan_result: object,
    *,
    alignments: tuple[YaraObservationAlignmentSpec, ...] = YARA_OBSERVATION_ALIGNMENTS,
    platform: str = "",
    repository_digest: str = "",
) -> tuple[DetectionObservation, ...]:
    """Project complete verified physical hits through exact reviewed alignments."""
    _by_id, by_key = _alignment_indexes(alignments)
    alignment_digest = _alignment_digest(alignments)
    result = canonical_yara_scan_result(scan_result)
    if not result.complete or not result.verified:
        return ()
    if type(platform) is not str:
        raise TypeError("yara_alignment_platform_invalid")
    platform_key = platform.strip().casefold()
    if not platform_key:
        return ()
    if type(repository_digest) is not str:
        raise TypeError("yara_alignment_repository_context_invalid")
    repository_key = repository_digest.strip().casefold()
    if len(repository_key) != 64 or any(ch not in "0123456789abcdef" for ch in repository_key):
        return ()
    observations: list[DetectionObservation] = []
    for hit in result.hits:
        identity = hit.rule_identity
        if not hit.verified or not identity.mapping_eligible:
            continue
        spec = by_key.get(_identity_key(identity))
        if (
            spec is None
            or spec.admission_state == "retired"
            or platform_key not in spec.platforms
            or spec.repository_digest != repository_key
            or spec.required_match_detail_fields
        ):
            continue
        observations.append(_observation(
            hit, spec, platform_key, alignment_digest=alignment_digest,
        ))
    return tuple(observations)



__all__ = (
    "YARA_OBSERVATION_ALIGNMENT_BY_ID",
    "YARA_OBSERVATION_ALIGNMENT_BY_RULE_IDENTITY",
    "YARA_OBSERVATION_ALIGNMENT_DIGEST",
    "YARA_OBSERVATION_ALIGNMENT_VERSION",
    "YARA_OBSERVATION_ALIGNMENTS",
    "YaraObservationAlignmentSpec",
    "canonical_yara_alignment_platform",
    "project_yara_observations",
)
