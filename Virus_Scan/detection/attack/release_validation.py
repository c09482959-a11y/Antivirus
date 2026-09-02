"""Fail-closed ATT&CK production reachability and release validation."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PosixPath, WindowsPath

from Virus_Scan.contracts.chain_evidence import ChainRule
from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.attack.alignment import (
    TAG_STIX_ALIGNMENT_SPECS,
    TagStixAlignmentSpec,
)
from Virus_Scan.detection.attack.calibration import (
    ATTACK_CALIBRATION_ARTIFACTS,
    AttackCalibrationArtifact,
)
from Virus_Scan.detection.attack.capabilities import (
    SCANNER_CAPABILITIES,
    ScannerCapabilitySpec,
)
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATIONS,
    AttackAnalyticImplementationSpec,
)
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.repository import technique_by_id
from Virus_Scan.detection.attack.validation import exact_bool, exact_hex, official_attack_id, ordered_text_tuple
from Virus_Scan.detection.registries.chain_registry import CANONICAL_CHAIN_RULES
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for

ATTACK_RELEASE_VALIDATION_VERSION = "stage2636_10011_attack_release_validation_v2"
ATTACK_FIXTURE_BOUNDARIES = frozenset({"scanner_input", "post_scanner_injected"})
_CONFIRMATION_STATES = frozenset({"confirmed_enabled", "production_mature"})


@dataclass(frozen=True, slots=True)
class AttackEndToEndFixtureSpec:
    """One controlled production-path fixture declaration."""

    fixture_id: str
    technique_id: str
    implementation_id: str
    producer_ids: tuple[str, ...]
    source_path: str
    input_boundary: str
    injects_tag_or_chain_evidence: bool
    platform: str
    modalities: tuple[str, ...]
    claim_scope: str

    def __post_init__(self) -> None:
        if type(self) is not AttackEndToEndFixtureSpec:
            raise TypeError("attack_fixture_owner_invalid")
        object.__setattr__(self, "fixture_id", exact_bounded_text(
            self.fixture_id, "attack_fixture_id_invalid", maximum=160,
        ))
        technique_id = official_attack_id(
            self.technique_id, "attack_fixture_technique_invalid",
        )
        if not technique_id.startswith("T") or technique_id.startswith("TA"):
            raise ValueError("attack_fixture_technique_invalid")
        object.__setattr__(self, "technique_id", technique_id)
        object.__setattr__(self, "implementation_id", exact_bounded_text(
            self.implementation_id, "attack_fixture_implementation_invalid", maximum=128,
        ))
        object.__setattr__(self, "producer_ids", ordered_text_tuple(
            self.producer_ids, "attack_fixture_producers_invalid", maximum_items=32,
        ))
        object.__setattr__(self, "source_path", exact_bounded_text(
            self.source_path, "attack_fixture_source_path_invalid", maximum=512,
        ))
        boundary = exact_bounded_text(
            self.input_boundary, "attack_fixture_boundary_invalid", maximum=32,
        )
        if boundary not in ATTACK_FIXTURE_BOUNDARIES:
            raise ValueError("attack_fixture_boundary_invalid")
        object.__setattr__(self, "input_boundary", boundary)
        object.__setattr__(self, "injects_tag_or_chain_evidence", exact_bool(
            self.injects_tag_or_chain_evidence, "attack_fixture_injection_invalid",
        ))
        object.__setattr__(self, "platform", exact_bounded_text(
            self.platform, "attack_fixture_platform_invalid", maximum=64,
            allow_blank=True,
        ))
        object.__setattr__(self, "modalities", ordered_text_tuple(
            self.modalities, "attack_fixture_modalities_invalid", maximum_items=16,
        ))
        object.__setattr__(self, "claim_scope", exact_bounded_text(
            self.claim_scope, "attack_fixture_claim_scope_invalid", maximum=64,
            allow_blank=True,
        ))

    def to_record(self) -> dict[str, object]:
        return {field: object.__getattribute__(self, field) for field in self.__slots__}


ATTACK_END_TO_END_FIXTURES: tuple[AttackEndToEndFixtureSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class AttackReleaseValidationReport:
    repository_digest: str
    confirmed_enabled_technique_ids: tuple[str, ...]
    confirmed_reachable_technique_ids: tuple[str, ...]
    issue_codes: tuple[str, ...]
    alignment_count: int
    capability_count: int
    implementation_count: int
    policy_count: int
    calibration_count: int
    chain_count: int
    fixture_count: int
    report_digest: str
    version: str = ATTACK_RELEASE_VALIDATION_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackReleaseValidationReport:
            raise TypeError("attack_release_report_owner_invalid")
        object.__setattr__(self, "repository_digest", exact_hex(
            self.repository_digest, "attack_release_repository_digest_invalid", length=64,
        ))
        for field_name in (
            "confirmed_enabled_technique_ids", "confirmed_reachable_technique_ids",
            "issue_codes",
        ):
            object.__setattr__(self, field_name, ordered_text_tuple(
                object.__getattribute__(self, field_name),
                "attack_release_report_tuple_invalid",
                maximum_items=4096,
            ))
        for field_name in (
            "alignment_count", "capability_count", "implementation_count",
            "policy_count", "calibration_count", "chain_count", "fixture_count",
        ):
            value = object.__getattribute__(self, field_name)
            if type(value) is not int or type(value) is bool or value < 0 or value > 100_000:
                raise ValueError("attack_release_report_count_invalid")
        object.__setattr__(self, "version", exact_bounded_text(
            self.version, "attack_release_version_invalid", maximum=128,
        ))
        expected = _report_digest(self._values())
        object.__setattr__(self, "report_digest", exact_hex(
            self.report_digest, "attack_release_report_digest_invalid", length=64,
        ))
        if self.report_digest != expected:
            raise ValueError("attack_release_report_digest_invalid")
        if not set(self.confirmed_reachable_technique_ids).issubset(
            self.confirmed_enabled_technique_ids
        ):
            raise ValueError("attack_release_reachable_subset_invalid")

    @property
    def valid(self) -> bool:
        return not self.issue_codes

    def _values(self) -> dict[str, object]:
        return {
            field: object.__getattribute__(self, field)
            for field in self.__slots__ if field != "report_digest"
        }

    def to_record(self) -> dict[str, object]:
        return {**self._values(), "valid": self.valid, "report_digest": self.report_digest}


def _report_digest(values: dict[str, object]) -> str:
    payload = json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _exact_tuple(values: object, owner: type, reason: str, maximum: int) -> tuple[object, ...]:
    if type(values) is not tuple or len(values) > maximum:
        raise TypeError(reason)
    if any(type(item) is not owner for item in values):
        raise TypeError(reason)
    return values


def _indexes(
    capabilities: tuple[ScannerCapabilitySpec, ...],
    implementations: tuple[AttackAnalyticImplementationSpec, ...],
    policies: tuple[AttackTechniquePolicy, ...],
    calibrations: tuple[AttackCalibrationArtifact, ...],
    chains: tuple[ChainRule, ...],
    fixtures: tuple[AttackEndToEndFixtureSpec, ...],
) -> tuple[dict[str, object], ...]:
    indexes: tuple[dict[str, object], ...] = (
        {item.producer_id: item for item in capabilities},
        {item.implementation_id: item for item in implementations},
        {item.technique_id: item for item in policies},
        {item.calibration_id: item for item in calibrations},
        {item.chain_id: item for item in chains},
        {item.fixture_id: item for item in fixtures},
    )
    sequences = (
        capabilities, implementations, policies, calibrations, chains, fixtures,
    )
    if any(len(index) != len(sequence) for index, sequence in zip(indexes, sequences)):
        raise ValueError("attack_release_duplicate_identity")
    return indexes


def _alignment_issues(
    snapshot: AttackRepositorySnapshot,
    alignments: tuple[TagStixAlignmentSpec, ...],
    capability_by_producer: dict[str, object],
) -> set[str]:
    issues: set[str] = set()
    requirement_digests = frozenset(
        snapshot.analytic_requirement_digest_by_id.values()
    )
    for alignment in alignments:
        if alignment.alignment_state not in {"exact", "partial"}:
            continue
        if any(
            component_id not in snapshot.data_component_by_attack_id
            for component_id in alignment.data_component_ids
        ):
            issues.add("active_alignment_data_component_missing:" + alignment.tag_id)
        if alignment.dataset_requirement_digest not in requirement_digests:
            issues.add("active_alignment_requirement_digest_stale:" + alignment.tag_id)
        for producer_id in alignment.producer_ids:
            capability = capability_by_producer.get(producer_id)
            if type(capability) is not ScannerCapabilitySpec:
                issues.add("active_alignment_producer_missing:" + alignment.tag_id)
                continue
            if alignment.tag_id not in capability.observable_tag_ids:
                issues.add("active_alignment_tag_not_produced:" + alignment.tag_id)
            if not set(alignment.required_observation_fields).issubset(
                capability.emitted_observation_fields
            ):
                issues.add("active_alignment_required_field_unproduced:" + alignment.tag_id)
            if not set(alignment.supported_modalities).intersection(
                capability.supported_modalities
            ):
                issues.add("active_alignment_modality_unproduced:" + alignment.tag_id)
            if not set(map(str.casefold, alignment.supported_platforms)).intersection(
                map(str.casefold, capability.supported_platforms)
            ):
                issues.add("active_alignment_platform_unproduced:" + alignment.tag_id)
    return issues


def _capability_issues(
    source_root: Path, capabilities: tuple[ScannerCapabilitySpec, ...],
) -> set[str]:
    issues: set[str] = set()
    for capability in capabilities:
        for source_path in capability.source_paths:
            relative = Path(source_path)
            if relative.is_absolute() or ".." in relative.parts:
                issues.add("capability_source_path_unsafe:" + capability.producer_id)
                continue
            if not (source_root / relative).is_file():
                issues.add("capability_source_missing:" + capability.producer_id)
        for tag_id in capability.observable_tag_ids:
            if not tag_class_for(tag_id):
                issues.add("capability_tag_missing:" + capability.producer_id + ":" + tag_id)
    return issues


def _chain_issues(chains: tuple[ChainRule, ...]) -> set[str]:
    issues: set[str] = set()
    for chain in chains:
        for step in chain.steps:
            for term in step.alternatives:
                if not tag_class_for(term):
                    issues.add("chain_tag_missing:" + chain.chain_id + ":" + term)
        for term in (*chain.optional_evidence, *chain.forbidden_evidence):
            if not tag_class_for(term):
                issues.add("chain_tag_missing:" + chain.chain_id + ":" + term)
    return issues


def _implementation_issues(
    snapshot: AttackRepositorySnapshot,
    implementations: tuple[AttackAnalyticImplementationSpec, ...],
    chain_by_id: dict[str, object],
) -> set[str]:
    issues: set[str] = set()
    for implementation in implementations:
        for chain_id in implementation.chain_ids:
            if type(chain_by_id.get(chain_id)) is not ChainRule:
                issues.add("implementation_chain_missing:" + implementation.implementation_id)
        if implementation.support_mode != "exact_official":
            continue
        strategy = snapshot.strategy_by_attack_id.get(implementation.strategy_id)
        analytic = snapshot.analytic_by_attack_id.get(implementation.analytic_id)
        if strategy is None or analytic is None:
            issues.add("official_implementation_binding_missing:" + implementation.implementation_id)
            continue
        strategy_techniques = snapshot.techniques_by_strategy_id.get(
            implementation.strategy_id, ()
        )
        strategy_analytics = snapshot.analytics_by_strategy_id.get(
            implementation.strategy_id, ()
        )
        if implementation.technique_id not in {
            item.attack_id for item in strategy_techniques
        } or implementation.analytic_id not in {
            item.attack_id for item in strategy_analytics
        }:
            issues.add("official_implementation_binding_mismatch:" + implementation.implementation_id)
        current_digest = snapshot.analytic_requirement_digest_by_id.get(
            implementation.analytic_id, ""
        )
        if current_digest != implementation.requirement_digest:
            issues.add("official_implementation_requirement_digest_mismatch:" + implementation.implementation_id)
        components = tuple(
            item.attack_id for item in snapshot.data_components_by_analytic_id.get(
                implementation.analytic_id, ()
            )
        )
        if components != implementation.required_data_component_ids:
            issues.add("official_implementation_data_components_mismatch:" + implementation.implementation_id)
    return issues


def _chain_requirements(
    chain_id: str, chain_by_id: dict[str, object], seen: frozenset[str] = frozenset(),
) -> tuple[frozenset[str], frozenset[str]]:
    if chain_id in seen:
        return frozenset(), frozenset()
    chain = chain_by_id.get(chain_id)
    if type(chain) is not ChainRule:
        return frozenset(), frozenset()
    terms: set[str] = set()
    fields = set(chain.required_fields)
    next_seen = seen | {chain_id}
    for step in chain.steps:
        for term in step.alternatives:
            if type(chain_by_id.get(term)) is ChainRule:
                nested_terms, nested_fields = _chain_requirements(
                    term, chain_by_id, next_seen,
                )
                terms.update(nested_terms)
                fields.update(nested_fields)
            else:
                terms.add(term)
    return frozenset(terms), frozenset(fields)


def _fixture_issues(
    source_root: Path,
    fixtures: tuple[AttackEndToEndFixtureSpec, ...],
    capability_by_producer: dict[str, object],
    implementation_by_id: dict[str, object],
    chain_by_id: dict[str, object],
) -> set[str]:
    issues: set[str] = set()
    for fixture in fixtures:
        implementation = implementation_by_id.get(fixture.implementation_id)
        if type(implementation) is not AttackAnalyticImplementationSpec:
            issues.add("fixture_implementation_missing:" + fixture.fixture_id)
            continue
        if fixture.technique_id != implementation.technique_id:
            issues.add("fixture_technique_mismatch:" + fixture.fixture_id)
        if fixture.input_boundary != "scanner_input" or fixture.injects_tag_or_chain_evidence:
            issues.add("fixture_bypasses_scanner_boundary:" + fixture.fixture_id)
        relative = Path(fixture.source_path)
        if relative.is_absolute() or ".." in relative.parts:
            issues.add("fixture_source_unsafe:" + fixture.fixture_id)
        elif not (source_root / relative).is_file():
            issues.add("fixture_source_missing:" + fixture.fixture_id)
        if not fixture.producer_ids:
            issues.add("fixture_producer_missing:" + fixture.fixture_id)
        producer_capabilities = tuple(
            capability_by_producer.get(producer_id)
            for producer_id in fixture.producer_ids
        )
        if any(type(item) is not ScannerCapabilitySpec for item in producer_capabilities):
            issues.add("fixture_producer_missing:" + fixture.fixture_id)
            producer_capabilities = tuple(
                item for item in producer_capabilities
                if type(item) is ScannerCapabilitySpec
            )
        if not fixture.platform or not fixture.modalities or not fixture.claim_scope:
            issues.add("fixture_context_missing:" + fixture.fixture_id)
        if fixture.claim_scope != implementation.claim_scope:
            issues.add("fixture_claim_scope_mismatch:" + fixture.fixture_id)
        if not set(fixture.modalities).intersection(implementation.required_modalities):
            issues.add("fixture_modality_mismatch:" + fixture.fixture_id)
        if fixture.platform.casefold() not in {
            item.casefold() for item in implementation.platforms
        }:
            issues.add("fixture_platform_mismatch:" + fixture.fixture_id)
        emitted_fields = frozenset(
            field for capability in producer_capabilities
            for field in capability.emitted_observation_fields
        )
        observable_tags = frozenset(
            tag for capability in producer_capabilities
            for tag in capability.observable_tag_ids
        )
        capability_modalities = frozenset(
            modality for capability in producer_capabilities
            for modality in capability.supported_modalities
        )
        capability_platforms = frozenset(
            platform.casefold() for capability in producer_capabilities
            for platform in capability.supported_platforms
        )
        if not set(fixture.modalities).issubset(capability_modalities):
            issues.add("fixture_capability_modality_unavailable:" + fixture.fixture_id)
        if (not capability_platforms
                or fixture.platform.casefold() not in capability_platforms):
            issues.add("fixture_capability_platform_unavailable:" + fixture.fixture_id)
        required_terms: set[str] = set()
        required_fields: set[str] = set()
        for chain_id in implementation.chain_ids:
            chain_terms, chain_fields = _chain_requirements(chain_id, chain_by_id)
            required_terms.update(chain_terms)
            required_fields.update(chain_fields)
        if not required_fields.issubset(emitted_fields):
            issues.add("fixture_required_field_unproduced:" + fixture.fixture_id)
        if not required_terms.issubset(observable_tags):
            issues.add("fixture_chain_term_unproduced:" + fixture.fixture_id)
    return issues


def validate_attack_release(
    snapshot: AttackRepositorySnapshot,
    *,
    alignments: tuple[TagStixAlignmentSpec, ...] = TAG_STIX_ALIGNMENT_SPECS,
    capabilities: tuple[ScannerCapabilitySpec, ...] = SCANNER_CAPABILITIES,
    implementations: tuple[AttackAnalyticImplementationSpec, ...] = ATTACK_ANALYTIC_IMPLEMENTATIONS,
    policies: tuple[AttackTechniquePolicy, ...] = ATTACK_TECHNIQUE_POLICIES,
    calibrations: tuple[AttackCalibrationArtifact, ...] = ATTACK_CALIBRATION_ARTIFACTS,
    chains: tuple[ChainRule, ...] = CANONICAL_CHAIN_RULES,
    fixtures: tuple[AttackEndToEndFixtureSpec, ...] = ATTACK_END_TO_END_FIXTURES,
    source_root: Path | None = None,
) -> AttackReleaseValidationReport:
    """Validate that every enabled mapping is real-pipeline reachable."""
    if type(snapshot) is not AttackRepositorySnapshot:
        raise TypeError("attack_release_repository_required")
    alignments = _exact_tuple(alignments, TagStixAlignmentSpec, "attack_release_alignments_invalid", 4096)
    capabilities = _exact_tuple(capabilities, ScannerCapabilitySpec, "attack_release_capabilities_invalid", 4096)
    implementations = _exact_tuple(implementations, AttackAnalyticImplementationSpec, "attack_release_implementations_invalid", 4096)
    policies = _exact_tuple(policies, AttackTechniquePolicy, "attack_release_policies_invalid", 4096)
    calibrations = _exact_tuple(
        calibrations, AttackCalibrationArtifact,
        "attack_release_calibrations_invalid", 4096,
    )
    chains = _exact_tuple(chains, ChainRule, "attack_release_chains_invalid", 16384)
    fixtures = _exact_tuple(fixtures, AttackEndToEndFixtureSpec, "attack_release_fixtures_invalid", 4096)
    if source_root is None:
        source_root = Path.cwd()
    elif type(source_root) not in (Path, PosixPath, WindowsPath):
        raise TypeError("attack_release_source_root_invalid")
    (
        capability_by_producer,
        implementation_by_id,
        policy_by_technique,
        calibration_by_id,
        chain_by_id,
        _fixture_by_id,
    ) = _indexes(
        capabilities, implementations, policies, calibrations, chains, fixtures,
    )
    issues = _alignment_issues(snapshot, alignments, capability_by_producer)
    issues.update(_capability_issues(source_root, capabilities))
    issues.update(_chain_issues(chains))
    issues.update(_implementation_issues(snapshot, implementations, chain_by_id))
    issues.update(_fixture_issues(
        source_root, fixtures, capability_by_producer, implementation_by_id,
        chain_by_id,
    ))
    fixture_implementations = {item.implementation_id for item in fixtures}
    confirmed_enabled: set[str] = set()
    confirmed_reachable: set[str] = set()
    for policy in policies:
        technique = technique_by_id(snapshot, policy.technique_id)
        if technique is None:
            issues.add("policy_technique_missing:" + policy.technique_id)
        elif technique.revoked or technique.deprecated:
            if policy.admission_state != "retired":
                issues.add("policy_lifecycle_state_mismatch:" + policy.technique_id)
        elif policy.admission_state == "retired":
            issues.add("retired_policy_technique_active:" + policy.technique_id)
        implementations_for_policy: list[AttackAnalyticImplementationSpec] = []
        for implementation_id in policy.implementation_ids:
            implementation = implementation_by_id.get(implementation_id)
            if type(implementation) is not AttackAnalyticImplementationSpec:
                issues.add("policy_implementation_missing:" + policy.technique_id)
                continue
            implementations_for_policy.append(implementation)
            if implementation.technique_id != policy.technique_id:
                issues.add("policy_implementation_technique_mismatch:" + policy.technique_id)
            if (policy.admission_state == "retired"
                    and implementation.admission_state != "quarantined"):
                issues.add("retired_policy_implementation_not_quarantined:" + policy.technique_id)
        if policy.admission_state == "production_mature":
            artifact = calibration_by_id.get(policy.calibration_artifact_id)
            if type(artifact) is not AttackCalibrationArtifact:
                issues.add("production_mature_calibration_missing:" + policy.technique_id)
            else:
                if policy.technique_id not in artifact.technique_ids:
                    issues.add("calibration_technique_mismatch:" + policy.technique_id)
                if artifact.policy_version != policy.policy_version:
                    issues.add("calibration_policy_version_mismatch:" + policy.technique_id)
                if artifact.evaluation_manifest_digest != policy.evaluation_manifest_digest:
                    issues.add("calibration_evaluation_mismatch:" + policy.technique_id)
                if artifact.requirement_digest_set != policy.requirement_digest_set:
                    issues.add("calibration_requirement_mismatch:" + policy.technique_id)
                if not set(policy.supported_claim_scopes).issubset(
                    artifact.valid_claim_scopes
                ):
                    issues.add("calibration_claim_scope_mismatch:" + policy.technique_id)
                implementation_platforms = {
                    platform
                    for implementation in implementations_for_policy
                    for platform in implementation.platforms
                }
                if not implementation_platforms.issubset(artifact.valid_platforms):
                    issues.add("calibration_platform_mismatch:" + policy.technique_id)
        if policy.admission_state not in _CONFIRMATION_STATES:
            continue
        confirmed_enabled.add(policy.technique_id)
        enabled_implementations = tuple(
            item for item in implementations_for_policy
            if item.admission_state == "confirmed_enabled"
        )
        if not enabled_implementations:
            issues.add("confirmed_policy_has_no_enabled_implementation:" + policy.technique_id)
            continue
        for implementation in enabled_implementations:
            if (not implementation.requirement_digest
                    or implementation.requirement_digest not in policy.requirement_digest_set):
                issues.add(
                    "confirmed_implementation_requirement_digest_mismatch:"
                    + implementation.implementation_id
                )
            if implementation.evaluation_manifest_digest != policy.evaluation_manifest_digest:
                issues.add(
                    "confirmed_implementation_evaluation_digest_mismatch:"
                    + implementation.implementation_id
                )
        missing_fixture = tuple(
            item for item in enabled_implementations
            if item.implementation_id not in fixture_implementations
        )
        if missing_fixture:
            issues.add("confirmed_implementation_fixture_missing:" + policy.technique_id)
            continue
        related_ids = {policy.technique_id}
        related_ids.update(item.implementation_id for item in enabled_implementations)
        related_ids.update(
            chain_id for item in enabled_implementations for chain_id in item.chain_ids
        )
        related_ids.update(
            fixture.fixture_id for fixture in fixtures
            if fixture.implementation_id in {
                item.implementation_id for item in enabled_implementations
            }
        )
        if not any(
            any(":" + identity in code for identity in related_ids)
            for code in issues
        ):
            confirmed_reachable.add(policy.technique_id)
    if set(policy_by_technique) != {item.technique_id for item in policies}:
        raise ValueError("attack_release_policy_index_invalid")
    values = {
        "repository_digest": snapshot.digest,
        "confirmed_enabled_technique_ids": tuple(sorted(confirmed_enabled)),
        "confirmed_reachable_technique_ids": tuple(sorted(confirmed_reachable)),
        "issue_codes": tuple(sorted(issues)),
        "alignment_count": len(alignments),
        "capability_count": len(capabilities),
        "implementation_count": len(implementations),
        "policy_count": len(policies),
        "calibration_count": len(calibrations),
        "chain_count": len(chains),
        "fixture_count": len(fixtures),
        "version": ATTACK_RELEASE_VALIDATION_VERSION,
    }
    return AttackReleaseValidationReport(
        **values,
        report_digest=_report_digest(values),
    )


__all__ = (
    "ATTACK_END_TO_END_FIXTURES",
    "ATTACK_FIXTURE_BOUNDARIES",
    "ATTACK_RELEASE_VALIDATION_VERSION",
    "AttackEndToEndFixtureSpec",
    "AttackReleaseValidationReport",
    "validate_attack_release",
)
