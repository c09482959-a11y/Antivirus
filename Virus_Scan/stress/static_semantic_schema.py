"""Immutable contracts for the Stage2636.11020 static-semantic corpus."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

STATIC_SEMANTIC_CORPUS_SCHEMA_VERSION = "stage2636_11020_static_semantic_corpus_v4"
STATIC_SEMANTIC_RENDERER_VERSION = "stage2636_11020_static_semantic_renderer_v3"
STATIC_SEMANTIC_ORACLE_VERSION = "stage2636_11020_artifact_byte_oracle_v5"
STATIC_SEMANTIC_ORACLE_VALIDATOR_VERSION = "stage2636_11020_artifact_byte_oracle_validator_v4"
STATIC_SEMANTIC_SAFETY_VERSION = "stage2636_11020_static_semantic_safety_v2"
STATIC_SEMANTIC_MASTER_SEED = "stage2636.11020:phase37:2026-08-15:inert"
STATIC_SEMANTIC_REVIEWED_TECHNIQUES = (
    "T1003", "T1021", "T1041", "T1055",
    "T1059", "T1059.001", "T1105", "T1562.001",
)
STATIC_SEMANTIC_PARTITION_SCHEDULE = (
    ("development", "2026-03-01T00:00:00Z", "static-semantic-development-v1"),
    ("validation", "2026-04-01T00:00:00Z", "static-semantic-validation-v1"),
    ("locked_holdout", "2026-05-01T00:00:00Z", "static-semantic-locked-v1"),
    ("future_time_holdout", "2026-07-01T00:00:00Z", "static-semantic-future-v1"),
)
STATIC_SEMANTIC_PARTITION_BY_ID = MappingProxyType({
    partition: (collected_at, seed)
    for partition, collected_at, seed in STATIC_SEMANTIC_PARTITION_SCHEDULE
})
_ALLOWED_RENDERERS = frozenset({"text", "nested_zip", "managed_pe", "native_elf_x86_64"})
_ALLOWED_PARSER_STATES = frozenset({"complete", "partial", "failed", "unavailable"})
_ALLOWED_IMPLEMENTATION_STATES = frozenset({
    "expected", "not_expected", "conditional", "unavailable",
})
_ALLOWED_REACHABILITY = frozenset({
    "entrypoint_reachable", "locally_reachable", "conditionally_reachable", "unreachable",
})


def _text_tuple(value: object, reason: str, *, limit: int = 128) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > limit:
        raise TypeError(reason)
    out = tuple(
        exact_bounded_text(item, reason, maximum=512)
        for item in value
    )
    if len(set(out)) != len(out):
        raise ValueError(reason)
    return out


@dataclass(frozen=True, slots=True, order=True)
class StaticReachabilityTruth:
    operation_kind: str
    reachability_state: str
    minimum_count: int = 1

    def __post_init__(self) -> None:
        if type(self) is not StaticReachabilityTruth:
            raise TypeError("static_semantic_reachability_owner_invalid")
        kind = exact_bounded_text(
            self.operation_kind, "static_semantic_operation_kind_invalid", maximum=96,
        )
        state = exact_bounded_text(
            self.reachability_state, "static_semantic_reachability_invalid", maximum=32,
        )
        if state not in _ALLOWED_REACHABILITY:
            raise ValueError("static_semantic_reachability_invalid")
        if type(self.minimum_count) is not int or type(self.minimum_count) is bool:
            raise TypeError("static_semantic_reachability_count_invalid")
        if self.minimum_count < 1 or self.minimum_count > 64:
            raise ValueError("static_semantic_reachability_count_invalid")
        object.__setattr__(self, "operation_kind", kind)
        object.__setattr__(self, "reachability_state", state)

    def to_record(self) -> dict[str, object]:
        return {
            "minimum_count": self.minimum_count,
            "operation_kind": self.operation_kind,
            "reachability_state": self.reachability_state,
        }


@dataclass(frozen=True, slots=True, order=True)
class StaticFlowTruth:
    """Independent source→sink relation recovered from artifact bytes.

    ``connected`` states whether the sink consumes/depends on the source value.
    ``same_resource`` is tri-state: ``True``/``False`` when the artifact proves
    the relation targets the same/different resource, and ``None`` when that
    identity relationship is not applicable or cannot be recovered.
    """

    source_operation_kind: str
    sink_operation_kind: str
    connected: bool
    same_resource: bool | None = None

    def __post_init__(self) -> None:
        if type(self) is not StaticFlowTruth:
            raise TypeError("static_semantic_flow_owner_invalid")
        source = exact_bounded_text(
            self.source_operation_kind, "static_semantic_flow_source_invalid", maximum=96,
        )
        sink = exact_bounded_text(
            self.sink_operation_kind, "static_semantic_flow_sink_invalid", maximum=96,
        )
        if type(self.connected) is not bool:
            raise TypeError("static_semantic_flow_connected_invalid")
        if self.same_resource is not None and type(self.same_resource) is not bool:
            raise TypeError("static_semantic_flow_same_resource_invalid")
        object.__setattr__(self, "source_operation_kind", source)
        object.__setattr__(self, "sink_operation_kind", sink)

    def to_record(self) -> dict[str, object]:
        return {
            "connected": self.connected,
            "same_resource": self.same_resource,
            "sink_operation_kind": self.sink_operation_kind,
            "source_operation_kind": self.source_operation_kind,
        }


@dataclass(frozen=True, slots=True)
class CorpusGenerationIntent:
    """Hidden evaluation-only desired behavior. This contract has zero evidence authority."""

    generation_id: str
    malware_class: str
    coverage_cohort: str
    desired_parser_status: str
    desired_literal_references: tuple[str, ...]
    desired_operation_kinds: tuple[str, ...]
    forbidden_operation_kinds: tuple[str, ...]
    desired_reachability: tuple[StaticReachabilityTruth, ...]
    desired_flow: tuple[StaticFlowTruth, ...]
    desired_technique_ids: tuple[str, ...]
    desired_artifact_implementation_state: str
    generation_seed: str
    unresolved_states: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self) is not CorpusGenerationIntent:
            raise TypeError("corpus_generation_intent_owner_invalid")
        generation_id = exact_bounded_text(
            self.generation_id, "corpus_generation_id_invalid", maximum=128,
        )
        malware_class = exact_bounded_text(
            self.malware_class, "corpus_generation_class_invalid", maximum=16,
        )
        if malware_class not in {"malware", "control"}:
            raise ValueError("corpus_generation_class_invalid")
        coverage_cohort = exact_bounded_text(
            self.coverage_cohort, "corpus_generation_cohort_invalid", maximum=64,
        )
        parser_status = exact_bounded_text(
            self.desired_parser_status, "corpus_generation_parser_status_invalid", maximum=32,
        )
        if parser_status not in _ALLOWED_PARSER_STATES:
            raise ValueError("corpus_generation_parser_status_invalid")
        implementation_state = exact_bounded_text(
            self.desired_artifact_implementation_state,
            "corpus_generation_implementation_state_invalid",
            maximum=32,
        )
        if implementation_state not in _ALLOWED_IMPLEMENTATION_STATES:
            raise ValueError("corpus_generation_implementation_state_invalid")
        generation_seed = exact_bounded_text(
            self.generation_seed, "corpus_generation_seed_invalid", maximum=192,
        )
        literals = _text_tuple(
            self.desired_literal_references,
            "corpus_generation_literal_references_invalid",
        )
        operations = _text_tuple(
            self.desired_operation_kinds,
            "corpus_generation_desired_operations_invalid",
        )
        forbidden = _text_tuple(
            self.forbidden_operation_kinds,
            "corpus_generation_forbidden_operations_invalid",
        )
        if set(operations) & set(forbidden):
            raise ValueError("corpus_generation_operation_truth_overlap")
        if (
            type(self.desired_reachability) is not tuple
            or any(type(item) is not StaticReachabilityTruth for item in self.desired_reachability)
        ):
            raise TypeError("corpus_generation_reachability_invalid")
        if (
            type(self.desired_flow) is not tuple
            or any(type(item) is not StaticFlowTruth for item in self.desired_flow)
        ):
            raise TypeError("corpus_generation_flow_invalid")
        techniques = _text_tuple(
            self.desired_technique_ids,
            "corpus_generation_techniques_invalid",
            limit=32,
        )
        if any(item not in STATIC_SEMANTIC_REVIEWED_TECHNIQUES for item in techniques):
            raise ValueError("corpus_generation_techniques_invalid")
        unresolved = _text_tuple(
            self.unresolved_states, "corpus_generation_unresolved_states_invalid",
        )
        object.__setattr__(self, "generation_id", generation_id)
        object.__setattr__(self, "malware_class", malware_class)
        object.__setattr__(self, "coverage_cohort", coverage_cohort)
        object.__setattr__(self, "desired_parser_status", parser_status)
        object.__setattr__(self, "desired_artifact_implementation_state", implementation_state)
        object.__setattr__(self, "generation_seed", generation_seed)
        object.__setattr__(self, "desired_literal_references", literals)
        object.__setattr__(self, "desired_operation_kinds", operations)
        object.__setattr__(self, "forbidden_operation_kinds", forbidden)
        object.__setattr__(self, "desired_technique_ids", techniques)
        object.__setattr__(self, "unresolved_states", unresolved)

    def to_hidden_record(self) -> dict[str, object]:
        return {
            "coverage_cohort": self.coverage_cohort,
            "desired_artifact_implementation_state": self.desired_artifact_implementation_state,
            "desired_flow": tuple(item.to_record() for item in self.desired_flow),
            "desired_literal_references": self.desired_literal_references,
            "desired_operation_kinds": self.desired_operation_kinds,
            "desired_parser_status": self.desired_parser_status,
            "desired_reachability": tuple(item.to_record() for item in self.desired_reachability),
            "desired_technique_ids": self.desired_technique_ids,
            "forbidden_operation_kinds": self.forbidden_operation_kinds,
            "generation_id": self.generation_id,
            "generation_seed": self.generation_seed,
            "malware_class": self.malware_class,
            "unresolved_states": self.unresolved_states,
        }


@dataclass(frozen=True, slots=True)
class ArtifactRendererSpecification:
    """Artifact-production instructions only; contains no expected ATT&CK decision."""

    renderer_kind: str
    extension: str
    member_extension: str
    language: str
    platform: str
    source_text: str
    fixture_variant: str = ""
    safety_constraints: tuple[str, ...] = (
        "inert_never_execute",
        "bounded_artifact",
    )

    def __post_init__(self) -> None:
        if type(self) is not ArtifactRendererSpecification:
            raise TypeError("artifact_renderer_specification_owner_invalid")
        renderer_kind = exact_bounded_text(
            self.renderer_kind, "artifact_renderer_kind_invalid", maximum=32,
        )
        if renderer_kind not in _ALLOWED_RENDERERS:
            raise ValueError("artifact_renderer_kind_invalid")
        extension = exact_bounded_text(
            self.extension, "artifact_renderer_extension_invalid", maximum=16,
        )
        if not extension.startswith("."):
            raise ValueError("artifact_renderer_extension_invalid")
        member_extension = exact_bounded_text(
            self.member_extension,
            "artifact_renderer_member_extension_invalid",
            maximum=16,
            allow_blank=True,
        )
        if renderer_kind == "nested_zip":
            if extension != ".zip" or not member_extension.startswith("."):
                raise ValueError("artifact_renderer_archive_extension_invalid")
        elif member_extension:
            raise ValueError("artifact_renderer_member_extension_unexpected")
        fixture_variant = exact_bounded_text(
            self.fixture_variant,
            "artifact_renderer_fixture_variant_invalid",
            maximum=64,
            allow_blank=renderer_kind in {"text", "nested_zip"},
        )
        if renderer_kind in {"managed_pe", "native_elf_x86_64"}:
            if not fixture_variant:
                raise ValueError("artifact_renderer_fixture_variant_invalid")
        elif fixture_variant:
            raise ValueError("artifact_renderer_fixture_variant_unexpected")
        if renderer_kind == "managed_pe" and extension not in {".exe", ".dll"}:
            raise ValueError("artifact_renderer_managed_pe_extension_invalid")
        if renderer_kind == "native_elf_x86_64" and extension != ".elf":
            raise ValueError("artifact_renderer_native_elf_extension_invalid")
        language = exact_bounded_text(
            self.language, "artifact_renderer_language_invalid", maximum=32,
        )
        platform = exact_bounded_text(
            self.platform, "artifact_renderer_platform_invalid", maximum=64,
        )
        if type(self.source_text) is not str or not self.source_text or len(self.source_text) > 131_072:
            raise ValueError("artifact_renderer_source_text_invalid")
        safety_constraints = _text_tuple(
            self.safety_constraints,
            "artifact_renderer_safety_constraints_invalid",
            limit=16,
        )
        if "inert_never_execute" not in safety_constraints:
            raise ValueError("artifact_renderer_safety_constraints_invalid")
        object.__setattr__(self, "renderer_kind", renderer_kind)
        object.__setattr__(self, "extension", extension)
        object.__setattr__(self, "member_extension", member_extension)
        object.__setattr__(self, "language", language)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "fixture_variant", fixture_variant)
        object.__setattr__(self, "safety_constraints", safety_constraints)

    def to_record(self) -> dict[str, object]:
        return {
            "extension": self.extension,
            "fixture_variant": self.fixture_variant,
            "language": self.language,
            "member_extension": self.member_extension,
            "platform": self.platform,
            "renderer_kind": self.renderer_kind,
            "safety_constraints": self.safety_constraints,
            "source_text": self.source_text,
        }


@dataclass(frozen=True, slots=True)
class CorpusFixtureDefinition:
    """Evaluation-only composition of hidden intent and renderer specification."""

    generation_intent: CorpusGenerationIntent
    renderer_specification: ArtifactRendererSpecification

    def __post_init__(self) -> None:
        if (
            type(self) is not CorpusFixtureDefinition
            or type(self.generation_intent) is not CorpusGenerationIntent
            or type(self.renderer_specification) is not ArtifactRendererSpecification
        ):
            raise TypeError("corpus_fixture_definition_owner_invalid")

    def to_hidden_record(self) -> dict[str, object]:
        return {
            "generation_intent": self.generation_intent.to_hidden_record(),
            "renderer_specification": self.renderer_specification.to_record(),
        }


@dataclass(frozen=True, slots=True)
class CorpusGenerationRecord:
    """Hidden evaluation record. Renderer receives only its renderer specification."""

    sample_id: str
    partition: str
    partition_seed: str
    collected_at: str
    fixture_definition: CorpusFixtureDefinition

    def __post_init__(self) -> None:
        if (
            type(self) is not CorpusGenerationRecord
            or type(self.fixture_definition) is not CorpusFixtureDefinition
        ):
            raise TypeError("corpus_generation_record_owner_invalid")
        sample_id = exact_bounded_text(
            self.sample_id, "corpus_generation_sample_id_invalid", maximum=128,
        )
        partition = exact_bounded_text(
            self.partition, "corpus_generation_partition_invalid", maximum=32,
        )
        if partition not in STATIC_SEMANTIC_PARTITION_BY_ID:
            raise ValueError("corpus_generation_partition_invalid")
        seed = exact_bounded_text(
            self.partition_seed, "corpus_generation_partition_seed_invalid", maximum=128,
        )
        collected = exact_bounded_text(
            self.collected_at, "corpus_generation_collected_at_invalid", maximum=32,
        )
        if (collected, seed) != STATIC_SEMANTIC_PARTITION_BY_ID[partition]:
            raise ValueError("corpus_generation_partition_schedule_invalid")
        object.__setattr__(self, "sample_id", sample_id)
        object.__setattr__(self, "partition", partition)
        object.__setattr__(self, "partition_seed", seed)
        object.__setattr__(self, "collected_at", collected)

    def to_hidden_record(self) -> dict[str, object]:
        return {
            "collected_at": self.collected_at,
            "fixture_definition": self.fixture_definition.to_hidden_record(),
            "partition": self.partition,
            "partition_seed": self.partition_seed,
            "sample_id": self.sample_id,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_hidden_record())


@dataclass(frozen=True, slots=True)
class ArtifactEvidenceTruth:
    """Evaluation truth derived from rendered artifact bytes, never generator labels."""

    sample_id: str
    artifact_sha256: str
    artifact_size: int
    artifact_format: str
    platform: str
    parser_status: str
    operation_kinds: tuple[str, ...]
    reachability: tuple[StaticReachabilityTruth, ...]
    flow: tuple[StaticFlowTruth, ...]
    resource_identities: tuple[str, ...] = ()
    resolved_call_identities: tuple[str, ...] = ()
    resolved_import_identities: tuple[str, ...] = ()
    resolved_syscall_identities: tuple[str, ...] = ()
    analysis_limitations: tuple[str, ...] = ()
    evidence_completeness: str = "complete"

    def __post_init__(self) -> None:
        if type(self) is not ArtifactEvidenceTruth:
            raise TypeError("artifact_evidence_truth_owner_invalid")
        sample_id = exact_bounded_text(self.sample_id, "artifact_evidence_truth_sample_id_invalid", maximum=128)
        digest = exact_bounded_text(self.artifact_sha256, "artifact_evidence_truth_digest_invalid", maximum=64)
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("artifact_evidence_truth_digest_invalid")
        if type(self.artifact_size) is not int or type(self.artifact_size) is bool or not (1 <= self.artifact_size <= 1_048_576):
            raise ValueError("artifact_evidence_truth_size_invalid")
        artifact_format = exact_bounded_text(self.artifact_format, "artifact_evidence_truth_format_invalid", maximum=64)
        platform = exact_bounded_text(self.platform, "artifact_evidence_truth_platform_invalid", maximum=64)
        parser_status = exact_bounded_text(self.parser_status, "artifact_evidence_truth_parser_status_invalid", maximum=32)
        if parser_status not in _ALLOWED_PARSER_STATES:
            raise ValueError("artifact_evidence_truth_parser_status_invalid")
        completeness = exact_bounded_text(self.evidence_completeness, "artifact_evidence_truth_completeness_invalid", maximum=32)
        if completeness not in {"complete", "partial", "unavailable"}:
            raise ValueError("artifact_evidence_truth_completeness_invalid")
        operations = _text_tuple(self.operation_kinds, "artifact_evidence_truth_operations_invalid")
        if type(self.reachability) is not tuple or any(type(item) is not StaticReachabilityTruth for item in self.reachability):
            raise TypeError("artifact_evidence_truth_reachability_invalid")
        if type(self.flow) is not tuple or any(type(item) is not StaticFlowTruth for item in self.flow):
            raise TypeError("artifact_evidence_truth_flow_invalid")
        tuple_fields = {
            "resource_identities": "artifact_evidence_truth_resources_invalid",
            "resolved_call_identities": "artifact_evidence_truth_calls_invalid",
            "resolved_import_identities": "artifact_evidence_truth_imports_invalid",
            "resolved_syscall_identities": "artifact_evidence_truth_syscalls_invalid",
            "analysis_limitations": "artifact_evidence_truth_limitations_invalid",
        }
        for field, reason in tuple_fields.items():
            object.__setattr__(self, field, _text_tuple(getattr(self, field), reason))
        object.__setattr__(self, "sample_id", sample_id)
        object.__setattr__(self, "artifact_sha256", digest)
        object.__setattr__(self, "artifact_format", artifact_format)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "parser_status", parser_status)
        object.__setattr__(self, "operation_kinds", operations)
        object.__setattr__(self, "evidence_completeness", completeness)

    def to_record(self) -> dict[str, object]:
        return {
            "analysis_limitations": self.analysis_limitations,
            "artifact_format": self.artifact_format,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "evidence_completeness": self.evidence_completeness,
            "flow": tuple(item.to_record() for item in self.flow),
            "operation_kinds": self.operation_kinds,
            "parser_status": self.parser_status,
            "platform": self.platform,
            "reachability": tuple(item.to_record() for item in self.reachability),
            "resolved_call_identities": self.resolved_call_identities,
            "resolved_import_identities": self.resolved_import_identities,
            "resolved_syscall_identities": self.resolved_syscall_identities,
            "resource_identities": self.resource_identities,
            "sample_id": self.sample_id,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_record())


@dataclass(frozen=True, slots=True)
class ExpectedAttackDecision:
    """Evaluation-only projection of artifact truth through frozen local policy."""

    technique_id: str
    artifact_evidence_digest: str
    policy_manifest_digest: str
    artifact_behavior_satisfied: bool | None
    policy_decision: str

    def __post_init__(self) -> None:
        if type(self) is not ExpectedAttackDecision:
            raise TypeError("expected_attack_decision_owner_invalid")
        technique_id = exact_bounded_text(self.technique_id, "expected_attack_decision_technique_invalid", maximum=32)
        if technique_id not in STATIC_SEMANTIC_REVIEWED_TECHNIQUES:
            raise ValueError("expected_attack_decision_technique_invalid")
        for field in ("artifact_evidence_digest", "policy_manifest_digest"):
            value = exact_bounded_text(getattr(self, field), "expected_attack_decision_digest_invalid", maximum=64)
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("expected_attack_decision_digest_invalid")
            object.__setattr__(self, field, value)
        if self.artifact_behavior_satisfied is not None and type(self.artifact_behavior_satisfied) is not bool:
            raise TypeError("expected_attack_decision_behavior_invalid")
        decision = exact_bounded_text(self.policy_decision, "expected_attack_decision_policy_invalid", maximum=32)
        if decision not in {"candidate", "confirmed", "rejected", "unavailable"}:
            raise ValueError("expected_attack_decision_policy_invalid")
        object.__setattr__(self, "technique_id", technique_id)
        object.__setattr__(self, "policy_decision", decision)

    def to_record(self) -> dict[str, object]:
        return {
            "artifact_behavior_satisfied": self.artifact_behavior_satisfied,
            "artifact_evidence_digest": self.artifact_evidence_digest,
            "policy_decision": self.policy_decision,
            "policy_manifest_digest": self.policy_manifest_digest,
            "technique_id": self.technique_id,
        }



__all__ = (
    "STATIC_SEMANTIC_CORPUS_SCHEMA_VERSION",
    "STATIC_SEMANTIC_MASTER_SEED",
    "STATIC_SEMANTIC_ORACLE_VALIDATOR_VERSION",
    "STATIC_SEMANTIC_ORACLE_VERSION",
    "STATIC_SEMANTIC_PARTITION_BY_ID",
    "STATIC_SEMANTIC_PARTITION_SCHEDULE",
    "STATIC_SEMANTIC_RENDERER_VERSION",
    "STATIC_SEMANTIC_REVIEWED_TECHNIQUES",
    "STATIC_SEMANTIC_SAFETY_VERSION",
    "ArtifactEvidenceTruth",
    "ArtifactRendererSpecification",
    "CorpusFixtureDefinition",
    "CorpusGenerationIntent",
    "CorpusGenerationRecord",
    "ExpectedAttackDecision",
    "StaticFlowTruth",
    "StaticReachabilityTruth",
)
