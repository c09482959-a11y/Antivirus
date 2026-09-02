"""Canonical inert Phase 25 static-semantic evaluation corpus owner."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PosixPath, WindowsPath
import shutil

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.core.jsonio import atomic_json_save
from Virus_Scan.runtime.api import (
    durable_activate_directory,
    flush_directory,
    flush_existing_regular_file,
)
from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_PARTITIONS,
    AttackEvaluationCorpusManifest,
    AttackEvaluationPartitionCount,
    AttackEvaluationSample,
)
from Virus_Scan.detection.attack.versioning import (
    ATTACK_MAPPING_POLICY_VERSION,
    ATTACK_REPOSITORY_SCHEMA_VERSION,
)
from Virus_Scan.stress.artifact_attack_projection import (
    artifact_attack_expectations,
    artifact_behavior_satisfied,
)
from Virus_Scan.stress.artifact_evidence_oracle import derive_artifact_evidence_truth
from Virus_Scan.stress.artifact_evidence_oracle_validator import validate_artifact_evidence_truth
from Virus_Scan.stress.artifact_generation_reconciliation import reconcile_generation_intent_with_artifact_truth
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_safety import validate_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import (
    STATIC_SEMANTIC_CORPUS_SCHEMA_VERSION,
    STATIC_SEMANTIC_MASTER_SEED,
    STATIC_SEMANTIC_ORACLE_VALIDATOR_VERSION,
    STATIC_SEMANTIC_ORACLE_VERSION,
    STATIC_SEMANTIC_PARTITION_SCHEDULE,
    STATIC_SEMANTIC_RENDERER_VERSION,
    STATIC_SEMANTIC_REVIEWED_TECHNIQUES,
    STATIC_SEMANTIC_SAFETY_VERSION,
    CorpusGenerationRecord,
)
from Virus_Scan.stress.static_semantic_templates import STATIC_SEMANTIC_FIXTURES

STATIC_SEMANTIC_CORPUS_VERSION = "stage2636_11020_static_semantic_evaluation_v6"
STATIC_SEMANTIC_LABEL_POLICY_VERSION = "stage2636_11020_static_semantic_label_policy_v6"
STATIC_SEMANTIC_POLICY_FROZEN_AT = "2026-06-01T00:00:00Z"
STATIC_SEMANTIC_MANIFEST_FROZEN_AT = "2026-07-20T00:00:00Z"
STATIC_SEMANTIC_SAMPLE_COUNT = 96
STATIC_SEMANTIC_MALWARE_COUNT = 48
STATIC_SEMANTIC_CONTROL_COUNT = 48
STATIC_SEMANTIC_SIDECAR_FILENAMES = (
    "static_semantic_generation_intent_manifest.json",
    "static_semantic_artifact_truth_manifest.json",
    "static_semantic_artifact_truth_validation.json",
    "static_semantic_safety_report.json",
    "static_semantic_leakage_report.json",
    "static_semantic_coverage_report.json",
)
_PATH_TYPES = (PosixPath, WindowsPath)


def _path(value: object, reason: str) -> Path:
    if type(value) not in _PATH_TYPES:
        raise TypeError(reason)
    return value


def _generation_policy_digest() -> str:
    return canonical_json_sha256({
        "corpus_schema": STATIC_SEMANTIC_CORPUS_SCHEMA_VERSION,
        "label_policy": STATIC_SEMANTIC_LABEL_POLICY_VERSION,
        "master_seed": STATIC_SEMANTIC_MASTER_SEED,
        "oracle_validator_version": STATIC_SEMANTIC_ORACLE_VALIDATOR_VERSION,
        "oracle_version": STATIC_SEMANTIC_ORACLE_VERSION,
        "partition_schedule": STATIC_SEMANTIC_PARTITION_SCHEDULE,
        "renderer_version": STATIC_SEMANTIC_RENDERER_VERSION,
        "reviewed_techniques": STATIC_SEMANTIC_REVIEWED_TECHNIQUES,
        "safety_version": STATIC_SEMANTIC_SAFETY_VERSION,
        "fixtures": tuple(item.to_hidden_record() for item in STATIC_SEMANTIC_FIXTURES),
    })


STATIC_SEMANTIC_GENERATION_POLICY_DIGEST = _generation_policy_digest()


@dataclass(frozen=True, slots=True)
class StaticSemanticCorpusBuild:
    manifest: AttackEvaluationCorpusManifest
    pending_artifacts: tuple[tuple[Path, bytes], ...]
    sidecars: tuple[tuple[str, dict[str, object]], ...]


def _report(version: str, records: tuple[object, ...], **summary: object) -> dict[str, object]:
    base = {"records": records, "version": version, **summary}
    return {**base, "digest": canonical_json_sha256(base)}


def _sample_id(partition: str, template_index: int, malware_class: str) -> str:
    material = (
        STATIC_SEMANTIC_MASTER_SEED + ":sample:" + partition + ":"
        + malware_class + ":" + str(template_index)
    )
    return "static-semantic-" + sha256(material.encode("utf-8")).hexdigest()[:24]


def _opaque_identity(*parts: object) -> str:
    material = ":".join(str(part) for part in parts)
    return sha256(
        (STATIC_SEMANTIC_MASTER_SEED + ":identity:" + material).encode("utf-8")
    ).hexdigest()[:20]


def _sample(
    *,
    partition: str,
    collected_at: str,
    partition_seed: str,
    fixture_index: int,
) -> tuple[
    AttackEvaluationSample,
    bytes,
    CorpusGenerationRecord,
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    fixture = STATIC_SEMANTIC_FIXTURES[fixture_index]
    intent = fixture.generation_intent
    renderer = fixture.renderer_specification
    sample_id = _sample_id(partition, fixture_index, intent.malware_class)
    generation = CorpusGenerationRecord(
        sample_id=sample_id,
        partition=partition,
        partition_seed=partition_seed,
        collected_at=collected_at,
        fixture_definition=fixture,
    )
    payload = render_static_semantic_artifact(sample_id, renderer)
    artifact_digest = sha256(payload).hexdigest()
    safety = validate_static_semantic_artifact(
        sample_id,
        payload,
        renderer_kind=renderer.renderer_kind,
        fixture_variant=renderer.fixture_variant,
    )
    if safety.safe is not True:
        raise ValueError("static_semantic_safety_rejected:" + sample_id)
    portable_path = Path("artifacts") / (sample_id + renderer.extension)
    truth = derive_artifact_evidence_truth(sample_id, portable_path.name, payload)
    expectations = artifact_attack_expectations(truth, STATIC_SEMANTIC_REVIEWED_TECHNIQUES)
    validation = validate_artifact_evidence_truth(
        sample_id, portable_path.name, payload, truth, expectations,
    )
    if validation["agreement"] is not True:
        raise ValueError("static_semantic_artifact_truth_disagreement:" + sample_id)
    # Hidden generation intent is used only to verify that the renderer actually
    # produced the intended physical challenge.  It never creates oracle truth.
    reconcile_generation_intent_with_artifact_truth(
        intent, truth, reason_prefix="static_semantic",
    )
    for technique_id in intent.desired_technique_ids:
        if artifact_behavior_satisfied(truth, technique_id) is not True:
            raise ValueError("static_semantic_generation_technique_behavior_missing:" + sample_id + ":" + technique_id)
    family = _opaque_identity("family", partition, intent.generation_id)
    group = _opaque_identity("group", partition, intent.generation_id)
    campaign = _opaque_identity("campaign", partition, intent.generation_id)
    session = _opaque_identity("session", partition, intent.generation_id)
    sample = AttackEvaluationSample(
        sample_id=sample_id,
        partition=partition,
        source_family="static-semantic-family-" + family,
        related_group="static-semantic-group-" + group,
        package_campaign_id="static-semantic-campaign-" + campaign,
        collection_session="static-semantic-session-" + session,
        malware_class=intent.malware_class,
        sample_category=intent.coverage_cohort,
        artifact_path=portable_path.as_posix(),
        artifact_sha256=artifact_digest,
        artifact_size=len(payload),
        acquisition_provenance=(
            "Deterministic inert artifact rendered from a renderer-only specification; "
            "hidden generation intent has zero production evidence authority."
        ),
        collected_at=collected_at,
        platform=truth.platform,
        file_type=truth.artifact_format,
        technique_expectations=expectations,
        evidence_domain="synthetic_engineering",
        eligible_for_production_metrics=False,
        eligible_for_policy_promotion=False,
        eligible_for_production_calibration=False,
    )
    oracle_record = {
        **truth.to_record(),
        "artifact_evidence_digest": truth.digest,
        "attack_expectations": tuple(item.to_record() for item in expectations),
    }
    return (
        sample,
        payload,
        generation,
        oracle_record,
        validation,
        safety.to_record(),
    )

def _partition_counts() -> tuple[AttackEvaluationPartitionCount, ...]:
    counts = {
        partition: {"malware": 0, "control": 0}
        for partition in ATTACK_EVALUATION_PARTITIONS
    }
    for partition, _collected_at, _seed in STATIC_SEMANTIC_PARTITION_SCHEDULE:
        for fixture in STATIC_SEMANTIC_FIXTURES:
            counts[partition][fixture.generation_intent.malware_class] += 1
    return tuple(
        AttackEvaluationPartitionCount(
            partition,
            counts[partition]["malware"],
            counts[partition]["control"],
        )
        for partition in ATTACK_EVALUATION_PARTITIONS
    )


def _leakage_report(
    samples: tuple[AttackEvaluationSample, ...],
    artifacts: tuple[tuple[Path, bytes], ...],
) -> dict[str, object]:
    """Reject scanner-visible class/template/evaluation labels and split leakage."""
    if len(samples) != len(artifacts):
        raise ValueError("static_semantic_leakage_input_count_mismatch")
    identities: dict[tuple[str, str], str] = {}
    violations: list[str] = []
    generation_tokens = tuple(
        item.generation_intent.generation_id.casefold() for item in STATIC_SEMANTIC_FIXTURES
    )
    for sample, (artifact_path, payload) in zip(samples, artifacts, strict=True):
        for dimension, identity in (
            ("source_family", sample.source_family),
            ("related_group", sample.related_group),
            ("package_campaign_id", sample.package_campaign_id),
            ("collection_session", sample.collection_session),
        ):
            prior = identities.setdefault((dimension, identity), sample.partition)
            if prior != sample.partition:
                violations.append(dimension + ":cross_partition:" + identity)
            lowered = identity.casefold()
            if any(token in lowered for token in ("malware", "control", "template", "t1055", "t1059")):
                violations.append(dimension + ":hidden_label:" + sample.sample_id)
        normalized_path = artifact_path.as_posix().casefold()
        if (
            "/malware/" in normalized_path
            or "/control/" in normalized_path
            or any(token in normalized_path for token in generation_tokens)
        ):
            violations.append("artifact_path:hidden_label:" + sample.sample_id)
        if any(
            marker in payload
            for marker in (b"template_id=", b"malware_class=", b"partition=")
        ):
            violations.append("artifact_payload:hidden_label:" + sample.sample_id)
    ordered = tuple(sorted(set(violations)))
    return _report(
        STATIC_SEMANTIC_CORPUS_SCHEMA_VERSION,
        ordered,
        group_identity_count=len(identities),
        public_artifact_count=len(artifacts),
        violation_count=len(ordered),
    )


def _coverage_report(
    samples: tuple[AttackEvaluationSample, ...],
    generation_records: tuple[dict[str, object], ...],
) -> dict[str, object]:
    fixtures = STATIC_SEMANTIC_FIXTURES
    intents = tuple(item.generation_intent for item in fixtures)
    renderers = tuple(item.renderer_specification for item in fixtures)
    parser_status_counts = tuple(sorted({
        status: sum(item.desired_parser_status == status for item in intents)
        for status in {item.desired_parser_status for item in intents}
    }.items()))
    language_counts = tuple(sorted({
        language: sum(item.language == language for item in renderers)
        for language in {item.language for item in renderers}
    }.items()))
    category_counts = tuple(sorted({
        category: sum(item.coverage_cohort == category for item in intents)
        for category in {item.coverage_cohort for item in intents}
    }.items()))
    base = {
        "archive_fixture_count": sum(item.renderer_kind == "nested_zip" for item in renderers),
        "bounded_decode_fixture_count": sum(
            "decode" in item.desired_operation_kinds for item in intents
        ),
        "managed_pe_fixture_count": sum(item.renderer_kind == "managed_pe" for item in renderers),
        "native_elf_fixture_count": sum(
            item.renderer_kind == "native_elf_x86_64" for item in renderers
        ),
        "artifact_implementation_desired_count": sum(
            item.desired_artifact_implementation_state in {"expected", "conditional"}
            for item in intents
        ),
        "category_counts": category_counts,
        "disconnected_flow_fixture_count": sum(
            any(flow.connected is False for flow in item.desired_flow) for item in intents
        ),
        "language_counts": language_counts,
        "generation_record_count": len(generation_records),
        "malware_sample_count": sum(item.malware_class == "malware" for item in samples),
        "control_sample_count": sum(item.malware_class == "control" for item in samples),
        "parser_status_counts": parser_status_counts,
        "runtime_occurrence_expected_count": 0,
        "sample_count": len(samples),
        "fixture_count": len(fixtures),
        "unreachable_fixture_count": sum(
            any(reach.reachability_state == "unreachable" for reach in item.desired_reachability)
            for item in intents
        ),
        "version": STATIC_SEMANTIC_CORPUS_SCHEMA_VERSION,
    }
    return {**base, "digest": canonical_json_sha256(base)}

def build_static_semantic_corpus(
    artifact_root: Path,
    *,
    repository_digest: str,
) -> StaticSemanticCorpusBuild:
    """Build all raw bytes, independent truth, validation, and manifest records."""
    root = _path(artifact_root, "static_semantic_artifact_root_invalid")
    pending: list[tuple[Path, bytes]] = []
    samples: list[AttackEvaluationSample] = []
    generation_records: list[dict[str, object]] = []
    oracle_records: list[dict[str, object]] = []
    validation_records: list[dict[str, object]] = []
    safety_records: list[dict[str, object]] = []
    for partition, collected_at, partition_seed in STATIC_SEMANTIC_PARTITION_SCHEDULE:
        for fixture_index in range(len(STATIC_SEMANTIC_FIXTURES)):
            sample, payload, generation, oracle, validation, safety = _sample(
                partition=partition,
                collected_at=collected_at,
                partition_seed=partition_seed,
                fixture_index=fixture_index,
            )
            samples.append(sample)
            portable_path = Path(sample.artifact_path)
            if portable_path.is_absolute() or portable_path.parts[:1] != ("artifacts",):
                raise RuntimeError("static_semantic_artifact_path_not_portable")
            pending.append((root / portable_path.relative_to("artifacts"), payload))
            generation_records.append(generation.to_hidden_record())
            oracle_records.append(oracle)
            validation_records.append(validation)
            safety_records.append(safety)
    sample_tuple = tuple(samples)
    generation_tuple = tuple(generation_records)
    if len(sample_tuple) != STATIC_SEMANTIC_SAMPLE_COUNT:
        raise RuntimeError("static_semantic_sample_count_invalid")
    if len({item.artifact_sha256 for item in sample_tuple}) != len(sample_tuple):
        raise RuntimeError("static_semantic_artifact_identity_duplicate")
    manifest = AttackEvaluationCorpusManifest(
        corpus_id="umige-stage2636-11020-static-semantic-evaluation",
        corpus_version=STATIC_SEMANTIC_CORPUS_VERSION,
        corpus_evidence_class="synthetic_development",
        label_review_status="artifact_byte_oracle",
        generation_policy_digest=STATIC_SEMANTIC_GENERATION_POLICY_DIGEST,
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
        repository_version=ATTACK_REPOSITORY_SCHEMA_VERSION + ":enterprise-attack-v19.1",
        repository_digest=repository_digest,
        policy_frozen_at=STATIC_SEMANTIC_POLICY_FROZEN_AT,
        frozen_at=STATIC_SEMANTIC_MANIFEST_FROZEN_AT,
        reviewer_ids=("artifact-byte-oracle-primary", "artifact-byte-oracle-validator"),
        adjudicator_ids=("static-semantic-safety-adjudicator",),
        reviewed_technique_ids=STATIC_SEMANTIC_REVIEWED_TECHNIQUES,
        partition_counts=_partition_counts(),
        samples=sample_tuple,
    )
    sidecars = (
        (STATIC_SEMANTIC_SIDECAR_FILENAMES[0], _report(
            STATIC_SEMANTIC_CORPUS_SCHEMA_VERSION,
            generation_tuple,
            master_seed=STATIC_SEMANTIC_MASTER_SEED,
            record_count=len(generation_tuple),
        )),
        (STATIC_SEMANTIC_SIDECAR_FILENAMES[1], _report(
            STATIC_SEMANTIC_ORACLE_VERSION,
            tuple(oracle_records),
            record_count=len(oracle_records),
        )),
        (STATIC_SEMANTIC_SIDECAR_FILENAMES[2], _report(
            STATIC_SEMANTIC_ORACLE_VALIDATOR_VERSION,
            tuple(validation_records),
            agreement_count=sum(item["agreement"] is True for item in validation_records),
            disagreement_count=sum(item["agreement"] is not True for item in validation_records),
        )),
        (STATIC_SEMANTIC_SIDECAR_FILENAMES[3], _report(
            STATIC_SEMANTIC_SAFETY_VERSION,
            tuple(safety_records),
            safe_count=sum(item["safe"] is True for item in safety_records),
            unsafe_count=sum(item["safe"] is not True for item in safety_records),
        )),
        (STATIC_SEMANTIC_SIDECAR_FILENAMES[4], _leakage_report(sample_tuple, tuple(pending))),
        (STATIC_SEMANTIC_SIDECAR_FILENAMES[5], _coverage_report(sample_tuple, generation_tuple)),
    )
    return StaticSemanticCorpusBuild(manifest, tuple(pending), sidecars)


def build_static_semantic_corpus_manifest(
    artifact_root: Path,
    *,
    repository_digest: str,
) -> tuple[AttackEvaluationCorpusManifest, tuple[tuple[Path, bytes], ...]]:
    build = build_static_semantic_corpus(
        artifact_root, repository_digest=repository_digest,
    )
    return build.manifest, build.pending_artifacts


def materialize_static_semantic_corpus(
    root: Path,
    *,
    repository_digest: str,
) -> AttackEvaluationCorpusManifest:
    """Atomically publish read-only raw artifacts and artifact-truth sidecars."""
    target = _path(root, "static_semantic_root_invalid").resolve()
    if target.exists():
        raise ValueError("static_semantic_root_exists")
    staging = target.with_name(target.name + ".staging")
    if staging.exists():
        raise ValueError("static_semantic_staging_exists")
    try:
        build = build_static_semantic_corpus(
            target / "artifacts", repository_digest=repository_digest,
        )
        for final_path, payload in build.pending_artifacts:
            if not final_path.is_relative_to(target):
                raise ValueError("static_semantic_artifact_path_escape")
            path = staging / final_path.relative_to(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        records = (
            ("attack_evaluation_corpus_manifest.json", build.manifest.to_record()),
            *build.sidecars,
        )
        for filename, record in records:
            path = staging / filename
            atomic_json_save(str(path), record, backups=0)
        generated_files: list[Path] = []
        generated_directories: set[Path] = {staging}
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                generated_files.append(path)
                flush_existing_regular_file(path)
            elif path.is_dir():
                generated_directories.add(path)
        for path in generated_files:
            path.chmod(0o444)
        for directory in sorted(generated_directories, key=lambda item: len(item.parts), reverse=True):
            flush_directory(directory)
        durable_activate_directory(staging, target)
        return build.manifest
    except (OSError, TypeError, ValueError, RuntimeError):
        shutil.rmtree(staging, ignore_errors=True)
        raise


__all__ = (
    "STATIC_SEMANTIC_CONTROL_COUNT",
    "STATIC_SEMANTIC_CORPUS_VERSION",
    "STATIC_SEMANTIC_GENERATION_POLICY_DIGEST",
    "STATIC_SEMANTIC_LABEL_POLICY_VERSION",
    "STATIC_SEMANTIC_MALWARE_COUNT",
    "STATIC_SEMANTIC_SAMPLE_COUNT",
    "STATIC_SEMANTIC_SIDECAR_FILENAMES",
    "StaticSemanticCorpusBuild",
    "build_static_semantic_corpus",
    "build_static_semantic_corpus_manifest",
    "materialize_static_semantic_corpus",
)
