"""Canonical external 10,000-sample inert static-semantic ATT&CK corpus."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PosixPath, WindowsPath
import shutil
from types import MappingProxyType

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
from Virus_Scan.stress.attack_synthetic_challenges import (
    validate_synthetic_attack_challenge_pair,
)
from Virus_Scan.stress.attack_synthetic_metadata import synthetic_metadata
from Virus_Scan.stress.artifact_attack_projection import (
    artifact_attack_expectations,
    artifact_behavior_satisfied,
)
from Virus_Scan.stress.artifact_evidence_oracle import derive_artifact_evidence_truth
from Virus_Scan.stress.artifact_evidence_oracle_validator import validate_artifact_evidence_truth
from Virus_Scan.stress.artifact_generation_reconciliation import reconcile_generation_intent_with_artifact_truth
from Virus_Scan.stress.attack_synthetic_schema import (
    SYNTHETIC_CHALLENGE_PAIR_VERSION,
    SYNTHETIC_CORPUS_SCHEMA_VERSION,
    SYNTHETIC_ENGINEERING_DOMAIN,
    SYNTHETIC_MASTER_SEED,
    SYNTHETIC_METADATA_VERSION,
    SYNTHETIC_ORACLE_VERSION,
    SYNTHETIC_PARTITION_SCHEDULE,
    SYNTHETIC_SAFETY_VERSION,
    partition_for_index,
)
from Virus_Scan.stress.attack_synthetic_templates import (
    CONTROL_SYNTHETIC_ATTACK_FIXTURES,
    MALWARE_SYNTHETIC_ATTACK_FIXTURES,
    SYNTHETIC_ATTACK_CHALLENGE_PAIRS,
    SYNTHETIC_ATTACK_TECHNIQUE_IDS,
)
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_safety import validate_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import (
    STATIC_SEMANTIC_RENDERER_VERSION,
    ArtifactEvidenceTruth,
    CorpusFixtureDefinition,
    CorpusGenerationRecord,
)

SYNTHETIC_ATTACK_CORPUS_VERSION = "stage2636_11020_static_attack_matrix_v7"
SYNTHETIC_ATTACK_LABEL_POLICY_VERSION = "stage2636_11020_static_attack_label_policy_v7"
SYNTHETIC_ATTACK_POLICY_FROZEN_AT = "2026-06-01T00:00:00Z"
SYNTHETIC_ATTACK_MANIFEST_FROZEN_AT = "2026-08-16T00:00:00Z"
SYNTHETIC_ATTACK_MALWARE_COUNT = 5_000
SYNTHETIC_ATTACK_CONTROL_COUNT = 5_000
SYNTHETIC_ATTACK_SIDECAR_FILENAMES = (
    "synthetic_generation_intent_manifest.json",
    "synthetic_challenge_pair_manifest.json",
    "synthetic_metadata_manifest.json",
    "synthetic_artifact_truth_manifest.json",
    "synthetic_safety_report.json",
    "synthetic_leakage_report.json",
)
_PATH_TYPES = (PosixPath, WindowsPath)
_PARTITION_LIMITS = MappingProxyType({
    partition: (start, stop)
    for partition, start, stop, _collected_at, _seed in SYNTHETIC_PARTITION_SCHEDULE
})


def _path(value: object, reason: str) -> Path:
    if type(value) not in _PATH_TYPES:
        raise TypeError(reason)
    return value


def _generation_policy_digest() -> str:
    return canonical_json_sha256({
        "challenge_pair_version": SYNTHETIC_CHALLENGE_PAIR_VERSION,
        "challenge_pairs": tuple(
            item.to_hidden_record() for item in SYNTHETIC_ATTACK_CHALLENGE_PAIRS
        ),
        "corpus_schema": SYNTHETIC_CORPUS_SCHEMA_VERSION,
        "label_policy": SYNTHETIC_ATTACK_LABEL_POLICY_VERSION,
        "master_seed": SYNTHETIC_MASTER_SEED,
        "metadata_version": SYNTHETIC_METADATA_VERSION,
        "oracle_version": SYNTHETIC_ORACLE_VERSION,
        "partition_schedule": SYNTHETIC_PARTITION_SCHEDULE,
        "renderer_version": STATIC_SEMANTIC_RENDERER_VERSION,
        "safety_version": SYNTHETIC_SAFETY_VERSION,
        "technique_ids": SYNTHETIC_ATTACK_TECHNIQUE_IDS,
        "templates": tuple(
            item.to_hidden_record()
            for item in (
                MALWARE_SYNTHETIC_ATTACK_FIXTURES
                + CONTROL_SYNTHETIC_ATTACK_FIXTURES
            )
        ),
    })


SYNTHETIC_ATTACK_GENERATION_POLICY_DIGEST = _generation_policy_digest()


@dataclass(frozen=True, slots=True)
class SyntheticAttackCorpusBuild:
    manifest: AttackEvaluationCorpusManifest
    pending_artifacts: tuple[tuple[Path, bytes], ...]
    sidecars: tuple[tuple[str, dict[str, object]], ...]


def _challenge_pair_for(index: int, partition: str):
    shift = 3 if partition == "future_time_holdout" else 0
    return SYNTHETIC_ATTACK_CHALLENGE_PAIRS[
        (index + shift) % len(SYNTHETIC_ATTACK_CHALLENGE_PAIRS)
    ]


def _opaque_token(*parts: object, length: int = 20) -> str:
    material = ":".join(str(part) for part in parts)
    return sha256((SYNTHETIC_MASTER_SEED + ":" + material).encode("utf-8")).hexdigest()[:length]


def _generation_record(
    fixture: CorpusFixtureDefinition,
    index: int,
    malware_class: str,
) -> CorpusGenerationRecord:
    partition, collected_at, seed = partition_for_index(index)
    sample_id = "static-attack-" + _opaque_token("sample", malware_class, index)
    return CorpusGenerationRecord(
        sample_id=sample_id,
        partition=partition,
        partition_seed=seed,
        collected_at=collected_at,
        fixture_definition=fixture,
    )


def _file_type(fixture: CorpusFixtureDefinition) -> str:
    renderer = fixture.renderer_specification
    if renderer.renderer_kind == "text":
        return renderer.language
    return renderer.renderer_kind + ":" + renderer.language


def _sample(
    artifact_root: Path,
    fixture: CorpusFixtureDefinition,
    index: int,
) -> tuple[
    AttackEvaluationSample,
    bytes,
    CorpusGenerationRecord,
    dict[str, object],
    dict[str, object],
    dict[str, object],
    ArtifactEvidenceTruth,
]:
    intent = fixture.generation_intent
    renderer = fixture.renderer_specification
    generation = _generation_record(fixture, index, intent.malware_class)
    path = artifact_root / (generation.sample_id + renderer.extension)
    payload = render_static_semantic_artifact(generation.sample_id, renderer)
    safety = validate_static_semantic_artifact(
        generation.sample_id,
        payload,
        renderer_kind=renderer.renderer_kind,
        fixture_variant=renderer.fixture_variant,
    )
    if safety.safe is not True:
        raise ValueError("synthetic_attack_safety_rejected:" + generation.sample_id)
    truth = derive_artifact_evidence_truth(generation.sample_id, path.name, payload)
    expectations = artifact_attack_expectations(truth, SYNTHETIC_ATTACK_TECHNIQUE_IDS)
    validation = validate_artifact_evidence_truth(
        generation.sample_id, path.name, payload, truth, expectations,
    )
    if validation["agreement"] is not True:
        raise ValueError("synthetic_attack_artifact_truth_disagreement:" + generation.sample_id)
    reconcile_generation_intent_with_artifact_truth(
        intent, truth, reason_prefix="synthetic_attack",
    )
    for technique_id in intent.desired_technique_ids:
        if artifact_behavior_satisfied(truth, technique_id) is not True:
            raise ValueError("synthetic_attack_generation_technique_behavior_missing:" + generation.sample_id + ":" + technique_id)

    family = _opaque_token("family", generation.partition, intent.generation_id, length=16)
    group = _opaque_token(
        "group", generation.partition, intent.malware_class, index // 10, length=16,
    )
    campaign = _opaque_token(
        "campaign", generation.partition, intent.malware_class, index // 50, length=16,
    )
    session = _opaque_token(
        "session", generation.partition, intent.malware_class, index // 100, length=16,
    )
    sample = AttackEvaluationSample(
        sample_id=generation.sample_id,
        partition=generation.partition,
        source_family="static-attack-family-" + family,
        related_group="static-attack-group-" + group,
        package_campaign_id="static-attack-campaign-" + campaign,
        collection_session="static-attack-session-" + session,
        malware_class=intent.malware_class,
        sample_category=intent.coverage_cohort,
        artifact_path=str(path),
        artifact_sha256=sha256(payload).hexdigest(),
        artifact_size=len(payload),
        acquisition_provenance=(
            "Deterministic inert artifact rendered from a renderer-only specification. "
            "Hidden generation intent is evaluation-only and has zero physical evidence authority."
        ),
        collected_at=generation.collected_at,
        platform=truth.platform,
        file_type=truth.artifact_format,
        technique_expectations=expectations,
        evidence_domain=SYNTHETIC_ENGINEERING_DOMAIN,
        eligible_for_production_metrics=False,
        eligible_for_policy_promotion=False,
        eligible_for_production_calibration=False,
    )
    metadata = synthetic_metadata(generation).to_record()
    oracle = {
        **truth.to_record(),
        "artifact_evidence_digest": truth.digest,
        "attack_expectations": tuple(item.to_record() for item in expectations),
        "validator": validation,
    }
    return sample, payload, generation, metadata, oracle, safety.to_record(), truth

def _partition_counts() -> tuple[AttackEvaluationPartitionCount, ...]:
    return tuple(
        AttackEvaluationPartitionCount(partition, stop - start, stop - start)
        for partition in ATTACK_EVALUATION_PARTITIONS
        for start, stop in (_PARTITION_LIMITS[partition],)
    )


def _report(version: str, records: tuple[object, ...], **summary: object) -> dict[str, object]:
    base = {"records": records, "version": version, **summary}
    return {**base, "digest": canonical_json_sha256(base)}


def _leakage_report(
    samples: tuple[AttackEvaluationSample, ...],
    artifacts: tuple[tuple[Path, bytes], ...],
    metadata_records: tuple[dict[str, object], ...],
) -> dict[str, object]:
    """Reject scanner-visible generator labels while allowing real behavior bytes."""
    if len(samples) != len(artifacts) or len(samples) != len(metadata_records):
        raise ValueError("synthetic_leakage_input_count_mismatch")
    identities: dict[tuple[str, str], str] = {}
    violations: list[str] = []
    forbidden_identity_tokens = (
        "malware", "control", "template", "t1003", "t1021", "t1041",
        "t1055", "t1059", "t1105", "t1562",
    )
    forbidden_payload_markers = (
        b'"malware_class"', b'"technique_ids"', b'"template_id"',
        b"template_id=", b"malware_class=", b"technique_ids=",
    )
    for sample, (artifact_path, payload), metadata in zip(
        samples, artifacts, metadata_records, strict=True,
    ):
        for dimension, identity in (
            ("source_family", sample.source_family),
            ("related_group", sample.related_group),
            ("package_campaign_id", sample.package_campaign_id),
            ("collection_session", sample.collection_session),
        ):
            key = (dimension, identity)
            prior = identities.setdefault(key, sample.partition)
            if prior != sample.partition:
                violations.append(dimension + ":cross_partition:" + identity)
            lowered = identity.casefold()
            if any(token in lowered for token in forbidden_identity_tokens):
                violations.append(dimension + ":hidden_label:" + sample.sample_id)
        normalized_path = artifact_path.as_posix().casefold()
        if any(token in normalized_path for token in forbidden_identity_tokens):
            violations.append("artifact_path:hidden_label:" + sample.sample_id)
        if any(marker in payload for marker in forbidden_payload_markers):
            violations.append("artifact_payload:hidden_label:" + sample.sample_id)
        tags = metadata.get("tags")
        signature = metadata.get("signature")
        if type(tags) is not tuple or any(
            type(tag) is not str
            or any(token in tag.casefold() for token in forbidden_identity_tokens)
            for tag in tags
        ):
            violations.append("metadata:label_tag:" + sample.sample_id)
        if type(signature) is not str or not signature.startswith("synthetic_challenge_"):
            violations.append("metadata:signature:" + sample.sample_id)
    ordered = tuple(sorted(set(violations)))
    return _report(
        SYNTHETIC_CORPUS_SCHEMA_VERSION,
        ordered,
        group_identity_count=len(identities),
        public_artifact_count=len(artifacts),
        violation_count=len(ordered),
    )


def build_synthetic_attack_corpus(
    artifact_root: Path,
    *,
    repository_digest: str,
) -> SyntheticAttackCorpusBuild:
    """Build raw artifacts, hidden static truth, reports, and current manifest."""
    root = _path(artifact_root, "synthetic_attack_artifact_root_invalid")
    pending: list[tuple[Path, bytes]] = []
    samples: list[AttackEvaluationSample] = []
    generation_records: list[dict[str, object]] = []
    metadata_records: list[dict[str, object]] = []
    oracle_records: list[dict[str, object]] = []
    safety_records: list[dict[str, object]] = []
    challenge_pair_records: list[dict[str, object]] = []
    for index in range(5_000):
        partition, _collected_at, _seed = partition_for_index(index)
        challenge = _challenge_pair_for(index, partition)
        pair_results = []
        for fixture in (challenge.positive_fixture, challenge.control_fixture):
            result = _sample(root, fixture, index)
            sample, payload, generation, metadata, oracle, safety, truth = result
            samples.append(sample)
            pending.append((Path(sample.artifact_path), payload))
            generation_records.append(generation.to_hidden_record())
            metadata_records.append(metadata)
            oracle_records.append(oracle)
            safety_records.append(safety)
            pair_results.append((sample, truth))
        positive, control = pair_results
        challenge_pair_records.append(validate_synthetic_attack_challenge_pair(
            challenge,
            positive[1],
            control[1],
            positive[0].technique_expectations,
        ))

    sample_tuple = tuple(samples)
    metadata_tuple = tuple(metadata_records)
    if len(sample_tuple) != SYNTHETIC_ATTACK_MALWARE_COUNT + SYNTHETIC_ATTACK_CONTROL_COUNT:
        raise RuntimeError("synthetic_attack_sample_count_invalid")
    if len({item.sample_id for item in sample_tuple}) != len(sample_tuple):
        raise RuntimeError("synthetic_attack_sample_identity_duplicate")
    if len({item.artifact_path for item in sample_tuple}) != len(sample_tuple):
        raise RuntimeError("synthetic_attack_artifact_path_duplicate")

    manifest = AttackEvaluationCorpusManifest(
        corpus_id="umige-stage2636-11020-static-attack-matrix",
        corpus_version=SYNTHETIC_ATTACK_CORPUS_VERSION,
        corpus_evidence_class="synthetic_development",
        label_review_status="artifact_byte_oracle",
        generation_policy_digest=SYNTHETIC_ATTACK_GENERATION_POLICY_DIGEST,
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
        repository_version=ATTACK_REPOSITORY_SCHEMA_VERSION + ":enterprise-attack-v19.1",
        repository_digest=repository_digest,
        policy_frozen_at=SYNTHETIC_ATTACK_POLICY_FROZEN_AT,
        frozen_at=SYNTHETIC_ATTACK_MANIFEST_FROZEN_AT,
        reviewer_ids=("artifact-byte-oracle-primary", "artifact-byte-oracle-validator"),
        adjudicator_ids=("static-semantic-safety-adjudicator",),
        reviewed_technique_ids=SYNTHETIC_ATTACK_TECHNIQUE_IDS,
        partition_counts=_partition_counts(),
        samples=sample_tuple,
    )
    file_type_counts = tuple(sorted({
        file_type: sum(item.file_type == file_type for item in sample_tuple)
        for file_type in {item.file_type for item in sample_tuple}
    }.items()))
    sidecars = (
        (SYNTHETIC_ATTACK_SIDECAR_FILENAMES[0], _report(
            SYNTHETIC_CORPUS_SCHEMA_VERSION,
            tuple(generation_records),
            master_seed=SYNTHETIC_MASTER_SEED,
            record_count=len(generation_records),
        )),
        (SYNTHETIC_ATTACK_SIDECAR_FILENAMES[1], _report(
            SYNTHETIC_CHALLENGE_PAIR_VERSION,
            tuple(challenge_pair_records),
            challenge_counts=tuple(sorted({
                kind: sum(
                    kind in record["challenge_kinds"]
                    for record in challenge_pair_records
                )
                for kind in {
                    kind
                    for record in challenge_pair_records
                    for kind in record["challenge_kinds"]
                }
            }.items())),
            pair_count=len(challenge_pair_records),
        )),
        (SYNTHETIC_ATTACK_SIDECAR_FILENAMES[2], _report(
            SYNTHETIC_METADATA_VERSION,
            metadata_tuple,
            file_type_counts=file_type_counts,
            record_count=len(metadata_records),
        )),
        (SYNTHETIC_ATTACK_SIDECAR_FILENAMES[3], _report(
            SYNTHETIC_ORACLE_VERSION,
            tuple(oracle_records),
            agreement_count=sum(
                item["validator"]["agreement"] is True for item in oracle_records
            ),
            record_count=len(oracle_records),
        )),
        (SYNTHETIC_ATTACK_SIDECAR_FILENAMES[4], _report(
            SYNTHETIC_SAFETY_VERSION,
            tuple(safety_records),
            safe_count=sum(item["safe"] is True for item in safety_records),
            unsafe_count=sum(item["safe"] is not True for item in safety_records),
        )),
        (SYNTHETIC_ATTACK_SIDECAR_FILENAMES[5], _leakage_report(
            sample_tuple, tuple(pending), metadata_tuple,
        )),
    )
    return SyntheticAttackCorpusBuild(manifest, tuple(pending), sidecars)


def build_synthetic_attack_corpus_manifest(
    artifact_root: Path,
    *,
    repository_digest: str,
) -> tuple[AttackEvaluationCorpusManifest, tuple[tuple[Path, bytes], ...]]:
    """Build the exact 5,000/5,000 corpus and its current manifest contract."""
    build = build_synthetic_attack_corpus(
        artifact_root, repository_digest=repository_digest,
    )
    return build.manifest, build.pending_artifacts


def materialize_synthetic_attack_corpus(
    root: Path,
    *,
    repository_digest: str,
) -> AttackEvaluationCorpusManifest:
    """Atomically materialize read-only external artifacts and hidden sidecars."""
    target = _path(root, "synthetic_attack_root_invalid").resolve()
    if target.exists():
        raise ValueError("synthetic_attack_root_exists")
    staging = target.with_name(target.name + ".staging")
    if staging.exists():
        raise ValueError("synthetic_attack_staging_exists")
    try:
        build = build_synthetic_attack_corpus(
            target / "artifacts", repository_digest=repository_digest,
        )
        for final_path, payload in build.pending_artifacts:
            if not final_path.is_relative_to(target):
                raise ValueError("synthetic_attack_artifact_path_escape")
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
    "SYNTHETIC_ATTACK_CONTROL_COUNT",
    "SYNTHETIC_ATTACK_CORPUS_VERSION",
    "SYNTHETIC_ATTACK_GENERATION_POLICY_DIGEST",
    "SYNTHETIC_ATTACK_LABEL_POLICY_VERSION",
    "SYNTHETIC_ATTACK_MALWARE_COUNT",
    "SYNTHETIC_ATTACK_SIDECAR_FILENAMES",
    "SyntheticAttackCorpusBuild",
    "build_synthetic_attack_corpus",
    "build_synthetic_attack_corpus_manifest",
    "materialize_synthetic_attack_corpus",
)
