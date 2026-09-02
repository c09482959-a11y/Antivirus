"""Phase 25 inert static-semantic corpus, oracle, safety, and raw-scan gates."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import zipfile

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.detection.attack.evaluation_contracts import AttackEvaluationCorpusManifest
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.stress.static_semantic_corpus import (
    STATIC_SEMANTIC_CONTROL_COUNT,
    STATIC_SEMANTIC_GENERATION_POLICY_DIGEST,
    STATIC_SEMANTIC_MALWARE_COUNT,
    STATIC_SEMANTIC_SAMPLE_COUNT,
    STATIC_SEMANTIC_SIDECAR_FILENAMES,
    build_static_semantic_corpus,
    materialize_static_semantic_corpus,
)
from Virus_Scan.stress.artifact_attack_projection import artifact_attack_expectations
from Virus_Scan.stress.artifact_evidence_oracle import derive_artifact_evidence_truth
from Virus_Scan.stress.artifact_evidence_oracle_validator import validate_artifact_evidence_truth
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_safety import validate_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import (
    STATIC_SEMANTIC_PARTITION_SCHEDULE,
    STATIC_SEMANTIC_REVIEWED_TECHNIQUES,
    CorpusGenerationRecord,
)
from Virus_Scan.stress.static_semantic_templates import STATIC_SEMANTIC_FIXTURES
from tools.evaluation.generate_static_semantic_corpus import generate

_REPOSITORY_DIGEST = "a" * 64
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_MODULES = (
    Path("Virus_Scan/stress/static_semantic_schema.py"),
    Path("Virus_Scan/stress/static_semantic_binary_fixtures.py"),
    Path("Virus_Scan/stress/static_semantic_templates.py"),
    Path("Virus_Scan/stress/static_semantic_renderer.py"),
    Path("Virus_Scan/stress/static_semantic_safety.py"),
    Path("Virus_Scan/stress/artifact_evidence_oracle.py"),
    Path("Virus_Scan/stress/artifact_evidence_oracle_validator.py"),
    Path("Virus_Scan/stress/artifact_attack_policy_data.py"),
    Path("Virus_Scan/stress/artifact_attack_projection.py"),
    Path("Virus_Scan/stress/static_semantic_corpus.py"),
)


@contextmanager
def _isolated_runtime(tmp_path: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    sqlite_lifecycle().close()
    runtime_root = tmp_path / "runtime"
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    try:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
        yield runtime_root
    finally:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def _generation(fixture_index: int, *, partition_index: int = 0) -> CorpusGenerationRecord:
    partition, collected_at, seed = STATIC_SEMANTIC_PARTITION_SCHEDULE[partition_index]
    fixture = STATIC_SEMANTIC_FIXTURES[fixture_index]
    return CorpusGenerationRecord(
        sample_id=f"phase25-{partition}-{fixture_index:02d}",
        partition=partition,
        partition_seed=seed,
        collected_at=collected_at,
        fixture_definition=fixture,
    )


def _fixture_index(generation_id: str) -> int:
    return next(
        index for index, fixture in enumerate(STATIC_SEMANTIC_FIXTURES)
        if fixture.generation_intent.generation_id == generation_id
    )


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def test_phase25_fixtures_split_generation_intent_from_renderer_and_cover_cohorts() -> None:
    assert len(STATIC_SEMANTIC_FIXTURES) == 24
    intents = tuple(item.generation_intent for item in STATIC_SEMANTIC_FIXTURES)
    renderers = tuple(item.renderer_specification for item in STATIC_SEMANTIC_FIXTURES)
    assert sum(item.malware_class == "malware" for item in intents) == 12
    assert sum(item.malware_class == "control" for item in intents) == 12
    assert {item.desired_parser_status for item in intents} == {
        "complete", "failed", "partial", "unavailable",
    }
    assert {
        "python", "renpy", "powershell", "javascript", "typescript",
        "batch", "shell", "ruby_unsupported",
    }.issubset({item.language.removesuffix("_nested_archive") for item in renderers})
    assert any(item.renderer_kind == "nested_zip" for item in renderers)
    assert sum(item.renderer_kind == "managed_pe" for item in renderers) == 2
    assert sum(item.renderer_kind == "native_elf_x86_64" for item in renderers) == 2
    assert any("decode" in item.desired_operation_kinds for item in intents)
    assert {"dotnet_il", "native_x86_64"}.issubset({item.language for item in renderers})
    assert any(
        any(reach.reachability_state == "unreachable" for reach in item.desired_reachability)
        for item in intents
    )
    assert any(
        any(flow.connected is False for flow in item.desired_flow)
        for item in intents
    )
    assert any(item.desired_artifact_implementation_state == "conditional" for item in intents)
    assert any(item.coverage_cohort == "benign_script_lookalike" for item in intents)
    assert any(item.coverage_cohort == "administrative_or_dual_use" for item in intents)
    assert any(item.coverage_cohort == "corrupt_or_truncated" for item in intents)
    assert all(not hasattr(item, "desired_technique_ids") for item in renderers)

def test_phase25_artifact_oracle_is_byte_derived_zero_authority_and_cross_validated() -> None:
    generation = _generation(0)
    renderer = generation.fixture_definition.renderer_specification
    payload = render_static_semantic_artifact(generation.sample_id, renderer)
    truth = derive_artifact_evidence_truth(generation.sample_id, generation.sample_id + renderer.extension, payload)
    expectations = artifact_attack_expectations(truth, STATIC_SEMANTIC_REVIEWED_TECHNIQUES)
    validation = validate_artifact_evidence_truth(
        generation.sample_id, generation.sample_id + renderer.extension, payload, truth, expectations,
    )
    by_id = {item.technique_id: item for item in expectations}

    assert validation["agreement"] is True
    assert tuple(sorted(by_id)) == tuple(sorted(STATIC_SEMANTIC_REVIEWED_TECHNIQUES))
    assert by_id["T1003"].expected_state == "rejected"
    assert by_id["T1105"].expected_state == "rejected"
    assert by_id["T1055"].expected_state == "rejected"
    # Physical upload behavior exists; current local T1041 policy is unsupported.
    assert by_id["T1041"].expected_state == "unavailable"
    assert truth.artifact_sha256 == __import__("hashlib").sha256(payload).hexdigest()
    assert truth.operation_kinds
    assert all("generation:" not in ref for item in expectations for ref in item.label_evidence_refs)


def test_phase25_artifact_oracle_validator_detects_independent_truth_drift() -> None:
    generation = _generation(0)
    renderer = generation.fixture_definition.renderer_specification
    payload = render_static_semantic_artifact(generation.sample_id, renderer)
    truth = derive_artifact_evidence_truth(generation.sample_id, generation.sample_id + renderer.extension, payload)
    tampered = replace(truth, operation_kinds=("process_launch",))
    validation = validate_artifact_evidence_truth(
        generation.sample_id, generation.sample_id + renderer.extension, payload, tampered,
        artifact_attack_expectations(truth, STATIC_SEMANTIC_REVIEWED_TECHNIQUES),
    )
    assert validation["agreement"] is False
    assert "truth:operation_kinds" in validation["errors"]


def test_phase25_unresolved_artifact_analysis_abstains_instead_of_forcing_negative() -> None:
    generation = _generation(_fixture_index("python_dynamic_eval"))
    renderer = generation.fixture_definition.renderer_specification
    payload = render_static_semantic_artifact(generation.sample_id, renderer)
    truth = derive_artifact_evidence_truth(generation.sample_id, generation.sample_id + renderer.extension, payload)
    by_id = {item.technique_id: item for item in artifact_attack_expectations(truth, STATIC_SEMANTIC_REVIEWED_TECHNIQUES)}
    assert truth.parser_status == "partial"
    assert truth.evidence_completeness == "partial"
    assert by_id["T1105"].expected_state == "unavailable"
    assert by_id["T1105"].supported_claim_scope == "unavailable"
    assert by_id["T1105"].modality == "unavailable"
    assert by_id["T1105"].label_evidence_refs == ()


def test_phase25_build_is_deterministic_balanced_safe_and_leak_free(tmp_path: Path) -> None:
    first_root = tmp_path / "first" / "artifacts"
    second_root = tmp_path / "second" / "artifacts"
    first = build_static_semantic_corpus(
        first_root, repository_digest=_REPOSITORY_DIGEST,
    )
    second = build_static_semantic_corpus(
        second_root, repository_digest=_REPOSITORY_DIGEST,
    )

    assert first.manifest.digest == second.manifest.digest
    assert first.manifest.to_record() == second.manifest.to_record()
    assert tuple(
        (path.relative_to(first_root), payload)
        for path, payload in first.pending_artifacts
    ) == tuple(
        (path.relative_to(second_root), payload)
        for path, payload in second.pending_artifacts
    )
    assert first.sidecars == second.sidecars
    assert all(not Path(item.artifact_path).is_absolute() for item in first.manifest.samples)
    assert all(Path(item.artifact_path).parts[0] == "artifacts" for item in first.manifest.samples)
    assert str(tmp_path) not in json.dumps(first.manifest.to_record(), sort_keys=True)
    assert len(first.manifest.samples) == STATIC_SEMANTIC_SAMPLE_COUNT == 96
    assert first.manifest.malware_sample_count == STATIC_SEMANTIC_MALWARE_COUNT == 48
    assert first.manifest.control_sample_count == STATIC_SEMANTIC_CONTROL_COUNT == 48
    assert all(
        item.malware_count == 12 and item.control_count == 12
        for item in first.manifest.partition_counts
    )
    assert len({item.artifact_sha256 for item in first.manifest.samples}) == 96
    sidecars = dict(first.sidecars)
    assert sidecars["static_semantic_artifact_truth_validation.json"]["agreement_count"] == 96
    assert sidecars["static_semantic_artifact_truth_validation.json"]["disagreement_count"] == 0
    assert sidecars["static_semantic_safety_report.json"]["safe_count"] == 96
    assert sidecars["static_semantic_safety_report.json"]["unsafe_count"] == 0
    assert sidecars["static_semantic_leakage_report.json"]["violation_count"] == 0
    assert sidecars["static_semantic_coverage_report.json"]["runtime_occurrence_expected_count"] == 0
    assert first.manifest.generation_policy_digest == STATIC_SEMANTIC_GENERATION_POLICY_DIGEST


def test_phase25_materialization_is_atomic_read_only_and_current_schema(tmp_path: Path) -> None:
    root = tmp_path / "static-semantic-corpus"
    manifest = materialize_static_semantic_corpus(
        root, repository_digest=_REPOSITORY_DIGEST,
    )
    loaded = AttackEvaluationCorpusManifest.from_path(
        root / "attack_evaluation_corpus_manifest.json"
    )

    assert loaded.digest == manifest.digest
    assert loaded.samples == manifest.samples
    assert all((root / item.artifact_path).is_file() for item in loaded.samples)
    assert str(root) not in (root / "attack_evaluation_corpus_manifest.json").read_text(
        encoding="utf-8",
    )
    assert not root.with_name(root.name + ".staging").exists()
    assert len(tuple((root / "artifacts").rglob("*.*"))) == 96
    for path in (
        root / "attack_evaluation_corpus_manifest.json",
        *(root / name for name in STATIC_SEMANTIC_SIDECAR_FILENAMES),
        *(path for path in (root / "artifacts").rglob("*") if path.is_file()),
    ):
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) & 0o222 == 0
    with pytest.raises(ValueError, match="static_semantic_root_exists"):
        materialize_static_semantic_corpus(root, repository_digest=_REPOSITORY_DIGEST)


def test_phase25_materialized_manifest_remains_valid_after_relocation(tmp_path: Path) -> None:
    source = tmp_path / "source-corpus"
    relocated = tmp_path / "relocated-corpus"
    original = materialize_static_semantic_corpus(
        source, repository_digest=_REPOSITORY_DIGEST,
    )
    import shutil
    shutil.copytree(source, relocated)
    loaded = AttackEvaluationCorpusManifest.from_path(
        relocated / "attack_evaluation_corpus_manifest.json",
    )
    assert loaded.digest == original.digest
    assert all((relocated / item.artifact_path).is_file() for item in loaded.samples)
    assert all(not Path(item.artifact_path).is_absolute() for item in loaded.samples)
    assert str(source) not in (
        relocated / "attack_evaluation_corpus_manifest.json"
    ).read_text(encoding="utf-8")


def test_phase25_nested_archives_are_deterministic_safe_and_bounded(tmp_path: Path) -> None:
    build = build_static_semantic_corpus(
        tmp_path / "corpus" / "artifacts", repository_digest=_REPOSITORY_DIGEST,
    )
    archives = tuple(
        (path, payload) for path, payload in build.pending_artifacts if path.suffix == ".zip"
    )
    assert len(archives) == 8
    for path, payload in archives:
        safety = validate_static_semantic_artifact(path.stem, payload)
        assert safety.safe is True
        assert safety.archive_member_count == 3
        assert safety.maximum_archive_depth == 2
        assert safety.expanded_bytes < 2_000
        with zipfile.ZipFile(__import__("io").BytesIO(payload)) as outer:
            assert outer.namelist() == ["nested/inner.zip", "README.txt"]


def test_phase25_safety_rejects_executables_network_targets_and_traversal() -> None:
    executable = b"\x7fELF" + b"X" * 64
    external_url = b"# inert-looking but invalid https://not-example.test/upload" + b"X" * 16
    assert validate_static_semantic_artifact("elf", executable).safe is False
    assert "executable_payload_rejected" in validate_static_semantic_artifact("elf", executable).reasons
    assert validate_static_semantic_artifact("url", external_url).safe is False
    assert "non_reserved_network_target_rejected" in validate_static_semantic_artifact("url", external_url).reasons

    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../escape.py", b"# inert" * 8)
    result = validate_static_semantic_artifact("traversal", buffer.getvalue())
    assert result.safe is False
    assert "archive_member_unsafe" in result.reasons


def test_phase25_corpus_owner_has_no_scanner_or_mapping_dependency() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in _CORPUS_MODULES)
    forbidden = (
        "Virus_Scan.routing",
        "Virus_Scan.scanners",
        "map_attack_evidence",
        "scan_file_by_type",
        "analyze_file_full_observe_only",
        "DetectionObservation(",
        "TagEvidence(",
        "ChainEvidence(",
    )
    assert all(token not in combined for token in forbidden)
    assert "scanner_boundary=\"production_file_scan\"" not in combined


def test_phase25_raw_artifacts_enter_actual_production_router_without_injection(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corpus"
    manifest = materialize_static_semantic_corpus(
        root, repository_digest=_REPOSITORY_DIGEST,
    )
    generation_records = _json(root / "static_semantic_generation_intent_manifest.json")
    generation_id_by_sample = {
        record["sample_id"]: record["fixture_definition"]["generation_intent"]["generation_id"]
        for record in generation_records["records"]
    }
    sample_by_generation = {
        generation_id_by_sample[item.sample_id]: item
        for item in manifest.samples
        if item.partition == "development"
    }
    selected = (
        sample_by_generation["python_credential_flow"],
        sample_by_generation["javascript_file_upload"],
        sample_by_generation["malformed_python"],
        sample_by_generation["unsupported_ruby_upload"],
    )
    with _isolated_runtime(tmp_path):
        records = []
        for sample in selected:
            path = root / sample.artifact_path
            outcome = scan_file_by_type(
                str(path),
                scan_session_snapshot=scan_session_snapshot_fixture(),
                artifact_read_snapshot=build_artifact_read_snapshot(path),
            )
            identity = route_identity_record(outcome.identity)
            assert identity is not None
            records.append((sample, identity, outcome))

    python_identity = records[0][1]["static_program_analysis"]
    javascript_identity = records[1][1]["static_program_analysis"]
    malformed_identity = records[2][1]["static_program_analysis"]
    assert python_identity["parser_status"] == "complete"
    assert javascript_identity["parser_status"] == "complete"
    assert malformed_identity["parser_status"] == "failed"
    assert records[3][1]["scanner_execution_plan"]["decisions"]
    for sample, identity, outcome in records:
        assert sample.scanner_boundary == "production_file_scan"
        assert sample.evidence_domain == "synthetic_engineering"
        identity_text = repr(identity).casefold()
        assert "oracle" not in identity_text
        assert "runtime_occurrence" not in identity_text
        assert all("oracle" not in tag.casefold() for tag in outcome.tags)


def test_phase25_manifest_group_identities_do_not_cross_partitions(tmp_path: Path) -> None:
    build = build_static_semantic_corpus(
        tmp_path / "corpus" / "artifacts", repository_digest=_REPOSITORY_DIGEST,
    )
    identities: dict[tuple[str, str], str] = {}
    for sample in build.manifest.samples:
        for dimension, identity in (
            ("source_family", sample.source_family),
            ("related_group", sample.related_group),
            ("package_campaign_id", sample.package_campaign_id),
            ("collection_session", sample.collection_session),
        ):
            assert identities.setdefault((dimension, identity), sample.partition) == sample.partition


def test_phase25_materialized_sidecars_have_complete_traceability(tmp_path: Path) -> None:
    root = tmp_path / "corpus"
    manifest = materialize_static_semantic_corpus(
        root, repository_digest=_REPOSITORY_DIGEST,
    )
    generation_records = _json(root / "static_semantic_generation_intent_manifest.json")
    oracle = _json(root / "static_semantic_artifact_truth_manifest.json")
    validation = _json(root / "static_semantic_artifact_truth_validation.json")
    safety = _json(root / "static_semantic_safety_report.json")

    assert generation_records["record_count"] == len(manifest.samples) == 96
    assert oracle["record_count"] == 96
    assert validation["agreement_count"] == 96
    assert validation["disagreement_count"] == 0
    assert safety["safe_count"] == 96
    generation_ids = {item["sample_id"] for item in generation_records["records"]}
    oracle_ids = {item["sample_id"] for item in oracle["records"]}
    validation_ids = {item["sample_id"] for item in validation["records"]}
    safety_ids = {item["sample_id"] for item in safety["records"]}
    manifest_ids = {item.sample_id for item in manifest.samples}
    assert generation_ids == oracle_ids == validation_ids == safety_ids == manifest_ids
    assert all("runtime_occurrence_expected" not in item for item in oracle["records"])
    assert all("generation_id" not in item for item in oracle["records"])
    assert all("malware_class" not in item for item in oracle["records"])
    assert all("desired_technique_ids" not in item for item in oracle["records"])
    assert all("execution_observed" not in item for item in oracle["records"])
    assert all("eligible_for_probability" not in item for item in oracle["records"])


def test_phase25_cli_generates_current_corpus_from_packaged_repository(tmp_path: Path) -> None:
    root = tmp_path / "cli-corpus"
    result = generate(
        bundle_path=_REPOSITORY_ROOT / "Mitre" / "enterprise-attack.json",
        corpus_root=root,
    )
    assert result["malware_sample_count"] == 48
    assert result["control_sample_count"] == 48
    assert result["bundle_sha256"] == "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3"
    assert Path(result["manifest_path"]).is_file()
    assert Path(result["artifact_truth_path"]).is_file()
    assert Path(result["artifact_truth_validation_path"]).is_file()
    assert Path(result["safety_path"]).is_file()
    assert Path(result["leakage_path"]).is_file()
    assert Path(result["coverage_path"]).is_file()
    assert len(tuple(root.rglob("*"))) >= 87
