"""Stage2636.10014 raw-file evaluator, reconciliation, and authority gates."""
from __future__ import annotations

import ast
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

from tools.evaluation.attack_production_reconciliation import (
    reconcile_production_runtime,
)
from tools.evaluation.attack_production_runtime import (
    ALL_PARTITIONS,
    AttackProductionResourceMetrics,
    AttackProductionRuntimeOutput,
    _parse_yara_scan_metrics,
    _prepare_yara_controls,
    _scan_cache_metrics,
    _resolve_yara_source,
    _runtime_environment,
    _yara_command_arguments,
    empty_production_resource_metrics,
    run_production_runtime,
    select_production_samples,
)
from tools.evaluation.evaluate_mitre_attack_mapping import (
    _stable_digest, acceptance, evaluate,
)
from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_CORPUS_VERSION,
    AttackEvaluationCorpusManifest,
    AttackEvaluationPartitionCount,
    AttackEvaluationSample,
    AttackTechniqueExpectation,
)
from Virus_Scan.detection.attack.evaluation_metrics import (
    AttackProductionEvaluationMetrics,
)
from Virus_Scan.detection.attack.evaluation_outcomes import (
    AttackTechniqueEvaluationOutcome,
)
from Virus_Scan.detection.attack.evaluation_results import (
    AttackProductionEvaluationRow,
)
from Virus_Scan.detection.attack.integrity import (
    git_blob_sha1_bytes,
    sha256_bytes,
)
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.attack.versioning import ATTACK_MAPPING_POLICY_VERSION
from Virus_Scan.storage.cache_repository import ScanCacheRepository
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleOwner
from Virus_Scan.tests.support.scan_cache_fixtures import verified_scan_cache_identity
from Virus_Scan.yara.config import load_config

_TECHNIQUES = (
    ("T1003", "Credential Dumping", ("credential-access",), False),
    ("T1021", "Remote Services", ("lateral-movement",), False),
    ("T1041", "Exfiltration Over C2", ("exfiltration",), False),
    ("T1055", "Process Injection", ("execution", "defense-evasion"), False),
    ("T1059", "Command Interpreter", ("execution",), False),
    ("T1059.001", "PowerShell", ("execution",), False),
    ("T1105", "Ingress Tool Transfer", ("command-and-control",), False),
    ("T1562.001", "Impair Defenses", ("defense-evasion",), True),
)
_TACTICS = {
    "credential-access": "TA0006",
    "lateral-movement": "TA0008",
    "exfiltration": "TA0010",
    "execution": "TA0002",
    "defense-evasion": "TA0005",
    "command-and-control": "TA0011",
}


def _stix_id(kind: str, number: int) -> str:
    return f"{kind}--{number:08x}-0000-4000-8000-{number:012x}"


def _tiny_bundle() -> bytes:
    objects: list[dict[str, object]] = []
    for index, (shortname, attack_id) in enumerate(sorted(_TACTICS.items()), 1):
        objects.append({
            "type": "x-mitre-tactic",
            "id": _stix_id("x-mitre-tactic", index),
            "name": shortname,
            "description": "",
            "x_mitre_shortname": shortname,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": attack_id},
            ],
        })
    for index, (attack_id, name, tactics, revoked) in enumerate(_TECHNIQUES, 100):
        objects.append({
            "type": "attack-pattern",
            "id": _stix_id("attack-pattern", index),
            "name": name,
            "description": "",
            "revoked": revoked,
            "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": shortname}
                for shortname in tactics
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": attack_id},
            ],
        })
    return json.dumps({
        "type": "bundle",
        "id": _stix_id("bundle", 999),
        "objects": objects,
    }, sort_keys=True).encode("utf-8")


def _expectations() -> tuple[AttackTechniqueExpectation, ...]:
    return tuple(
        AttackTechniqueExpectation(
            attack_id,
            "rejected",
            "Synthetic raw-file evaluator oracle.",
            ("synthetic:raw-runtime",),
            "artifact_implementation",
            "Windows",
            "static_structure",
        )
        for attack_id, _name, _tactics, _revoked in _TECHNIQUES
    )


def _manifest(tmp_path: Path, *, sample_count: int = 1) -> tuple[AttackEvaluationCorpusManifest, Path, Path]:
    bundle = _tiny_bundle()
    identity = git_blob_sha1_bytes(bundle)
    snapshot = import_stix_bundle(
        bundle,
        dataset_version=identity,
        source_ref="synthetic-test",
        expected_git_blob_sha1=identity,
        computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(bundle),
    )
    bundle_path = tmp_path / "enterprise-attack.json"
    bundle_path.write_bytes(bundle)
    samples: list[AttackEvaluationSample] = []
    for index in range(sample_count):
        path = tmp_path / f"sample-{index}.ps1"
        payload = ("# NON-EXECUTABLE synthetic powershell marker " + str(index) + "\n").encode()
        path.write_bytes(payload)
        samples.append(AttackEvaluationSample(
            sample_id=f"sample-{index}",
            partition="development",
            source_family=f"family-{index}",
            related_group=f"group-{index}",
            package_campaign_id=f"campaign-{index}",
            collection_session=f"session-{index}",
            malware_class="malware" if index % 2 == 0 else "control",
            sample_category=(
                "malware_artifact" if index % 2 == 0 else "clean_software"
            ),
            artifact_path=str(path),
            artifact_sha256=sha256(payload).hexdigest(),
            artifact_size=len(payload),
            acquisition_provenance="Synthetic production-path integration fixture.",
            collected_at="2026-07-13T00:00:00Z",
            platform="Windows",
            file_type="powershell_text_fixture",
            technique_expectations=_expectations(),
            evidence_domain="synthetic_engineering",
            eligible_for_production_metrics=False,
            eligible_for_policy_promotion=False,
            eligible_for_production_calibration=False,
        ))
    malware_count = sum(sample.malware_class == "malware" for sample in samples)
    control_count = len(samples) - malware_count
    manifest = AttackEvaluationCorpusManifest(
        corpus_id="stage2636-10014-production-test",
        corpus_version=ATTACK_EVALUATION_CORPUS_VERSION,
        corpus_evidence_class="synthetic_development",
        label_review_status="artifact_byte_oracle",
        generation_policy_digest="7" * 64,
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
        repository_version="synthetic-test-repository",
        repository_digest=snapshot.digest,
        policy_frozen_at="2026-07-14T00:00:00Z",
        frozen_at="2026-07-15T00:00:00Z",
        reviewer_ids=("synthetic-reviewer-a", "synthetic-reviewer-b"),
        adjudicator_ids=("synthetic-adjudicator",),
        reviewed_technique_ids=tuple(item[0] for item in _TECHNIQUES),
        partition_counts=(
            AttackEvaluationPartitionCount(
                "development", malware_count, control_count,
            ),
            AttackEvaluationPartitionCount("future_time_holdout", 0, 0),
            AttackEvaluationPartitionCount("locked_holdout", 0, 0),
            AttackEvaluationPartitionCount("validation", 0, 0),
        ),
        samples=tuple(samples),
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest.to_record()), encoding="utf-8")
    return manifest, manifest_path, bundle_path


def _outcome(probability: float = 0.0) -> AttackTechniqueEvaluationOutcome:
    return AttackTechniqueEvaluationOutcome(
        "T1003", "rejected", "rejected", probability, 0.0,
        (), (), "insufficient_implementation_evidence", "", (), (),
    )


def test_result_contracts_deny_nonconfirmed_probability_and_synthetic_authority() -> None:
    with pytest.raises(ValueError, match="nonconfirmed_probability_invalid"):
        _outcome(0.1)
    row = AttackProductionEvaluationRow(
        "sample", "development", "control", "/external/sample.bin", "1" * 64,
        "path_sample", 0, "completed", "benign_clean", (), "2" * 64,
        "3" * 40, ATTACK_MAPPING_POLICY_VERSION, (_outcome(),),
    )
    metrics = AttackProductionEvaluationMetrics.from_rows(
        (row,), synthetic_development=True, production_authority=False,
    )
    assert metrics.production_authority is False
    assert metrics.nonconfirming_zero_probability is True
    with pytest.raises(ValueError, match="synthetic_authority_invalid"):
        replace(metrics, production_authority=True)


def test_selection_is_balanced_deterministic_and_partition_bounded(tmp_path: Path) -> None:
    manifest, _manifest_path, _bundle_path = _manifest(tmp_path, sample_count=4)
    selected = select_production_samples(manifest, partition="development", limit=4)
    assert tuple(item.sample_id for item in selected) == (
        "sample-0", "sample-1", "sample-2", "sample-3",
    )
    assert sum(item.malware_class == "malware" for item in selected) == 2
    assert sum(item.malware_class == "control" for item in selected) == 2
    assert select_production_samples(
        manifest, partition=ALL_PARTITIONS, limit=4,
    ) == selected
    with pytest.raises(ValueError, match="partition_capacity_invalid"):
        select_production_samples(manifest, partition="validation", limit=1)



def test_production_yara_modes_bind_one_canonical_package_and_exact_digest(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    rules_root = repository / "Yara"
    rules_root.mkdir(parents=True)
    core = rules_root / "yara-forge-rules-core.zip"
    extended = rules_root / "yara-forge-rules-extended.zip"
    core.write_bytes(b"synthetic-core-rule-source")
    extended.write_bytes(b"synthetic-extended-rule-source")

    core_source, core_digest = _resolve_yara_source(
        repository, yara_mode="core", yara_source_path=None,
    )
    core_config = _prepare_yara_controls(
        tmp_path / "core-state", yara_mode="core", source_sha256=core_digest,
    )
    loaded_core = load_config(core_config)
    core_args = _yara_command_arguments(
        yara_mode="core",
        yara_source_path=core_source,
        yara_config_path=core_config,
    )
    assert loaded_core.light_expected_sha256 == core_digest
    assert loaded_core.full_expected_sha256 == ""
    assert core_args.count("--yaralight") == 1
    assert "--yara" not in core_args
    assert "--no-yara" not in core_args
    assert core_args[core_args.index("--deep-scan-mode") + 1] == "fast"

    extended_source, extended_digest = _resolve_yara_source(
        repository, yara_mode="extended", yara_source_path=None,
    )
    extended_config = _prepare_yara_controls(
        tmp_path / "extended-state",
        yara_mode="extended",
        source_sha256=extended_digest,
    )
    loaded_extended = load_config(extended_config)
    extended_args = _yara_command_arguments(
        yara_mode="extended",
        yara_source_path=extended_source,
        yara_config_path=extended_config,
    )
    assert loaded_extended.full_expected_sha256 == extended_digest
    assert loaded_extended.light_expected_sha256 == ""
    assert extended_args.count("--yara") == 1
    assert "--yaralight" not in extended_args
    assert "--no-yaralight" in extended_args
    assert extended_args[extended_args.index("--deep-scan-mode") + 1] == "thorough"

    disabled_args = _yara_command_arguments(
        yara_mode="disabled", yara_source_path=None, yara_config_path=None,
    )
    assert "--no-yara" in disabled_args
    assert "--no-yaralight" in disabled_args
    with pytest.raises(ValueError, match="source_while_disabled"):
        _resolve_yara_source(
            repository, yara_mode="disabled", yara_source_path=core,
        )


def test_process_yara_metric_environment_is_explicit_and_nonsemantic(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    state = tmp_path / "state"
    repository.mkdir()
    state.mkdir()
    serial = _runtime_environment(
        repository, state, scheduler="serial", yara_mode="core", hash_seed=17,
    )
    process_disabled = _runtime_environment(
        repository, state, scheduler="process", yara_mode="disabled", hash_seed=17,
    )
    process_core = _runtime_environment(
        repository, state, scheduler="process", yara_mode="core", hash_seed=17,
    )
    assert serial["PYTHONHASHSEED"] == "17"
    assert process_disabled["PYTHONHASHSEED"] == "17"
    assert process_core["PYTHONHASHSEED"] == "17"
    assert "UMIGE_YARA_SCAN_METRIC_LOGGING" not in serial
    assert "UMIGE_YARA_SCAN_METRIC_LOGGING" not in process_disabled
    assert process_core["UMIGE_YARA_SCAN_METRIC_LOGGING"] == "1"

def test_yara_metric_parser_reports_exact_calls_latency_and_counts(tmp_path: Path) -> None:
    log_path = tmp_path / "scan.log"
    records = (
        {
            "duplicate_match_count": 1,
            "elapsed_ns": 10,
            "engine_match_invoked": True,
            "package_kind": "core",
            "retained_match_count": 2,
            "scan_pass_id": "yscan_a",
            "status": "complete",
            "total_match_count": 3,
            "truncated_match_count": 0,
        },
        {
            "duplicate_match_count": 0,
            "elapsed_ns": 30,
            "engine_match_invoked": True,
            "package_kind": "core",
            "retained_match_count": 0,
            "scan_pass_id": "yscan_b",
            "status": "complete_no_match",
            "total_match_count": 0,
            "truncated_match_count": 0,
        },
        {
            "duplicate_match_count": 0,
            "elapsed_ns": 0,
            "engine_match_invoked": False,
            "package_kind": "unavailable",
            "retained_match_count": 0,
            "scan_pass_id": "yscan_c",
            "status": "unavailable",
            "total_match_count": 0,
            "truncated_match_count": 0,
        },
    )
    log_path.write_text(
        "".join(
            "INFO [YARA_SCAN_METRIC] "
            + json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    metrics = _parse_yara_scan_metrics(log_path)
    assert metrics == {
        "metric_line_count": 3,
        "engine_call_count": 2,
        "unique_scan_pass_count": 2,
        "latency_min_ns": 10,
        "latency_median_ns": 10,
        "latency_p95_ns": 30,
        "latency_p99_ns": 30,
        "latency_max_ns": 30,
        "total_match_count": 3,
        "retained_match_count": 2,
        "duplicate_match_count": 1,
        "truncated_match_count": 0,
        "status_counts": (("complete", 1), ("complete_no_match", 1), ("unavailable", 1)),
    }


def test_resource_metrics_are_strict_and_excluded_from_semantic_digest() -> None:
    metrics = AttackProductionResourceMetrics(
        1, 2, 3, 4, 5, 2, 2, 2, 10, 10, 20, 20, 20, 3, 2, 1, 0,
        (("complete", 2),),
    )
    assert metrics.to_record()["yara_engine_call_count"] == 2
    with pytest.raises(TypeError, match="resource_metric_invalid"):
        replace(metrics, elapsed_ns=True)
    left = {"production_run": {"performance_metrics": {"elapsed_ns": 1}, "rows": ()}}
    right = {"production_run": {"performance_metrics": {"elapsed_ns": 999}, "rows": ()}}
    assert _stable_digest(left) == _stable_digest(right)


def test_reconciliation_rejects_duplicate_output_keys(tmp_path: Path) -> None:
    manifest, _manifest_path, _bundle_path = _manifest(tmp_path, sample_count=1)
    output = tmp_path / "output.json"
    sample_path = manifest.samples[0].artifact_path
    encoded_sample_path = json.dumps(sample_path, ensure_ascii=True)
    output.write_text(
        "{" + encoded_sample_path + ":{}," + encoded_sample_path + ":{}}",
        encoding="utf-8",
    )
    runtime = AttackProductionRuntimeOutput(
        selected_samples=manifest.samples,
        run_root=tmp_path,
        output_path=output,
        stdout_path=tmp_path / "stdout",
        stderr_path=tmp_path / "stderr",
        bundle_git_blob_sha1="3" * 40,
        bundle_sha256="4" * 64,
        returncode=0,
        command=("python",),
        yara_mode="disabled",
        yara_source_path="",
        yara_source_sha256="",
        resource_metrics=empty_production_resource_metrics(),
    )
    with pytest.raises(ValueError, match="output_duplicate_key"):
        reconcile_production_runtime(corpus=manifest, runtime=runtime)


def test_reconciliation_accepts_completed_risk_exits_and_rejects_runtime_failures(
    tmp_path: Path,
) -> None:
    manifest, _manifest_path, bundle_path = _manifest(tmp_path, sample_count=1)
    runtime = run_production_runtime(
        repository_root=Path(__file__).resolve().parents[2],
        corpus=manifest,
        partition="development",
        limit=1,
        run_root=tmp_path / "risk-runtime",
        bundle_path=bundle_path,
        scheduler="serial",
        timeout_seconds=180,
    )
    output = json.loads(runtime.output_path.read_text(encoding="utf-8"))
    key, base_record = next(iter(output.items()))

    def write_record(
        exit_code: int,
        final_status: str,
        *,
        timed_out: bool = False,
        errors: list[object] | None = None,
        warnings: list[object] | None = None,
    ) -> None:
        record = json.loads(json.dumps(base_record))
        record["exit_code"] = exit_code
        record["final_status"] = final_status
        record["timed_out"] = timed_out
        record["errors"] = [] if errors is None else errors
        record["errors_warnings"] = [] if warnings is None else warnings
        runtime.output_path.write_text(
            json.dumps({key: record}, sort_keys=True),
            encoding="utf-8",
        )

    for exit_code in range(4):
        status = "completed" if exit_code == 0 else "completed_nonzero_exit"
        write_record(exit_code, status)
        rows, metrics = reconcile_production_runtime(
            corpus=manifest,
            runtime=replace(runtime, returncode=exit_code),
        )
        assert rows[0].runtime_exit_code == exit_code
        assert rows[0].completed is True
        assert metrics.row_count == 1

    write_record(0, "completed")
    with pytest.raises(ValueError, match="runtime_error_exit"):
        reconcile_production_runtime(corpus=manifest, runtime=replace(runtime, returncode=4))
    write_record(1, "completed")
    with pytest.raises(ValueError, match="record_incomplete"):
        reconcile_production_runtime(corpus=manifest, runtime=replace(runtime, returncode=1))
    write_record(0, "completed", timed_out=True)
    with pytest.raises(ValueError, match="record_timed_out"):
        reconcile_production_runtime(corpus=manifest, runtime=runtime)
    write_record(0, "completed", errors=["synthetic_runtime_failure"])
    with pytest.raises(ValueError, match="record_failed"):
        reconcile_production_runtime(corpus=manifest, runtime=runtime)
    write_record(0, "completed", warnings=["bounded_static_metadata_warning"])
    rows, _metrics = reconcile_production_runtime(corpus=manifest, runtime=runtime)
    assert rows[0].degraded_reasons == ("bounded_static_metadata_warning",)


def test_evaluator_scan_cache_metrics_disabled_shape_is_explicit(tmp_path: Path) -> None:
    metrics = _scan_cache_metrics(
        output_path=tmp_path / "not-read-when-disabled.json",
        state_root=tmp_path,
        scan_cache_enabled=False,
    )
    assert metrics == {
        "hit_count": 0,
        "miss_count": 0,
        "database_bytes": 0,
        "wal_bytes": 0,
        "content_row_count": 0,
        "alias_row_count": 0,
        "fast_fingerprint_row_count": 0,
        "execution_identity_row_count": 0,
        "semantic_result_row_count": 0,
        "parse_result_row_count": 0,
        "static_operation_row_count": 0,
        "scanner_observation_row_count": 0,
    }


def test_evaluator_scan_cache_metrics_use_canonical_cache_repository(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    repository = ScanCacheRepository(lifecycle)
    profiles = tmp_path / "profiles"
    repository.configure(profiles, enabled=True)
    try:
        identity = verified_scan_cache_identity()
        assert repository.put_result(
            content_sha256="a" * 64,
            content_size=7,
            canonical_path=str(tmp_path / "sample.bin"),
            file_name="sample.bin",
            execution_identity=identity,
            result={"classification": "benign_clean", "tags": []},
        ) is True
    finally:
        lifecycle.close()
    output_path = tmp_path / "scan_results.json"
    output_path.write_text(
        json.dumps({"sample": {"cache_hit": True}}, sort_keys=True),
        encoding="utf-8",
    )
    metrics = _scan_cache_metrics(
        output_path=output_path,
        state_root=tmp_path,
        scan_cache_enabled=True,
    )
    assert metrics["hit_count"] == 1
    assert metrics["miss_count"] == 0
    assert metrics["content_row_count"] == 1
    assert metrics["execution_identity_row_count"] == 1
    assert metrics["semantic_result_row_count"] == 1
    assert metrics["database_bytes"] > 0
    assert metrics["wal_bytes"] >= 0


def test_evaluator_scan_cache_metrics_have_no_direct_sqlite_owner() -> None:
    source = Path("tools/evaluation/attack_production_runtime.py")
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    direct_imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "sqlite3" not in direct_imports
    assert "Virus_Scan.storage.cache_repository" in imported_modules
    assert "Virus_Scan.storage.sqlite_lifecycle" in imported_modules
    assert "sqlite3.connect" not in source.read_text(encoding="utf-8")


def test_evaluator_support_does_not_import_or_construct_internal_attack_evidence() -> None:
    forbidden = {
        "TagEvidence", "ChainEvidence", "ChainDecision", "map_attack_evidence",
        "mitre_probability_component", "official_attack_probability_evidence",
    }
    for source in (
        Path("tools/evaluation/evaluate_mitre_attack_mapping.py"),
        Path("tools/evaluation/attack_production_runtime.py"),
        Path("tools/evaluation/attack_production_reconciliation.py"),
    ):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        names = {
            alias.name
            for node in ast.walk(tree)
            if type(node) in (ast.Import, ast.ImportFrom)
            for alias in node.names
        }
        assert names.isdisjoint(forbidden)


def test_single_evaluator_runs_raw_file_through_runtime_and_stays_zero_authority(
    tmp_path: Path,
) -> None:
    _manifest_value, manifest_path, bundle_path = _manifest(tmp_path)
    result = evaluate(
        corpus_path=manifest_path,
        include_process=False,
        run_production=True,
        production_partition="development",
        production_limit=1,
        production_root=tmp_path / "production-run",
        bundle_path=bundle_path,
        production_scheduler="serial",
        production_timeout_seconds=180,
    )
    assert result["production_path_execution_available"] is True
    assert result["production_path_evaluation_available"] is True
    assert result["engineering_metrics_available"] is True
    assert result["production_metrics_authority"] is False
    assert result["model_metrics_available"] is False
    assert result["semantic_validity_10_10_supported"] is False
    assert result["production_run"]["engineering_metrics"]["row_count"] == 1
    assert result["production_run"]["performance_metrics"]["elapsed_ns"] > 0
    assert result["production_run"]["performance_metrics"]["yara_engine_call_count"] == 0
    assert result["production_run"]["engineering_metrics"][
        "nonconfirming_zero_probability"
    ] is True
    assert result["evaluation_rows"][0]["completed"] is True
    assert all(acceptance(result).values())
