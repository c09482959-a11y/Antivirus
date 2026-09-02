"""Single deterministic corpus and production-path ATT&CK evaluator.

The evaluator validates the canonical multi-label manifest and can optionally
run selected raw artifacts through ``Virus_Scan.runtime_main``. Synthetic runs
produce engineering metrics only and never acquire production or calibration
authority.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path, PosixPath, WindowsPath
import subprocess
import sys
from time import perf_counter

from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_CORPUS_VERSION,
    AttackEvaluationCorpusManifest,
)
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
)
from tools.evaluation.attack_production_reconciliation import (
    reconcile_production_runtime,
)
from tools.evaluation.attack_production_runtime import run_production_runtime

EVALUATION_VERSION = ATTACK_EVALUATION_PROVENANCE
CORPUS_VERSION = ATTACK_EVALUATION_CORPUS_VERSION
DEFAULT_CORPUS_MANIFEST = Path(
    "/mnt/data/UMIGE_Evaluation_Corpus/attack_evaluation_corpus_manifest.json"
)
DEFAULT_BUNDLE_PATH = Path("/mnt/data/Mitre/enterprise-attack.json")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CHUNK_SIZE = 1024 * 1024


def _stable_digest(value: dict[str, object]) -> str:
    projection = dict(value)
    projection.pop("elapsed_seconds", None)
    projection.pop("manifest_digest", None)
    projection.pop("process_determinism", None)
    corpus = projection.get("corpus")
    if type(corpus) is dict:
        normalized_corpus = dict(corpus)
        normalized_corpus["manifest_path"] = "<external-corpus-manifest>"
        projection["corpus"] = normalized_corpus
    production = projection.get("production_run")
    if type(production) is dict:
        normalized_production = dict(production)
        normalized_production.pop("performance_metrics", None)
        projection["production_run"] = normalized_production
    payload = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _file_digest(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(_CHUNK_SIZE)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _artifact_status(corpus: AttackEvaluationCorpusManifest) -> dict[str, object]:
    missing: list[str] = []
    unsafe: list[str] = []
    size_mismatched: list[str] = []
    digest_mismatched: list[str] = []
    for sample in corpus.samples:
        path = Path(sample.artifact_path)
        if path_contains_filesystem_alias(path):
            unsafe.append(sample.sample_id)
            continue
        if not path.is_file():
            missing.append(sample.sample_id)
            continue
        if path.stat().st_size != sample.artifact_size:
            size_mismatched.append(sample.sample_id)
            continue
        if _file_digest(path) != sample.artifact_sha256:
            digest_mismatched.append(sample.sample_id)
    all_available = not (
        missing or unsafe or size_mismatched or digest_mismatched
    )
    return {
        "all_artifacts_available": all_available,
        "missing_sample_ids": tuple(sorted(missing)),
        "unsafe_sample_ids": tuple(sorted(unsafe)),
        "size_mismatch_sample_ids": tuple(sorted(size_mismatched)),
        "digest_mismatch_sample_ids": tuple(sorted(digest_mismatched)),
    }


def _corpus_status(path: Path) -> dict[str, object]:
    if path_contains_filesystem_alias(path) or not path.is_file():
        return {
            "available": False,
            "unavailable_reason": "independent_corpus_manifest_unavailable",
            "manifest_path": str(path),
            "manifest_digest": "",
            "corpus_evidence_class": "",
            "label_review_status": "",
            "generation_policy_digest": "",
            "sample_count": 0,
            "malware_sample_count": 0,
            "control_sample_count": 0,
            "partition_counts": {},
            "future_time_holdout_available": False,
            "exact_5000_malware_contract": False,
            "minimum_5000_control_contract": False,
            "artifact_status": {
                "all_artifacts_available": False,
                "missing_sample_ids": (),
                "unsafe_sample_ids": (),
                "size_mismatch_sample_ids": (),
                "digest_mismatch_sample_ids": (),
            },
        }
    corpus = AttackEvaluationCorpusManifest.from_path(path)
    partition_counts = {
        item.partition: {
            "malware": item.malware_count,
            "control": item.control_count,
        }
        for item in corpus.partition_counts
    }
    return {
        "available": True,
        "unavailable_reason": "",
        "manifest_path": str(path),
        "manifest_digest": corpus.digest,
        "corpus_evidence_class": corpus.corpus_evidence_class,
        "label_review_status": corpus.label_review_status,
        "generation_policy_digest": corpus.generation_policy_digest,
        "sample_count": len(corpus.samples),
        "malware_sample_count": corpus.malware_sample_count,
        "control_sample_count": corpus.control_sample_count,
        "partition_counts": partition_counts,
        "future_time_holdout_available": (
            partition_counts["future_time_holdout"]["malware"] > 0
            and partition_counts["future_time_holdout"]["control"] > 0
        ),
        "exact_5000_malware_contract": corpus.malware_sample_count == 5_000,
        "minimum_5000_control_contract": corpus.control_sample_count >= 5_000,
        "artifact_status": _artifact_status(corpus),
    }


def _process_determinism(corpus_path: Path) -> dict[str, object]:
    command = [
        sys.executable,
        "-m",
        "tools.evaluation.evaluate_mitre_attack_mapping",
        "--digest-only",
        "--corpus",
        str(corpus_path),
    ]
    runs = tuple(
        subprocess.run(
            command,
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        for _ in range(2)
    )
    return {
        "all_exit_zero": all(run.returncode == 0 for run in runs),
        "output_equal": runs[0].stdout == runs[1].stdout,
        "digest": runs[0].stdout.strip(),
    }


def _production_run(
    *,
    corpus_path: Path,
    partition: str,
    limit: int,
    output_root: Path,
    bundle_path: Path,
    scheduler: str,
    timeout_seconds: int,
    yara_mode: str,
    yara_source_path: Path | None,
) -> dict[str, object]:
    corpus = AttackEvaluationCorpusManifest.from_path(corpus_path)
    runtime = run_production_runtime(
        repository_root=REPOSITORY_ROOT,
        corpus=corpus,
        partition=partition,
        limit=limit,
        run_root=output_root,
        bundle_path=bundle_path,
        scheduler=scheduler,
        timeout_seconds=timeout_seconds,
        yara_mode=yara_mode,
        yara_source_path=yara_source_path,
    )
    rows, metrics = reconcile_production_runtime(corpus=corpus, runtime=runtime)
    return {
        "available": True,
        "partition": partition,
        "limit": limit,
        "scheduler": scheduler,
        "bundle_git_blob_sha1": runtime.bundle_git_blob_sha1,
        "bundle_sha256": runtime.bundle_sha256,
        "runtime_returncode": runtime.returncode,
        "selected_sample_ids": tuple(row.sample_id for row in rows),
        "rows": tuple(row.to_record() for row in rows),
        "engineering_metrics": metrics.to_record(),
        "performance_metrics": runtime.resource_metrics.to_record(),
        "production_metrics_authority": metrics.production_authority,
        "yara_enabled": runtime.yara_mode != "disabled",
        "yara_mode": runtime.yara_mode,
        "yara_source_path": runtime.yara_source_path,
        "yara_source_sha256": runtime.yara_source_sha256,
    }


def evaluate(
    *,
    corpus_path: Path = DEFAULT_CORPUS_MANIFEST,
    include_process: bool = True,
    run_production: bool = False,
    production_partition: str = "development",
    production_limit: int = 2,
    production_root: Path | None = None,
    bundle_path: Path = DEFAULT_BUNDLE_PATH,
    production_scheduler: str = "serial",
    production_timeout_seconds: int = 600,
    production_yara_mode: str = "disabled",
    production_yara_source: Path | None = None,
) -> dict[str, object]:
    if type(corpus_path) not in (PosixPath, WindowsPath):
        raise TypeError("attack_evaluation_corpus_path_invalid")
    if type(run_production) is not bool:
        raise TypeError("attack_evaluation_run_production_invalid")
    if type(bundle_path) not in (PosixPath, WindowsPath):
        raise TypeError("attack_evaluation_bundle_path_invalid")
    if run_production and type(production_root) not in (PosixPath, WindowsPath):
        raise TypeError("attack_evaluation_production_root_required")
    started = perf_counter()
    corpus = _corpus_status(corpus_path)
    production = (
        _production_run(
            corpus_path=corpus_path,
            partition=production_partition,
            limit=production_limit,
            output_root=production_root,
            bundle_path=bundle_path,
            scheduler=production_scheduler,
            timeout_seconds=production_timeout_seconds,
            yara_mode=production_yara_mode,
            yara_source_path=production_yara_source,
        )
        if run_production
        else {
            "available": False,
            "unavailable_reason": "production_run_not_requested",
            "rows": (),
            "engineering_metrics": {},
            "performance_metrics": {},
            "production_metrics_authority": False,
            "yara_enabled": False,
            "yara_mode": production_yara_mode,
            "yara_source_path": "",
            "yara_source_sha256": "",
        }
    )
    confirmed_enabled = tuple(
        item.technique_id
        for item in ATTACK_TECHNIQUE_POLICIES
        if item.admission_state in {"confirmed_enabled", "production_mature"}
    )
    nonconfirming_zero_contract = all(
        item.admission_state in {
            "candidate_only", "unsupported_by_sensors", "retired",
        }
        and item.evaluation_manifest_digest == ""
        and item.calibration_artifact_id == ""
        for item in ATTACK_TECHNIQUE_POLICIES
    )
    corpus_available = corpus["available"] is True
    independent_corpus_available = (
        corpus_available
        and corpus["corpus_evidence_class"] == "independent_external"
        and corpus["label_review_status"] == "independent_adjudicated"
    )
    synthetic_corpus_available = (
        corpus_available
        and corpus["corpus_evidence_class"] == "synthetic_development"
        and corpus["label_review_status"] == "artifact_byte_oracle"
    )
    artifacts_available = (
        corpus["artifact_status"]["all_artifacts_available"] is True
    )
    corpus_engineering_ready = (
        corpus_available
        and artifacts_available
        and corpus["exact_5000_malware_contract"] is True
        and corpus["minimum_5000_control_contract"] is True
        and corpus["future_time_holdout_available"] is True
    )
    corpus_reference_ready = (
        independent_corpus_available
        and artifacts_available
        and corpus["exact_5000_malware_contract"] is True
        and corpus["minimum_5000_control_contract"] is True
        and corpus["future_time_holdout_available"] is True
    )
    limitations = {
        "threshold_fpr_confidence_intervals_unavailable",
        "brier_log_loss_ece_unavailable",
    }
    if not run_production:
        limitations.add("production_scanner_metrics_not_executed")
    else:
        if production["yara_enabled"] is not True:
            limitations.add("yara_disabled_for_production_path")
        if synthetic_corpus_available:
            limitations.add("synthetic_production_metrics_engineering_only")
    if not corpus_available:
        limitations.add("independent_multilabel_corpus_unavailable")
    else:
        if synthetic_corpus_available:
            limitations.update({
                "synthetic_development_corpus_not_independent",
                "synthetic_labels_not_operational_ground_truth",
                "future_time_partition_is_simulated",
            })
        elif not independent_corpus_available:
            limitations.add("corpus_review_provenance_not_independent")
        if corpus["exact_5000_malware_contract"] is not True:
            limitations.add("exact_5000_malware_contract_not_met")
        if corpus["minimum_5000_control_contract"] is not True:
            limitations.add("minimum_5000_control_contract_not_met")
        if corpus["future_time_holdout_available"] is not True:
            limitations.add("independent_future_time_corpus_unavailable")
        if not artifacts_available:
            limitations.add("corpus_artifact_integrity_unavailable")
    manifest: dict[str, object] = {
        "evaluation_version": EVALUATION_VERSION,
        "corpus_version": CORPUS_VERSION,
        "policy_version": ATTACK_MAPPING_POLICY_VERSION,
        "evaluation_scope": (
            "synthetic_development_production_path_engineering"
            if synthetic_corpus_available and production["available"] is True
            else (
                "independent_multilabel_production_path_evaluation"
                if independent_corpus_available and production["available"] is True
                else (
                    "synthetic_development_corpus_validated_production_run_pending"
                    if synthetic_corpus_available
                    else "independent_multilabel_corpus_unavailable_fail_closed"
                )
            )
        ),
        "independent_corpus_available": independent_corpus_available,
        "synthetic_development_corpus_available": synthetic_corpus_available,
        "corpus": corpus,
        "corpus_engineering_run_ready": corpus_engineering_ready,
        "corpus_reference_run_ready": corpus_reference_ready,
        "registry_derived_ground_truth": False,
        "post_scanner_evidence_injection_allowed": False,
        "production_run_requested": run_production,
        "production_path_execution_available": production["available"] is True,
        "production_path_evaluation_available": production["available"] is True,
        "engineering_metrics_available": production["available"] is True,
        "production_metrics_authority": production["production_metrics_authority"],
        "model_metrics_available": (
            production["available"] is True
            and production["production_metrics_authority"] is True
        ),
        "semantic_validity_10_10_supported": False,
        "confirmed_enabled_technique_ids": confirmed_enabled,
        "confirmed_enabled_count": len(confirmed_enabled),
        "all_confirmed_enabled_have_independent_holdout": not confirmed_enabled,
        "candidate_and_rejected_zero_probability_contract": nonconfirming_zero_contract,
        "production_run": production,
        "evaluation_rows": production["rows"],
        "unresolved_limitations": tuple(sorted(limitations)),
        "elapsed_seconds": round(perf_counter() - started, 6),
    }
    manifest["manifest_digest"] = _stable_digest(manifest)
    manifest["process_determinism"] = (
        _process_determinism(corpus_path)
        if include_process
        else {
            "all_exit_zero": True,
            "output_equal": True,
            "digest": manifest["manifest_digest"],
        }
    )
    return manifest


def acceptance(manifest: dict[str, object]) -> dict[str, bool]:
    confirmed_count = manifest["confirmed_enabled_count"]
    corpus_available = manifest["independent_corpus_available"] is True
    synthetic_available = manifest["synthetic_development_corpus_available"] is True
    return {
        "evaluation_provenance_exact": (
            manifest["evaluation_version"] == EVALUATION_VERSION
        ),
        "no_registry_derived_ground_truth": (
            manifest["registry_derived_ground_truth"] is False
        ),
        "no_post_scanner_evidence_injection": (
            manifest["post_scanner_evidence_injection_allowed"] is False
        ),
        "candidate_and_rejected_zero_probability": (
            manifest["candidate_and_rejected_zero_probability_contract"] is True
        ),
        "confirmed_enabled_holdout_gate": (
            manifest["all_confirmed_enabled_have_independent_holdout"] is True
        ),
        "corpus_unavailability_fails_closed": (
            corpus_available or synthetic_available or confirmed_count == 0
        ),
        "synthetic_corpus_has_no_production_authority": (
            not synthetic_available
            or (
                manifest["production_metrics_authority"] is False
                and manifest["model_metrics_available"] is False
                and manifest["semantic_validity_10_10_supported"] is False
            )
        ),
        "production_path_claim_matches_execution": (
            manifest["production_path_evaluation_available"]
            is manifest["production_run_requested"]
        ),
        "no_unearned_model_metrics": (
            manifest["model_metrics_available"] is False
            and manifest["semantic_validity_10_10_supported"] is False
        ),
        "process_deterministic": (
            manifest["process_determinism"]["all_exit_zero"] is True
            and manifest["process_determinism"]["output_equal"] is True
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS_MANIFEST))
    parser.add_argument("--digest-only", action="store_true")
    parser.add_argument("--run-production", action="store_true")
    parser.add_argument("--production-partition", default="development")
    parser.add_argument("--production-limit", type=int, default=2)
    parser.add_argument("--production-root", default=None)
    parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE_PATH))
    parser.add_argument(
        "--production-scheduler", choices=("serial", "process"), default="serial",
    )
    parser.add_argument("--production-timeout", type=int, default=600)
    parser.add_argument(
        "--production-yara-mode",
        choices=("disabled", "core", "extended"),
        default="disabled",
    )
    parser.add_argument("--production-yara-source", default=None)
    return parser


def main() -> int:
    args = _parser().parse_args()
    corpus_path = Path(args.corpus)
    manifest = evaluate(
        corpus_path=corpus_path,
        include_process=not args.digest_only,
        run_production=args.run_production,
        production_partition=args.production_partition,
        production_limit=args.production_limit,
        production_root=(
            Path(args.production_root) if args.production_root is not None else None
        ),
        bundle_path=Path(args.bundle),
        production_scheduler=args.production_scheduler,
        production_timeout_seconds=args.production_timeout,
        production_yara_mode=args.production_yara_mode,
        production_yara_source=(
            Path(args.production_yara_source)
            if args.production_yara_source is not None
            else None
        ),
    )
    if args.digest_only:
        print(manifest["manifest_digest"])
        return 0
    result = {"manifest": manifest, "acceptance": acceptance(manifest)}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if all(result["acceptance"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
