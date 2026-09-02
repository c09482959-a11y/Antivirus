"""Stage2636.11 deterministic holdout-manifest acceptance contracts."""
from __future__ import annotations

import hashlib
import json

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_policy import (
    ATTACK_ENSEMBLE_POLICY, ATTACK_INTELLIGENCE_CALIBRATION_VERSION,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import (
    ATTACK_INTELLIGENCE_CLASSIFIERS,
)
from tools.evaluation.evaluate_attack_intelligence import acceptance, evaluate


def test_stage2636_11_holdout_manifest_is_valid_and_all_acceptance_gates_pass() -> None:
    manifest = evaluate()
    gates = acceptance(manifest)
    assert gates and all(gates.values())
    assert manifest["sample_count"] == 66
    assert manifest["partition_counts"] == {
        "train": 22,
        "validation": 22,
        "holdout": 22,
    }
    assert manifest["policy_version"] == ATTACK_ENSEMBLE_POLICY.version
    assert manifest["policy_evaluation_provenance"] == (
        ATTACK_ENSEMBLE_POLICY.evaluation_provenance
    )
    assert ATTACK_ENSEMBLE_POLICY.evaluation_provenance == (
        "stage2636_11020_atomic_family_holdout_v3"
    )
    assert manifest["calibration_version"] == ATTACK_INTELLIGENCE_CALIBRATION_VERSION
    assert manifest["evaluation_version"] == "stage2636_11020_attack_intelligence_evaluation_v4"
    assert manifest["family_confusion"]["holdout"]["off_diagonal_count"] == 0
    assert manifest["family_confusion"]["holdout"]["accuracy"] == 1.0
    assert manifest["benign_engine_runtime_controls"]["false_positive_count"] == 0
    assert manifest["process_determinism"]["all_exit_zero"] is True
    assert manifest["process_determinism"]["output_equal"] is True
    assert manifest["family_thresholds"] == {
        spec.family: spec.production_threshold
        for spec in ATTACK_INTELLIGENCE_CLASSIFIERS
    }


def test_stage2636_11_holdout_manifest_digest_excludes_only_elapsed_time() -> None:
    manifest = evaluate()
    published_digest = manifest["manifest_digest"]
    digest_payload = dict(manifest)
    digest_payload.pop("elapsed_seconds")
    digest_payload.pop("manifest_digest")
    expected = hashlib.sha256(json.dumps(
        digest_payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    assert published_digest == expected
    holdout = manifest["aggregate_metrics"]["holdout"]
    assert holdout["precision"] == 1.0
    assert holdout["recall"] == 1.0
    assert holdout["false_positive_rate"] == 0.0
