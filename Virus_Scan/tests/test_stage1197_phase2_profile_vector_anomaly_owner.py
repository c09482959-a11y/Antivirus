import ast
from pathlib import Path

from Virus_Scan.models.profiles import vector_baseline_anomaly
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.vector_statistics import (
    default_profile_vector_statistics,
    update_profile_vector_statistics,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_MODEL_PATH = REPO_ROOT / "Virus_Scan" / "models" / "profiles" / "api.py"
CORE_LOGGING_PATH = REPO_ROOT / "Virus_Scan" / "core" / "logging.py"


def _module_imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(("." * node.level) + (node.module or ""))
    return tuple(imports)


def _function_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_profile_vector_anomaly_owned_by_profile_model_not_core_logging():
    assert "Virus_Scan.core.logging" not in _module_imports(PROFILE_MODEL_PATH)
    assert "vector_baseline_anomaly" not in _function_names(CORE_LOGGING_PATH)


def test_profile_vector_anomaly_cold_start_is_explicit_unavailable_evidence():
    baseline = default_profile_vector_statistics()
    baseline = update_profile_vector_statistics(
        baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"cold:{baseline['count']}",
    )
    baseline = update_profile_vector_statistics(
        baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"cold:{baseline['count']}",
    )
    result = vector_baseline_anomaly(baseline, [0.2] * len(PROFILE_RAW_FEATURE_NAMES))
    assert result["ready"] is False
    assert result["anomaly"] == 0.0
    assert result["reason"] == "insufficient_trusted_profile_support"
    assert result["unavailable_reason"] == "insufficient_trusted_profile_support"
    assert result["count"] == 2
    assert result["evidence_type"] == "profile_vector_baseline"
    assert result["profile_model_version"]
    assert result["degraded"] is True
    assert result["final_json_must_record"] is True
    assert result["replay_record_required"] is True
    assert result["model_failures"][0]["reason"] == "insufficient_trusted_profile_support"
    assert result["model_failures"][0]["output_affecting"] is True

def test_profile_vector_anomaly_trained_baseline_is_bounded_and_ready():
    baseline = default_profile_vector_statistics()
    for _ordinal in range(12):
        baseline = update_profile_vector_statistics(
            baseline, [0.2] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"mature:{_ordinal}",
        )
    result = vector_baseline_anomaly(baseline, [0.8] + [0.1] * (len(PROFILE_RAW_FEATURE_NAMES) - 1))
    assert result["ready"] is True
    assert result["count"] == 12
    assert result["maturity"] == "mature"
    assert result["suppression_authority"] == 1.0
    assert 0.0 <= result["anomaly"] <= 1.0
    assert result["avg_z"] > 0.0
    assert result["max_z"] > 0.0
