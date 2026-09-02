from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields

PUBLIC_ENTRYPOINT = Path("Virus_Scan/publication/model_evidence_projection/__init__.py")
IMPL_PACKAGE = Path("Virus_Scan/publication/model_evidence_projection")

FORBIDDEN_MODEL_COMPUTE_IMPORTS = (
    "Virus_Scan.detection.scoring.adaptive.model_score",
    "Virus_Scan.models.markov",
    "Virus_Scan.models.temporal",
    "Virus_Scan.models.graph",
    "Virus_Scan.models.clustering",
    "Virus_Scan.models.profiles",
    "build_probability_features",
    "calibrated_log_odds_score_100",
)


def test_stage1441_public_writer_is_bounded_entrypoint_without_model_compute_imports() -> None:
    assert not Path("Virus_Scan/publication/model_evidence_writer.py").exists()
    text = PUBLIC_ENTRYPOINT.read_text(encoding="utf-8")
    assert len(text.splitlines()) <= 40
    for token in FORBIDDEN_MODEL_COMPUTE_IMPORTS:
        assert token not in text


def test_stage1441_publication_model_evidence_projection_is_decomposed_package() -> None:
    modules = sorted(path for path in IMPL_PACKAGE.glob("*.py") if path.name != "__init__.py")
    module_names = {path.name for path in modules}
    assert {
        "api.py",
        "container_candidates.py",
        "contract_records.py",
        "contract_sanitization.py",
        "existing_evidence.py",
        "failure_projection.py",
        "model_failure_sanitization.py",
        "nonfinite.py",
        "probability_projection.py",
        "probability_validation.py",
        "record_validation.py",
        "safe_mapping.py",
        "sources.py",
        "unavailable_projection.py",
    }.issubset(module_names)
    assert all(len(path.read_text(encoding="utf-8").splitlines()) < 300 for path in modules)


def test_stage1441_publication_projection_package_does_not_import_model_compute_owners() -> None:
    for path in IMPL_PACKAGE.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
        joined = "\n".join(imported_modules + [text])
        for token in FORBIDDEN_MODEL_COMPUTE_IMPORTS:
            assert token not in joined


def test_stage1441_publication_projection_preserves_existing_final_json_behavior() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "score_metadata": {
                "feature_probabilities": {
                    "markov": 0.75,
                    "temporal": float("nan"),
                    "temporal_unavailable_reason": "non_finite_probability",
                    "model_failure": {
                        "model_name": "temporal",
                        "failure_type": "probability_invalid",
                        "reason": "non_finite_probability",
                    },
                }
            }
        }
    )
    evidence = fields["model_evidence"]
    assert evidence["feature_probabilities"]["markov"] == 0.75
    assert evidence["unavailable_reasons"]["temporal"] == "non_finite_probability"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
