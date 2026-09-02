from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


JSON_WRITER = Path("Virus_Scan/publication/json_writer.py")
JSON_FINALIZATION = Path("Virus_Scan/publication/json_finalization")
MODEL_EVIDENCE_API = Path("Virus_Scan/publication/model_evidence_projection/api.py")
MODEL_EVIDENCE_ASSEMBLY = Path("Virus_Scan/publication/model_evidence_projection/assembly.py")


def _function_lengths(path: Path) -> dict[str, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: (node.end_lineno or node.lineno) - node.lineno + 1
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def test_stage1442_json_writer_is_bounded_stable_public_entrypoint() -> None:
    text = JSON_WRITER.read_text(encoding="utf-8")
    assert sum(1 for _ in JSON_WRITER.open(encoding="utf-8")) < 80
    assert "Virus_Scan.scheduler" not in text
    assert "existing_scheduler_final_json_fields" in text
    assert "finalize_scan_results" in text
    assert "compact_result_record" in text


def test_stage1442_json_finalization_package_is_decomposed_and_publication_owned() -> None:
    modules = sorted(path for path in JSON_FINALIZATION.glob("*.py") if path.name != "__init__.py")
    module_names = {path.name for path in modules}
    assert {
        "base_projection.py",
        "compact_record.py",
        "error_fields.py",
        "model_evidence_boundary.py",
        "partial_results.py",
        "record_fields.py",
        "scheduler_projection.py",
        "signal_projection.py",
        "streaming.py",
        "success_context.py",
        "success_fields.py",
    } <= module_names
    for path in modules:
        assert sum(1 for _ in path.open(encoding="utf-8")) < 300, path
        text = path.read_text(encoding="utf-8")
        assert "Virus_Scan.scheduler" not in text, path
        assert "Virus_Scan.models.markov" not in text, path
        assert "Virus_Scan.models.temporal" not in text, path
        assert "Virus_Scan.detection.scoring.adaptive.model_score" not in text, path


def test_stage1442_model_evidence_api_delegates_to_bounded_private_assembly() -> None:
    assert MODEL_EVIDENCE_ASSEMBLY.exists()
    assert _function_lengths(MODEL_EVIDENCE_API)["build_model_evidence_final_json_fields"] <= 6
    for name, length in _function_lengths(MODEL_EVIDENCE_ASSEMBLY).items():
        assert length <= 75, (name, length)
    text = MODEL_EVIDENCE_ASSEMBLY.read_text(encoding="utf-8")
    assert "Virus_Scan.models.markov" not in text
    assert "Virus_Scan.models.temporal" not in text
    assert "Virus_Scan.detection.scoring" not in text


def test_stage1442_decomposed_publication_paths_preserve_model_and_scheduler_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "sample.exe",
            "classification": "suspicious",
            "score": 64,
            "tags": ["alpha"],
            "scheduler_status": "completed",
            "feature_probabilities": {"markov": 0.25},
        }
    )
    assert compact["scheduler_status"] == "completed"
    assert compact["model_evidence"]["feature_probabilities"]["markov"] == 0.25
    projected = build_model_evidence_final_json_fields(
        {"feature_probabilities": {"temporal": {"ready": False, "probability": None, "reason": "cold_start"}}}
    )
    assert projected["model_evidence"]["unavailable_reasons"]["temporal"] == "non_numeric_probability"
