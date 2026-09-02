"""Stage 1217: temporal graph correlation consumes temporal validation through a detection boundary."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.correlation.multi_signal.model_projections import detection_temporal_validation
from Virus_Scan.models.api.temporal_contracts import compute_temporal_validation

TEMPORAL_GRAPH = Path("Virus_Scan/detection/correlation/graph/temporal_graph.py")
MODEL_PROJECTIONS = Path("Virus_Scan/detection/correlation/multi_signal/model_projections.py")


def _import_modules(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return tuple(modules)


def test_temporal_graph_no_longer_imports_temporal_model_directly() -> None:
    imports = _import_modules(TEMPORAL_GRAPH)

    assert "Virus_Scan.models.temporal" not in imports
    assert "Virus_Scan.detection.correlation.multi_signal.model_projections" in imports


def test_temporal_validation_boundary_is_the_only_correlation_temporal_model_import() -> None:
    graph_imports = _import_modules(TEMPORAL_GRAPH)
    projection_imports = _import_modules(MODEL_PROJECTIONS)

    assert not [module for module in graph_imports if module.startswith("Virus_Scan.models")]
    assert "Virus_Scan.models.temporal" not in projection_imports
    assert "Virus_Scan.models.api.temporal_contracts" in projection_imports


def test_temporal_validation_boundary_preserves_canonical_temporal_output(tmp_path) -> None:
    sample = tmp_path / "payload.py"
    sample.write_text("print('x')", encoding="utf-8")
    kwargs = {
        "node": sample,
        "tags": ["encoded_payload_candidate", "process_exec"],
        "prev_stage": "asset",
        "curr_stage": "runtime",
        "markov": {
            "ready": True,
            "transition": 0.0,
            "rarity": 0.0,
            "pair_anomaly": 0.0,
            "sequence_anomaly": 0.0,
        },
    }

    direct = compute_temporal_validation(**kwargs)
    boundary = detection_temporal_validation(**kwargs)

    assert boundary["evidence_type"] == "temporal_validation"
    assert boundary["score"] == direct["score"]
    assert boundary["hits"] == direct["hits"]
    assert boundary["ready"] == direct["ready"]
