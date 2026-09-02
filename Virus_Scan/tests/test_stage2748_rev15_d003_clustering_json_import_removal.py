"""REV15 D003: clustering runtime authority has no arbitrary JSON/path importer."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.models import clustering
from Virus_Scan.models.api import clustering_contracts
from Virus_Scan.models.clustering import common, snapshots


REMOVED_SYMBOLS = (
    "import_cluster_runtime_model_snapshot",
    "import_runtime_model_snapshot",
    "owner_import_runtime_model_snapshot",
    "cluster_snapshot_path_value",
    "_EXACT_CLUSTER_PATH_TYPES",
)


def test_stage2748_d003_removed_clustering_importer_surfaces_are_not_exported() -> None:
    assert not hasattr(clustering_contracts, "import_cluster_runtime_model_snapshot")
    assert not hasattr(clustering, "import_runtime_model_snapshot")
    assert not hasattr(snapshots, "import_runtime_model_snapshot")
    assert not hasattr(common, "cluster_snapshot_path_value")
    assert snapshots.__all__ == ("load_runtime_model_record",)


def test_stage2748_d003_removed_importer_symbols_have_zero_production_definitions_or_reexports() -> None:
    production = Path("Virus_Scan")
    matches: dict[str, list[str]] = {symbol: [] for symbol in REMOVED_SYMBOLS}
    for path in production.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for symbol in REMOVED_SYMBOLS:
            if symbol in text:
                matches[symbol].append(path.as_posix())
    assert matches == {symbol: [] for symbol in REMOVED_SYMBOLS}


def test_stage2748_d003_current_record_hydrator_has_exactly_two_production_callers() -> None:
    expected = {
        "Virus_Scan/models/profiles/learning_transaction.py",
        "Virus_Scan/orchestration/model_state_loader.py",
    }
    callers: set[str] = set()
    for path in Path("Virus_Scan").rglob("*.py"):
        if "tests" in path.parts or path.as_posix() == "Virus_Scan/models/api/clustering_contracts.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "load_cluster_runtime_model_record(" in text:
            callers.add(path.as_posix())
    assert callers == expected


def test_stage2748_d003_clustering_snapshot_owner_has_no_json_or_path_file_hydration() -> None:
    source = Path("Virus_Scan/models/clustering/snapshots.py").read_text(encoding="utf-8")
    assert "json.load" not in source
    assert "Path(" not in source
    assert "open(" not in source
    assert "load_runtime_model_record" in source
