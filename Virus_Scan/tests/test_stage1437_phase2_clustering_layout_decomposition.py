from __future__ import annotations

import inspect
from pathlib import Path

from Virus_Scan.models import clustering


def test_stage1437_clustering_root_monolith_removed_and_package_owners_exist() -> None:
    assert not Path("Virus_Scan/models/clustering.py").exists()
    package = Path("Virus_Scan/models/clustering")
    expected = {
        "api.py",
        "assignment.py",
        "assignment_decision.py",
        "centroid.py",
        "common.py",
        "context.py",
        "metadata.py",
        "microcluster.py",
        "microcluster_record.py",
        "microcluster_update.py",
        "microcluster_values.py",
        "retention.py",
        "risk.py",
        "similarity.py",
        "snapshots.py",
        "state.py",
        "storage.py",
        "vector_baseline.py",
        "vectors.py",
    }
    assert expected <= {path.name for path in package.glob("*.py")}


def test_stage1437_clustering_public_symbols_are_owned_by_decomposed_modules() -> None:
    ownership = {
        clustering.build_feature_vector: "Virus_Scan.models.clustering.vectors",
        clustering.online_vector_update: "Virus_Scan.models.clustering.vector_baseline",
        clustering.assign_cluster_with_context_tags: "Virus_Scan.models.clustering.assignment",
        clustering.prune_cluster_state_for_retention: "Virus_Scan.models.clustering.retention",
        clustering.context_cluster_quality: "Virus_Scan.models.clustering.context",
        clustering.cluster_risk_score: "Virus_Scan.models.clustering.risk",
    }
    for func, module_name in ownership.items():
        assert inspect.getmodule(func).__name__ == module_name
    assert not hasattr(clustering, "update_cluster_centroid")


def test_stage1437_clustering_decomposed_owner_files_are_bounded() -> None:
    oversized = {
        path.name: len(path.read_text(encoding="utf-8").splitlines())
        for path in Path("Virus_Scan/models/clustering").glob("*.py")
        if len(path.read_text(encoding="utf-8").splitlines()) > 250
    }
    assert oversized == {}


def test_stage1437_clustering_owners_do_not_import_graph_model_orprofile_internals() -> None:
    package_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(Path("Virus_Scan/models/clustering").glob("*.py"))
    )
    assert "Virus_Scan.models.graph" not in package_source
    assert "Virus_Scan.models.profiles" not in package_source
