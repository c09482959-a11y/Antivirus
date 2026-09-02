from __future__ import annotations

import Virus_Scan.models.clustering as clustering
import Virus_Scan.models.clustering.api as clustering_api
import Virus_Scan.models.clustering.metadata as metadata
import Virus_Scan.models.clustering.similarity as similarity


def test_stage1450_clustering_root_and_api_do_not_publish_private_helpers() -> None:
    assert clustering.__all__
    assert clustering_api.__all__
    assert all(not name.startswith("_") for name in clustering.__all__)
    assert all(not name.startswith("_") for name in clustering_api.__all__)
    assert all(not name.startswith("_") for name in metadata.__all__)
    assert all(not name.startswith("_") for name in similarity.__all__)


def test_stage1450_clustering_root_and_api_keep_canonical_public_owner_names() -> None:
    expected = {
        "build_feature_vector",
        "assign_cluster",
        "assign_cluster_with_context_tags",
        "adaptive_cluster_signal",
        "cluster_members_for",
        "cluster_meta_for",
        "cluster_update_metadata",
        "cluster_risk_score",
        "prune_cluster_state_for_retention",
    }
    assert expected <= set(clustering.__all__)
    assert expected <= set(clustering_api.__all__)


def test_stage1450_clustering_jaccard_overlap_has_public_owner_name_only() -> None:
    assert "cluster_jaccard_similarity" in similarity.__all__
    assert "_jaccard" not in similarity.__all__
    assert similarity.cluster_jaccard_similarity(["a", "b"], ["b", "c"]) == 1 / 3
