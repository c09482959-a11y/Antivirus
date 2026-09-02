import Virus_Scan.models.clustering as clustering
import Virus_Scan.models.clustering.api as clustering_api
import Virus_Scan.models.clustering.metadata as metadata
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state


def test_stage1449_clustering_metadata_exports_public_names_not_private_aliases() -> None:
    for name in ("cluster_members_for", "cluster_meta_for", "cluster_update_metadata"):
        assert name in clustering.__all__
        assert name in clustering_api.__all__
        assert name in metadata.__all__
    for name in ("_cluster_members_for", "_cluster_meta_for", "_cluster_update_metadata"):
        assert name not in clustering.__all__
        assert name not in clustering_api.__all__
        assert name not in metadata.__all__
        assert not hasattr(clustering, name)
        assert not hasattr(clustering_api, name)
        assert not hasattr(metadata, name)


def test_stage1449_clustering_public_metadata_helpers_preserve_behavior() -> None:
    configure_runtime_cluster_state(RuntimeClusterState())
    assert clustering.cluster_members_for("missing") == frozenset()
    meta = clustering.cluster_meta_for("stage1449")
    assert isinstance(meta, dict)
