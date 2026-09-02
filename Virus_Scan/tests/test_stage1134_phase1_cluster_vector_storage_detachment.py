from Virus_Scan.models import clustering
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.tests.support.clustering_v2 import assignment_cluster_vector


def _reset_cluster_state():
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage1134_store_node_vector_return_is_detached_from_runtime_state():
    state = _reset_cluster_state()

    source = assignment_cluster_vector()
    returned = clustering.store_node_vector("sample.bin", source)

    assert returned == source
    assert state.node_feature_vectors["sample.bin"] == source
    returned[0] = 99.0
    assert state.node_feature_vectors["sample.bin"] == source


def test_stage1134_store_node_vector_detaches_from_caller_owned_input():
    state = _reset_cluster_state()
    caller_vector = assignment_cluster_vector(offset=0.25)
    expected = list(caller_vector)

    returned = clustering.store_node_vector("caller.bin", caller_vector)

    caller_vector[0] = 999.0
    returned[1] = 888.0
    assert state.node_feature_vectors["caller.bin"] == expected
