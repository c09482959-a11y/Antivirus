"""Initialize core cache, graph, model, and profile runtime state."""

from collections import defaultdict
from threading import RLock

from Virus_Scan.runtime.graph_state import reset_graph_state
from Virus_Scan.runtime.init_state import publish_init_values




def init_finalize() -> object:
    """Mark full top-level runtime initialization complete through init state."""
    return publish_init_values((("_TOP_LEVEL_INITIALIZED", True),))


def init_caches() -> object:
    reset_graph_state()
    cache_state = {
        "MAX_COUNTER_KEYS": 5000,
        "MAX_TAG_COUNTER_KEYS": 2500,
        "MAX_PAIR_COUNTER_KEYS": 20000,
        "MAX_TRANSITION_KEYS": 10000,
        "MAX_TRANSITION_NEXT_KEYS": 256,
        "MAX_FILETYPE_BASELINES": 256,
        "MAX_TEMPORAL_NODES": 5000,
        "MAX_TEMPORAL_HISTORY_PER_NODE": 25,
        "MAX_STAGED_BENIGN_CANDIDATES": 10000,
        "MAX_EXTENSION_BASELINES_PER_ENGINE": 512,
        "MAX_PROFILE_TAGS_PER_EXTENSION": 2500,
        "MAX_PROFILE_BUCKET_TAGS": 1200,
        "MAX_PROFILE_TIMELINE_EVENTS": 2500,
        "MAX_PROFILE_TIMELINE_TRANSITIONS": 5000,
        "MAX_PROFILE_CHAINS": 2500,
        "MAX_CLUSTER_COUNT": 2000,
        "MAX_CLUSTER_MEMBERS": 250,
        "MAX_NODE_CLUSTER_MAP": 50000,
        "MAX_NODE_FEATURE_VECTORS": 50000,
        "MAX_VECTOR_DIMENSIONS": 128,
        "MAX_PERSISTED_CLUSTER_CENTROIDS": 2000,
        "MAX_PERSISTED_CLUSTER_METADATA": 2000,
        "MAX_CACHE_ITEMS_PER_MAP": 20000,
        "CACHE_PRUNE_EVERY_UPDATES": 250,
        "CACHE_PRUNE_UPDATE_COUNT": 0,
        "DETECTOR_ERRORS": [],
        "STRICT_DETECTOR_ERRORS": False,
        "GRAPH_RISK_CACHE": {},
        "MARKOV_CACHE": {},
        "TEMPORAL_CACHE": {},
        "RISK_CACHE": {},
        "CACHE_LOCK": RLock(),
        "CACHE_TTL": 300,
        "GRAPH_LOCK": RLock(),
        "GLOBAL_STATE_LOCK": RLock(),
        "PROFILE_EXT_LOCKS": defaultdict(RLock),
        "RUNTIME_MODEL_LOCK": RLock(),
        "TEMPORAL_STATE_LOCK": RLock(),
        "CLUSTER_STATE_LOCK": RLock(),
        "GLOBAL_HALF_LIFE": 1800,
        "MIN_CLUSTER_SIZE": 2,
        "CACHE_STORE": {},
        "ENGINE_CACHE": {},
        "CONTEXTUAL_BASELINE_VERSION": "learned_engine_ext_tag_frequency_reducer_v2_poison_guarded",
    }
    return publish_init_values(tuple(dict.items(cache_state)))


__all__ = ("init_caches", "init_finalize")
