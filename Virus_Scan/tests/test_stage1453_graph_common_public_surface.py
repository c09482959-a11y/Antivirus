from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.models.graph import common

_IMPORTED_OR_FOREIGN_OWNER_NAMES = (
    "annotations",
    "Mapping",
    "MappingProxyType",
    "RECOVERABLE_RUNTIME_ERRORS",
    "GLOBAL_HALF_LIFE",
    "defaultdict",
    "Path",
    "hashlib",
    "math",
    "os",
    "re",
    "zipfile",
    "log_error",
    "record_detector_error",
    "detect_unity_runtime_behavior",
    "normalize_tags",
    "safe_clamp",
    "runtime_model_mapping_snapshot",
    "runtime_cache_by_name",
    "canonical_behavior_flow",
    "markov_known_chain_score",
    "markov_transition_score",
    "record_temporal_observation",
)


def test_stage1453_graph_common_all_does_not_publish_imported_foreign_authority():
    leaked = sorted(set(common.__all__) & set(_IMPORTED_OR_FOREIGN_OWNER_NAMES))
    assert leaked == []


def test_stage1453_graph_common_all_is_limited_to_public_graph_contracts():
    assert tuple(common.__all__) == (
        "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
        "ATTACK_GRAPH",
        "CAUSAL_ENTITY_MODEL_VERSION",
        "GLOBAL_TAG_BASELINE",
        "MIN_CLUSTER_SIZE",
        "TAG_TO_BEHAVIOR",
        "coerce_graph_event_time",
        "graph_event_time_failure_reason",
        "normalize_graph_tags_with_reason",
        "record_graph_input_degraded",
        "safe_graph_metadata_value",
        "safe_graph_sequence",
        "safe_graph_text",
        "safe_graph_text_with_reason",
    )


def test_stage1453_graph_common_does_not_publish_private_helpers_through_all():
    assert not any(name.startswith("_") for name in common.__all__)
    source = read_python_file(Path("Virus_Scan/models/graph/common.py"))
    tree = ast.parse(source)
    assignments = [node for node in tree.body if isinstance(node, ast.Assign) for target in node.targets if isinstance(target, ast.Name) and target.id == "__all__"]
    assert len(assignments) == 1
