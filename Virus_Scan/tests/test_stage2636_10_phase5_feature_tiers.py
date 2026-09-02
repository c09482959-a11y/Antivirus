from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import pytest

from Virus_Scan.models.clustering.common import VECTOR_FEATURE_NAMES as CLUSTER_FEATURE_NAMES
from Virus_Scan.models.clustering.learning_features import build_learning_feature_vector
from Virus_Scan.models.profiles.feature_registry import (
    PROFILE_RAW_FEATURE_NAMES,
    PROFILE_RAW_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.learning import behavior_vector_from_scan
from Virus_Scan.models.profiles.schema import (
    ProfileSchemaInvariantError,
    validate_engine_profile_schema,
)
from Virus_Scan.models.profiles.snapshots import default_engine_profile, default_extension_baseline
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.profiles.vector_statistics import (
    PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION,
    update_profile_vector_statistics,
)


FORBIDDEN_PROFILE_FEATURES = frozenset({
    "graph_risk", "graph_anomaly", "temporal_belief", "markov_transition",
    "markov_rarity", "markov_pair_anomaly", "cluster_size", "cluster_risk",
    "cluster_anomaly", "risk_scaled", "engine_filetype_risk",
    "rare_high_risk_count", "weak_evidence_count", "strong_evidence_count",
    "yara_count", "yara_weight",
})


def test_phase5_profile_registry_is_raw_only_and_independent() -> None:
    assert len(PROFILE_RAW_FEATURE_NAMES) == 16
    assert not (set(PROFILE_RAW_FEATURE_NAMES) & FORBIDDEN_PROFILE_FEATURES)
    assert PROFILE_RAW_FEATURE_NAMES != CLUSTER_FEATURE_NAMES


def test_phase5_profile_learning_has_no_downstream_model_imports() -> None:
    path = Path("Virus_Scan/models/profiles/learning.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = {
        node.module for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    forbidden = {
        "Virus_Scan.models.api.markov_contracts",
        "Virus_Scan.models.api.temporal_contracts",
        "Virus_Scan.models.api.clustering_contracts",
        "Virus_Scan.models.graph",
    }
    assert not (imports & forbidden)


def test_phase5_profile_vector_is_raw_and_profile_statistics_are_profile_owned() -> None:
    vector = behavior_vector_from_scan(
        "renpy", "sample.rpy", physical_tag_evidence(("network_download", "process_exec")),
        ordered_events=("read_file", "process_exec"),
    )
    baseline = default_extension_baseline(".rpy")["vector_baseline"]
    updated = update_profile_vector_statistics(
        baseline, vector, diversity_key="phase5:raw-vector",
    )
    assert len(vector) == 16
    assert updated["schema_version"] == PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION
    assert updated["feature_schema_version"] == PROFILE_RAW_FEATURE_SCHEMA_VERSION
    assert tuple(updated["feature_names"]) == PROFILE_RAW_FEATURE_NAMES
    assert updated["count"] == 1


def test_phase5_clustering_learning_projection_excludes_current_model_state() -> None:
    vector = build_learning_feature_vector(
        ("network_download", "process_exec"), {"renpy": 1.0},
    )
    assert len(vector) == len(CLUSTER_FEATURE_NAMES) == 17
    assert "yara_count" not in CLUSTER_FEATURE_NAMES
    assert "yara_weight" not in CLUSTER_FEATURE_NAMES
    for name in (
        "graph_risk", "graph_anomaly", "temporal_belief", "markov_transition",
        "markov_rarity", "markov_pair_anomaly", "cluster_size", "cluster_risk",
        "cluster_anomaly",
    ):
        assert vector[CLUSTER_FEATURE_NAMES.index(name)] == 0.0
    assert vector[CLUSTER_FEATURE_NAMES.index("renpy_context")] == 1.0


def test_phase5_incompatible_profile_vector_is_rejected_without_repair() -> None:
    profile = default_engine_profile("renpy")
    profile["extension_baselines"][".rpy"] = {
        **default_extension_baseline(".rpy"),
        "vector_baseline": {
            "count": 8, "mean": [0.1] * 19, "m2": [0.0] * 19,
            "variance": [0.0] * 19, "feature_names": list(CLUSTER_FEATURE_NAMES),
        },
    }
    before = deepcopy(profile)
    with pytest.raises(
        ProfileSchemaInvariantError,
        match="profile_vector_statistics_schema_invalid",
    ):
        validate_engine_profile_schema(profile, expected_engine="renpy")
    assert profile == before
    assert not Path("Virus_Scan/models/profiles/feature_migration.py").exists()
