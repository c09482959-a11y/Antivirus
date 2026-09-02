"""Stage 1983 models API text-boundary no-hook regression coverage."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.api import (
    clustering_contracts,
    graph_contracts,
    profile_contracts,
    profile_learning_contracts,
    profile_retention_contracts,
    temporal_contracts,
)
from Virus_Scan.models.api.text_boundary import public_api_contract_text, public_api_sort_key


class HostilePublicObject:
    def __str__(self):  # pragma: no cover - failure if public text calls caller hook
        raise AssertionError("caller __str__ invoked")

    def __repr__(self):  # pragma: no cover - failure if public text calls caller hook
        raise AssertionError("caller __repr__ invoked")

    def __format__(self, _spec):  # pragma: no cover - failure if public text calls caller hook
        raise AssertionError("caller __format__ invoked")

    def __iter__(self):  # pragma: no cover - failure if public text calls caller hook
        raise AssertionError("caller __iter__ invoked")

    def __bool__(self):  # pragma: no cover - failure if public text probes truthiness
        raise AssertionError("caller __bool__ invoked")


CONTRACT_SOURCES = (
    Path("Virus_Scan/models/api/text_boundary.py"),
    Path("Virus_Scan/models/api/clustering_contracts.py"),
    Path("Virus_Scan/models/api/graph_contracts.py"),
    Path("Virus_Scan/models/api/profile_contracts.py"),
    Path("Virus_Scan/models/api/profile_learning_contracts.py"),
    Path("Virus_Scan/models/api/profile_retention_contracts.py"),
    Path("Virus_Scan/models/api/replay_comparison_contracts.py"),
    Path("Virus_Scan/models/api/temporal_contracts.py"),
)


def _plain_mapping(value):
    return dict(value)


def test_stage1983_public_api_text_boundary_uses_default_text_without_hooks() -> None:
    hostile = HostilePublicObject()

    assert public_api_contract_text(hostile, default_text="blocked") == (
        "blocked",
        "unreadable_public_contract_text",
    )
    sort_key = public_api_sort_key(hostile)
    assert sort_key[0] == "<unreadable_HostilePublicObject>"
    assert sort_key[1] == "unreadable_public_contract_text"


def test_stage1983_model_api_mapping_keys_are_labeled_without_fstrings_or_hooks() -> None:
    hostile = HostilePublicObject()
    source = {hostile: hostile}

    cluster = _plain_mapping(clustering_contracts._immutable_cluster_value(source))
    graph = _plain_mapping(graph_contracts._immutable_graph_value(source))
    profile = _plain_mapping(profile_contracts._immutable_profile_value(source))
    learning = _plain_mapping(profile_learning_contracts._immutable_profile_learning_value(source))
    retention = _plain_mapping(profile_retention_contracts._immutable_retention_value(source))
    temporal = temporal_contracts._materialize_temporal_value(source)

    assert set(cluster) == {"<unreadable_mapping_key_0>"}
    assert set(graph) == {"<unreadable_mapping_key_0>"}
    assert set(profile) == {"<unreadable_mapping_key_0>"}
    assert set(learning) == {"<unreadable_mapping_key_0>"}
    assert set(retention) == {"<unreadable_mapping_key_0>"}
    assert set(temporal) == {"<unreadable_mapping_key_0>"}


def test_stage1983_repaired_model_api_sources_do_not_restore_fallback_or_joined_strings() -> None:
    for source_path in CONTRACT_SOURCES:
        source = source_path.read_text(encoding="utf-8")
        assert "fallback" not in source
        tree = ast.parse(source)
        joined_strings = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
        assert joined_strings == []
