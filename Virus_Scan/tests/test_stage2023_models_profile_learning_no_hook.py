from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path
from Virus_Scan.models.profiles import learning as profile_learning



class HostileDict(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __iter__(self):  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()

    def items(self):  # pragma: no cover - must not execute
        return self._touch()

    def values(self):  # pragma: no cover - must not execute
        return self._touch()


def test_stage2023_profile_learning_has_no_parallel_chain_registry_or_classifier() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/learning.py"))
    assert "ATTACK_GRAPH" not in source
    assert "def detect_profile_chains" not in source
    assert "evaluate_chain_evidence(" in source


def test_stage2023_profile_behavior_vector_has_no_downstream_model_dependencies() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/learning.py"))
    for forbidden in (
        "profile_behavior_bucket_validation",
        "compute_markov_features",
        "snapshot_temporal",
        "models.api.clustering_contracts",
        "graph_risk",
        "cluster_size",
        "risk_scaled",
    ):
        assert forbidden not in source

    vector = profile_learning.behavior_vector_from_scan(
        "renpy",
        "game/script.rpy",
        physical_tag_evidence(("api_download", "network_connect")),
        ordered_events=("api_download",),
    )
    assert isinstance(vector, list)
    assert len(vector) == len(profile_learning.VECTOR_FEATURE_NAMES) == 16
    assert all(0.0 <= value <= 1.0 for value in vector)


def test_stage2023_profile_learning_source_has_no_backlog_unsafe_reads() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/learning.py"))

    forbidden = (
        "from collections.abc import Mapping",
        "safe_clamp",
        "dict(get_init_value",
        "attack_graph.items()",
        ".get('records'",
        ".get(name, 0.0)",
    )
    for snippet in forbidden:
        assert snippet not in source
