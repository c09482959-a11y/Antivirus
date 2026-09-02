from __future__ import annotations
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.tests.support.static_inventory import read_python_file
from dataclasses import replace
from Virus_Scan.tests.support.profile_learning import accepted_learning_request


from pathlib import Path
from unittest.mock import patch
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence

from Virus_Scan.models.graph.attention import safe_attention_lookup
from Virus_Scan.models.graph.cluster_projection import _owned_mapping_get
from Virus_Scan.models.graph.common import graph_owned_key_matches
from Virus_Scan.models.profiles import adaptive_signal, coordinated_validation
from Virus_Scan.models.profiles import promotion
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.models.temporal import overlay as temporal_overlay


class HostileKey:
    touched = 0

    def __eq__(self, other):  # pragma: no cover - failure proves caller-owned equality ran
        type(self).touched += 1
        raise AssertionError("caller-owned key equality hook executed")

    def __hash__(self) -> int:
        return 24

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key text hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key repr hook executed")


class HostileConfigError(OSError):
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves exception text hook executed
        type(self).touched += 1
        raise AssertionError("caller-owned exception text hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned exception repr hook executed")


def test_stage1997_graph_attention_lookup_ignores_hostile_dict_keys_without_equality_hooks() -> None:
    HostileKey.touched = 0

    attention = {HostileKey(): 0.99, "edge:target": 0.25}

    assert safe_attention_lookup(attention, "edge:target") == 0.25
    assert safe_attention_lookup(attention, "missing") == 0.0
    assert HostileKey.touched == 0


def test_stage1997_graph_cluster_lookup_ignores_hostile_dict_keys_without_equality_hooks() -> None:
    HostileKey.touched = 0

    value = _owned_mapping_get({HostileKey(): "unsafe", "members": ("node-a",)}, "members", ())

    assert value == ("node-a",)
    assert HostileKey.touched == 0


def test_stage1997_graph_owned_key_match_accepts_only_exact_primitive_keys() -> None:
    HostileKey.touched = 0

    assert graph_owned_key_matches("alpha", "alpha") is True
    assert graph_owned_key_matches(3, 3) is True
    assert graph_owned_key_matches(HostileKey(), "alpha") is False
    assert HostileKey.touched == 0


def test_stage1997_graph_lookup_sources_do_not_use_generic_key_equality() -> None:
    for source_path in (
        Path("Virus_Scan/models/graph/attention.py"),
        Path("Virus_Scan/models/graph/cluster_projection.py"),
    ):
        source = source_path.read_text(encoding="utf-8")
        assert "if key == name" not in source
        assert "graph_owned_key_matches(key, name)" in source


def test_stage1997_profile_prior_baseline_failure_does_not_format_exception_text() -> None:
    HostileConfigError.touched = 0

    def raise_hostile(*_args, **_kwargs):
        raise HostileConfigError()

    with patch.object(adaptive_signal, "get_extension_baseline", raise_hostile):
        assert adaptive_signal.profile_prior_for_scoring("renpy", "game.rpy", ("renpy_script",)) == 0.0

    assert HostileConfigError.touched == 0


def test_stage1997_profile_adaptive_signal_source_does_not_log_format_caught_errors() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/adaptive_signal.py"))

    assert "log_error(f" not in source
    assert "type(e).__name__" not in source
    assert "no_hook_type_name(e)" in source


def test_stage1997_temporal_overlay_failure_uses_no_hook_exception_type() -> None:
    HostileConfigError.touched = 0

    def raise_hostile(*_args, **_kwargs):
        raise HostileConfigError()

    with patch.object(temporal_overlay, "temporal_markov_overlay_support", raise_hostile):
        result = temporal_overlay.transition_probability_overlay(
            prev_stage="load",
            tags=("decode", "exec"),
            curr_stage="exec",
            ordered_events=(
                {"tag": "decode", "timestamp": 0.0, "stage": "load"},
                {"tag": "exec", "timestamp": 1.0, "stage": "exec"},
            ),
        )

    assert result["degraded"] is True
    assert result["unavailable_reason"] == "temporal_probability_overlay_error"
    assert HostileConfigError.touched == 0


def test_stage1997_profile_coordinated_validation_failure_uses_no_hook_exception_type() -> None:
    HostileConfigError.touched = 0

    def raise_hostile(*_args, **_kwargs):
        raise HostileConfigError()

    with (
        patch.object(coordinated_validation, "get_extension_baseline", return_value=default_extension_baseline(".rpy")),
        patch.object(coordinated_validation, "behavior_vector_from_scan", raise_hostile),
        patch.object(coordinated_validation, "snapshot_temporal", return_value={"ready": True, "belief": 0.0}),
        patch.object(
            coordinated_validation,
            "compute_markov_features",
            return_value={"ready": True, "transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0},
        ),
        patch.object(coordinated_validation, "extension_timeline_anomaly", return_value={"anomaly": 0.0}),
    ):
        result = coordinated_validation.coordinated_model_validation_signal(
            "renpy",
            "game.rpy",
            ("renpy_script",),
        )

    failure_details = result["model_failures"][0]["details"]
    assert failure_details["error_type"] == "HostileConfigError"
    assert HostileConfigError.touched == 0


def test_stage1997_runtime_transaction_projection_requires_profile_authority() -> None:
    counters = {"runtime": 0}
    projection = project_runtime_transaction_stats({}, counters)

    assert projection["runtime_committed"] is False
    assert projection["reason"] == "profile_promotion_required"
    assert projection["model_updates_authorized"] is False
    assert counters["runtime"] == 0


def test_stage1997_profile_promotion_hash_rejects_hostile_path_without_text_hooks() -> None:
    HostileKey.touched = 0

    digest = promotion._scan_hash_for_staging(HostileKey())

    assert len(digest) == 64
    assert HostileKey.touched == 0


def test_stage1997_profile_promotion_staging_does_not_stringify_hostile_path() -> None:
    HostileKey.touched = 0
    store = default_staged_benign_store()
    valid = accepted_learning_request(
        Path("sample.rpy"), observation_id="stage1997-hostile-path",
    )

    profile_persistence_state().set_staged_cache(store, dirty=False)
    transition = promotion.prepare_benign_observation(
        replace(valid, file_path=HostileKey())
    )

    assert transition.promoted is False
    assert transition.reason == "learning_commit_request_invalid"
    assert transition.candidate is None
    assert HostileKey.touched == 0


def test_stage1997_model_failure_logging_sources_do_not_format_caught_exceptions() -> None:
    for source_path in (
        Path("Virus_Scan/models/temporal/overlay.py"),
        Path("Virus_Scan/models/replay/learning.py"),
        Path("Virus_Scan/models/profiles/commit.py"),
        Path("Virus_Scan/models/profiles/coordinated_validation.py"),
        Path("Virus_Scan/models/markov/features.py"),
        Path("Virus_Scan/models/markov/learning.py"),
        Path("Virus_Scan/models/profiles/persistence.py"),
        Path("Virus_Scan/models/profiles/replay_learning.py"),
        Path("Virus_Scan/models/profiles/learning_gate.py"),
        Path("Virus_Scan/models/profiles/promotion.py"),
    ):
        source = source_path.read_text(encoding="utf-8")
        assert "log_error(f" not in source
        assert "str(exc)" not in source
        assert "str(e)" not in source
        assert "type(e).__name__" not in source
        assert "str(file_path" not in source
        assert "str(verdict" not in source
