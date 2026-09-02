
"""Stage 1473: hostile scalar conversions must become explicit unavailable evidence."""

from __future__ import annotations
from dataclasses import replace
from Virus_Scan.tests.support.profile_learning import accepted_learning_request
from Virus_Scan.tests.support.static_inventory import read_python_file


import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from Virus_Scan.detection.scoring.yara.context_evidence import generic_yara_evidence_context
from Virus_Scan.models.graph.common import coerce_graph_event_time
from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles.vector_anomaly import vector_baseline_anomaly
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.context import contextual_profile_bucket_key
from Virus_Scan.models.profiles.evidence import profile_nonnegative_int
from Virus_Scan.models.profiles.schema import EngineProfileSchemaSnapshot, ProfileSchemaInvariantError
from Virus_Scan.models.profiles.promotion import prepare_benign_observation
from Virus_Scan.models.profiles.staged_store_schema import (
    default_staged_benign_store,
)
from Virus_Scan.detection.scoring.weighting.context_confidence import compute_context_confidence_amplifier
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state, runtime_cluster_state_to_json
from Virus_Scan.runtime.model_state import configure_runtime_model_state, runtime_model_snapshot, runtime_transition_key_to_json
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.runtime.provenance import make_failure_provenance


class _HostileNumeric:
    def __float__(self):  # pragma: no cover - boundary is the exception contract
        raise RuntimeError("hostile numeric conversion")

    def __int__(self):  # pragma: no cover - boundary is the exception contract
        raise RuntimeError("hostile integer conversion")


def _isolate_profile_state(tmp_path: Path) -> None:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles_dir))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.clear_all_profiles()
    state.set_staged_cache(default_staged_benign_store(), dirty=False)


def test_stage1473_graph_event_time_hostile_numeric_is_unavailable() -> None:
    value, reason = coerce_graph_event_time(_HostileNumeric())

    assert value is None
    assert reason == "non_numeric_event_time"


def test_stage1473_profile_support_hostile_numeric_is_unavailable() -> None:
    assert profile_nonnegative_int(_HostileNumeric()) is None

    baseline = default_profile_vector_statistics()
    baseline["count"] = 5
    baseline["trusted_count"] = 5
    baseline["clean_diversity_keys"] = ["fixture:a", "fixture:b", "fixture:c"]
    baseline["clean_diversity_count"] = 3
    baseline["maturity"] = "warming"
    baseline["suppression_authority"] = 0.35
    dimension = len(PROFILE_RAW_FEATURE_NAMES)
    baseline["mean"] = [_HostileNumeric()] + [0.0] * (dimension - 1)
    baseline["variance"] = [1.0] * dimension
    record = vector_baseline_anomaly(baseline, [0.2] * dimension)

    assert record["ready"] is False
    assert record["unavailable_reason"] == "non_finite_profile_vector_baseline"
    assert record["final_json_must_record"] is True


def test_stage1473_profile_schema_hostile_version_raises_typed_invariant() -> None:
    with pytest.raises(ProfileSchemaInvariantError):
        EngineProfileSchemaSnapshot.from_profile(
            {
                "engine": "renpy",
                "schema_version": _HostileNumeric(),
                "extension_baselines": {},
                "model_state": {},
            },
            expected_engine="renpy",
        )


def test_stage1473_runtime_model_snapshot_hostile_count_records_reason() -> None:
    transition_counts = defaultdict(Counter)
    transition_counts[("markov_context_support_v2", "global:trusted_benign")]["observations"] = _HostileNumeric()
    configure_runtime_model_state(
        transition_counts=transition_counts,
        global_tag_baseline={"download": _HostileNumeric()},
        global_tag_pair_baseline={("download", "exec"): _HostileNumeric()},
        filetype_baseline={".bin": Counter({"download": _HostileNumeric()})},
    )

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert snapshot["transition_counts"] == []
    assert snapshot["global_tag_baseline"] == {}
    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(item["reason"] == "non_numeric_runtime_model_count" for item in reasons)
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1473_cluster_runtime_snapshot_hostile_numeric_is_json_safe() -> None:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    state.cluster_signatures["cluster-a"] = [_HostileNumeric()]
    state.cluster_metadata["cluster-a"] = {
        "confidence": _HostileNumeric(),
        "malicious_ratio": _HostileNumeric(),
        "samples": _HostileNumeric(),
        "last_updated": _HostileNumeric(),
        "centroid_vector": [_HostileNumeric()],
    }

    snapshot = runtime_cluster_state_to_json()

    assert "cluster_signatures" not in snapshot
    assert isinstance(snapshot["microclusters"]["cluster-a"]["confidence"], str)
    assert snapshot["microclusters"]["cluster-a"]["centroid_vector"] == [0.0]
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1473_context_confidence_hostile_scores_are_unavailable() -> None:
    result = compute_context_confidence_amplifier(
        node="sample.exe",
        tags=("process_exec", "network_download"),
        
        layers={"graph": {"score": _HostileNumeric()}},
        adaptive_learning={"markov": {"markov_anomaly": _HostileNumeric()}},
        pre_context_score=_HostileNumeric(),
    )

    assert result["pre_context_score"] == 0.0
    assert result["graph_score"] == 0.0
    assert result["markov_signal"] == 0.0
    assert result["context_unavailable_reasons"] == {
        "graph": "invalid_context_layer_score",
        "markov": "invalid_context_model_signal",
    }


def test_stage1473_profile_maturity_prior_and_signal_hostile_counts_are_bounded(tmp_path: Path) -> None:
    _isolate_profile_state(tmp_path)
    path = tmp_path / "game" / "script.rpy"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("label start:\n    return\n", encoding="utf-8")
    contextual_key, _ctx = contextual_profile_bucket_key(path, trusted_benign=True)
    profile = profile_api.default_engine_profile("renpy")
    maturity_baseline = profile_api.default_extension_baseline(".rpy")
    maturity_baseline["files"] = _HostileNumeric()
    maturity_baseline["learning_gate"] = {"accepted": _HostileNumeric(), "rejected": _HostileNumeric()}
    prior_baseline = profile_api.default_extension_baseline(contextual_key)
    prior_baseline["files"] = 10
    prior_baseline["tags"] = {"benign_asset": _HostileNumeric()}
    profile["extension_baselines"][".rpy"] = maturity_baseline
    profile["extension_baselines"][contextual_key] = prior_baseline
    profile_persistence_state().cache_engine_profile("renpy", profile)

    report = profile_api.baseline_maturity_report("renpy", path)
    prior = profile_api.profile_prior_for_scoring("renpy", path, ["benign_asset"])

    assert report["maturity"] == "cold"
    assert report["trusted_support"] == 0
    assert report["suppression_authority"] == 0.0
    assert report["learning_gate"] == {"accepted": 0, "rejected": 0}
    assert prior == 0.0

    prior_baseline["files"] = _HostileNumeric()
    signal = profile_api.adaptive_profile_signal(path, ["benign_asset"])
    assert signal["profile_ready"] is False
    assert signal["unavailable_reason"] == "invalid_profile_history_support"


def test_stage1473_learning_rejection_hostile_counter_is_bounded(tmp_path: Path) -> None:
    _isolate_profile_state(tmp_path)
    path = tmp_path / "game" / "script.rpy"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("label start:\n    return\n", encoding="utf-8")
    learning_key, _ctx = contextual_profile_bucket_key(path, trusted_benign=False)
    profile = profile_api.default_engine_profile("renpy")
    baseline = profile_api.default_extension_baseline(learning_key)
    baseline["learning_gate"]["rejected"] = _HostileNumeric()
    profile["extension_baselines"][learning_key] = baseline
    profile_persistence_state().cache_engine_profile("renpy", profile)

    result = profile_api.record_learning_rejection("renpy", path, "unit_test_rejection")

    assert result["recorded"] is True
    gate = profile_persistence_state().get_engine_profile("renpy")["extension_baselines"][learning_key]["learning_gate"]
    assert gate["rejected"] == 1
    assert gate["last_rejection_reason"] == "unit_test_rejection"


def test_stage1473_staged_benign_rejections_and_risk_are_bounded(tmp_path: Path) -> None:
    _isolate_profile_state(tmp_path)
    state = profile_persistence_state()
    store = default_staged_benign_store()
    store["rejections"]["risk_too_high_for_staging"] = _HostileNumeric()
    state.set_staged_cache(store, dirty=False)
    path = tmp_path / "game" / "script.rpy"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("label start:\n    return\n", encoding="utf-8")

    rejected = prepare_benign_observation(accepted_learning_request(
        path, risk=999.0, observation_id="stage1473-high-risk",
    ))
    valid = accepted_learning_request(
        path, observation_id="stage1473-hostile-risk",
    )
    hostile = prepare_benign_observation(replace(valid, risk=_HostileNumeric()))

    assert (rejected.promoted, rejected.reason) == (False, "benign_candidate_store_invalid")
    assert type(store["rejections"]["risk_too_high_for_staging"]) is _HostileNumeric
    assert (hostile.promoted, hostile.reason) == (False, "benign_candidate_store_invalid")
    assert hostile.candidate is None


def test_stage1473_failure_provenance_hostile_context_ints_are_bounded() -> None:
    provenance = make_failure_provenance(
        domain="runtime",
        where="unit-test",
        error_type="RuntimeError",
        message="hostile numeric context",
        fingerprint="stage1473",
        correlation_id="stage1473",
        fatal=False,
        unsafe_to_continue=False,
        continuation_policy="degrade",
        context={"retry_generation": _HostileNumeric(), "scheduler_epoch": _HostileNumeric()},
    )

    assert provenance.retry_generation == 0
    assert provenance.scheduler_epoch == 0
    json.dumps(provenance.to_json(), allow_nan=False, sort_keys=True)


def test_stage1473_yara_context_rejects_hostile_non_scan_input() -> None:
    context = generic_yara_evidence_context(_HostileNumeric())
    assert context.scan_status == "unavailable"
    assert context.probability_authority is False
    assert context.probability_unavailable_reason == "yara_scan_result_invalid"


def test_stage1473_runtime_constants_delegate_parallel_workers_to_env_contract() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/constants.py"))

    assert "os.environ.get" not in source
    assert 'STAGE_PARALLEL_DEFAULT_WORKERS = int_env("UMIGE_STAGE_PARALLEL_WORKERS", 6, 1, None)' in source
