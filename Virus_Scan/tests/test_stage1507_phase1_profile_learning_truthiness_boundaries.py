"""Stage 1507 Phase 1 profile learning/evidence truthiness boundary tests."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.profiles.baseline import profile_behavior_bucket_validation
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest
from Virus_Scan.models.profiles.evidence import adaptive_profile_unavailable, merge_profile_subsignal_unavailable
from Virus_Scan.models.profiles.commit import commit_promoted_learning
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.runtime.config_state import configure_profiles_dir


class HostileBoolText:
    def __init__(self, text: str):
        self.text = text
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("profile code probed caller-owned truthiness")

    def __str__(self):
        return self.text


class HostileIterable:
    def __bool__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("profile iterable truthiness was probed")

    def __iter__(self):
        raise RuntimeError("iteration unavailable")


class HostileFailureIterable:
    touched = 0

    def __init__(self, items):
        self.items = tuple(items)

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("model_failures truthiness was probed")

    def __iter__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("model_failures iteration was probed")


def test_stage1507_profile_unavailable_reason_and_engine_do_not_probe_truthiness() -> None:
    engine = HostileBoolText("renpy")
    reason = HostileBoolText("profile_unavailable")

    record = adaptive_profile_unavailable(engine, reason, files_seen=0)

    assert record["engine"] == "renpy"
    assert record["unavailable_reason"] == "profile_unavailable"
    assert engine.bool_calls == 0
    assert reason.bool_calls == 0


def test_stage1507_profile_subsignal_failure_iteration_does_not_probe_truthiness() -> None:
    failures = ({"model_name": "profiles", "reason": "nested"},)
    signal = {
        "degraded": True,
        "unavailable_reason": HostileBoolText("nested_unavailable"),
        "model_failures": failures,
    }
    unavailable_reasons: dict[str, str] = {}
    model_failures: list[dict[str, object]] = []

    merge_profile_subsignal_unavailable("vector_validation", signal, unavailable_reasons, model_failures)

    assert unavailable_reasons["vector_validation"] == "nested_unavailable"
    assert model_failures == [{"model_name": "profiles", "reason": "nested"}]


def test_stage1507_profile_subsignal_rejects_hostile_failure_iterable_without_hooks() -> None:
    HostileFailureIterable.touched = 0
    signal = {
        "degraded": True,
        "unavailable_reason": HostileBoolText("nested_unavailable"),
        "model_failures": HostileFailureIterable(({"model_name": "profiles", "reason": "nested"},)),
    }
    unavailable_reasons: dict[str, str] = {}
    model_failures: list[dict[str, object]] = []

    merge_profile_subsignal_unavailable("vector_validation", signal, unavailable_reasons, model_failures)

    assert unavailable_reasons["vector_validation"] == "nested_unavailable"
    assert model_failures == []
    assert HostileFailureIterable.touched == 0


def test_stage1507_profile_chain_and_bucket_boundaries_reject_hostile_iterables_without_truthiness() -> None:
    hostile = HostileIterable()

    chain_evidence = evaluate_chain_evidence(tags=hostile)
    assert chain_evidence.decisions == ()
    assert chain_evidence.failures
    validation = profile_behavior_bucket_validation(ProfileBucketValidationRequest("renpy", "sample.rpy", hostile))

    assert validation["degraded"] is True
    assert validation["unavailable_reason"] == "malformed_profile_bucket_tags"
    assert validation["final_json_must_record"] is True
    assert validation["replay_record_required"] is True


def test_stage1507_commit_rejects_hostile_tags_without_mutation(tmp_path: Path) -> None:
    configure_profiles_dir(str(tmp_path / "profiles"))
    hostile = HostileIterable()

    result = commit_promoted_learning(
        "renpy", tmp_path / "game" / "script.rpy", hostile,
        yara_hits=hostile, ordered_events=hostile, verdict="clean",
    )

    assert result["learned"] is False
    assert result["degraded"] is True
    assert result["unavailable_reason"] == "malformed_profile_learning_tags"
    assert result["final_json_must_record"] is True



def test_stage1507_profile_public_api_has_no_parallel_chain_classifier() -> None:
    from Virus_Scan.models.profiles import api as profile_api

    assert "classify_chain_match" not in profile_api.__all__
    assert not hasattr(profile_api, "classify_chain_match")
