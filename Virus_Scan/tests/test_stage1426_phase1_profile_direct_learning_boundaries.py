"""Stage 1426: direct profile model public helpers expose degraded evidence."""

from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models import profiles


class HostileProfileInput:
    def __bool__(self):  # pragma: no cover - exercised by absence of crash
        raise RuntimeError("truthiness should not be probed")

    def __iter__(self):  # pragma: no cover - exercised by absence of crash
        raise RuntimeError("iteration should be bounded")

    def __str__(self):  # pragma: no cover - exercised by absence of crash
        raise RuntimeError("string conversion should be bounded")


def test_stage1426_direct_profile_engine_inference_records_degraded_evidence() -> None:
    hostile = HostileProfileInput()

    engine, context = profiles.infer_profile_engine(
        hostile,
        file_structure=hostile,
        strings_blob=hostile,
    )

    assert engine == "other"
    assert context["other"] == 1.0
    assert context["degraded"] is True
    assert context["unavailable_reason"] == "malformed_profile_engine_tags"
    assert context["final_json_must_record"] is True
    assert context["replay_record_required"] is True


def test_stage1426_direct_profile_flow_helpers_do_not_truthiness_probe_inputs() -> None:
    hostile = HostileProfileInput()

    assert profiles.timeline_transitions(hostile) == ([], [], [], [])
    assert profiles.real_ordered_event_names(hostile) == []
    assert profiles.canonical_profile_learning_flow(
        tags=hostile,
        ordered_events=hostile,
        behavior_flow=hostile,
    ) == []
    assert profiles.canonical_behavior_flow_from_sources(
        raw_tags=hostile,
        ordered_events=hostile,
        behavior_timeline=hostile,
        behavior_flow=hostile,
    ) == []
    assert profiles.learning_verdict_is_clean(hostile) is False


def test_stage1426_direct_profile_learning_and_vector_return_failure_evidence() -> None:
    hostile = HostileProfileInput()

    vector = profiles.behavior_vector_from_scan(
        "renpy",
        "sample.rpy",
        hostile,
        api_calls=hostile,
        ordered_events=hostile,
    )
    assert isinstance(vector, Mapping)
    assert vector["ready"] is False
    assert vector["degraded"] is True
    assert vector["evidence_type"] == "profile_behavior_vector"
    assert vector["unavailable_reason"] == "malformed_profile_behavior_tags"
    assert vector["final_json_must_record"] is True
    assert vector["replay_record_required"] is True

    commit = profiles.commit_promoted_learning(
        "renpy",
        "sample.rpy",
        hostile,
        api_calls=hostile,
        ordered_events=hostile,
        behavior_flow=hostile,
        verdict="clean",
    )
    assert commit["learned"] is False
    assert commit["promoted"] is False
    assert commit["degraded"] is True
    assert commit["evidence_type"] == "profile_learning_commit"
    assert commit["unavailable_reason"] == "malformed_profile_learning_tags"
    assert commit["final_json_must_record"] is True
    assert commit["replay_record_required"] is True

    update = profiles.update_profile_from_scan_result(
        "sample.rpy",
        hostile,
        api_calls=hostile,
        ordered_events=hostile,
        verdict="clean",
    )
    assert update["engine_context"]["degraded"] is True
    assert update["baseline"] is None
    assert update["learning"]["degraded"] is True
    assert update["learning"]["unavailable_reason"] == "malformed_profile_learning_tags"
