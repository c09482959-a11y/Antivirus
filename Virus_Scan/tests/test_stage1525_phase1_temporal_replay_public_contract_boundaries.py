"""Stage 1525 Phase 1 temporal/replay public-contract boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from Virus_Scan.models.api import replay_comparison_contracts, temporal_contracts


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        obj.str_calls = 0
        obj.strip_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was probed")


def test_stage1525_temporal_overlay_detaches_public_text_and_freezes_output():
    prev_stage = HostileText("asset")
    curr_stage = HostileText("runtime")
    first_tag = HostileText("decode")
    second_tag = HostileText("exec")

    evidence = temporal_contracts.transition_probability_overlay(
        prev_stage=prev_stage,
        curr_stage=curr_stage,
        tags=(first_tag, second_tag),
        ordered_events=(
            {"tag": first_tag, "timestamp": 1.0, "stage": prev_stage},
            {"tag": second_tag, "timestamp": 2.0, "stage": curr_stage},
        ),
    )

    assert isinstance(evidence, dict)
    assert evidence["evidence_type"] == "sequence_probability"
    assert evidence["prev_stage"] == "asset"
    assert evidence["curr_stage"] == "runtime"
    assert tuple(evidence["flow"]) == ("decode", "exec")
    assert type(evidence["prev_stage"]) is str
    assert type(evidence["curr_stage"]) is str
    assert all(type(item) is str for item in evidence["flow"])
    evidence["mutated"] = True
    assert evidence["mutated"] is True
    assert prev_stage.str_calls == 0
    assert curr_stage.str_calls == 0
    assert first_tag.str_calls == 0
    assert second_tag.str_calls == 0
    assert prev_stage.strip_calls == 0
    assert curr_stage.strip_calls == 0
    assert first_tag.strip_calls == 0
    assert second_tag.strip_calls == 0
    assert prev_stage.bool_calls == 0
    assert curr_stage.bool_calls == 0
    assert first_tag.bool_calls == 0
    assert second_tag.bool_calls == 0


def test_stage1525_temporal_validation_snapshot_and_update_freeze_public_evidence():
    node = HostileText("node-a")
    stage = HostileText("execution")
    tag = HostileText("network")

    validation = temporal_contracts.compute_temporal_validation(
        node,
        prev_stage=HostileText("asset"),
        curr_stage=stage,
        tags=(tag,),
    )
    snapshot = temporal_contracts.snapshot_temporal(node)
    update = temporal_contracts.update_temporal(node, stage, (tag,), learning_decision=accepted_learning_decision(target_names=("temporal",)))

    assert isinstance(validation, dict)
    assert isinstance(snapshot, dict)
    assert isinstance(update, dict)
    assert validation["evidence_type"] == "temporal_validation"
    assert snapshot["evidence_type"] == "temporal_snapshot"
    assert update["stage"] == "execution"
    assert type(update["node"]) is str
    assert type(update["stage"]) is str
    assert all(type(item) is str for item in update["flow"])
    update["stage"] = "mutated"
    assert update["stage"] == "mutated"
    assert node.str_calls == 0
    assert node.strip_calls == 0
    assert node.bool_calls == 0
    assert stage.str_calls == 0
    assert stage.strip_calls == 0
    assert stage.bool_calls == 0
    assert tag.str_calls == 0
    assert tag.strip_calls == 0
    assert tag.bool_calls == 0


def test_stage1525_replay_comparison_mismatch_keys_do_not_call_raw_str():
    expected_key = HostileText("expected_field")
    actual_key = HostileText("actual_field")
    model_name = HostileText("temporal")

    record = replay_comparison_contracts.compare_model_evidence(
        model_name=model_name,
        expected={expected_key: 1},
        actual={actual_key: 2},
    )
    materialized = replay_comparison_contracts.materialize_model_evidence_comparison(record)

    assert tuple(materialized["mismatch_fields"]) == ("actual_field", "expected_field")
    assert materialized["model_name"] == "temporal"
    assert expected_key.str_calls == 0
    assert actual_key.str_calls == 0
    assert model_name.str_calls == 0
    assert expected_key.strip_calls == 0
    assert actual_key.strip_calls == 0
    assert model_name.strip_calls == 0
    assert expected_key.bool_calls == 0
    assert actual_key.bool_calls == 0
    assert model_name.bool_calls == 0
