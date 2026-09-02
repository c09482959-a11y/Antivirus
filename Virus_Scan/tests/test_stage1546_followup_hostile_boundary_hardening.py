import json

import pytest

from Virus_Scan.reporting import evidence_line_rules
from Virus_Scan.models.clustering.common import finite_cluster_metric, safe_cluster_text
from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)
from Virus_Scan.models.contracts.model_snapshot import make_model_snapshot, materialize_model_snapshot
from Virus_Scan.models.contracts.probability_record import make_probability_record, materialize_probability_record
from Virus_Scan.models.graph.common import coerce_graph_event_time, graph_finite_float, safe_graph_text_with_reason
from Virus_Scan.models.behavior_sequence_contract import _model_sequence_detached_text
from Virus_Scan.models.markov.text_boundary import markov_detached_text
from Virus_Scan.models.profiles.common import profile_finite_float, profile_int, profile_safe_text
from Virus_Scan.models.replay.detachment import detach_replay_payload_value, finite_replay_score
from Virus_Scan.models.replay_economics import replay_compress_metadata, replay_should_retain
from Virus_Scan.models.temporal.text_boundary import TEMPORAL_TEXT_UNAVAILABLE, temporal_boundary_text
from Virus_Scan.publication.json_finalization.base_projection import bounded_signal_value, canonical_tag_list
from Virus_Scan.publication.json_finalization.projection_text import safe_projection_text
from Virus_Scan.runtime import model_state
from Virus_Scan.routing import magic_extension_tags
from Virus_Scan.routing.magic_extension_tags import is_rpgm_passive_recovered


class HostileScalar:
    __hash__ = object.__hash__

    def __init__(self):
        self.str_calls = 0
        self.repr_calls = 0
        self.bool_calls = 0
        self.float_calls = 0
        self.int_calls = 0
        self.eq_calls = 0

    def __str__(self):
        self.str_calls += 1
        raise RuntimeError("string hook must not run")

    def __repr__(self):
        self.repr_calls += 1
        raise RuntimeError("repr hook must not run")

    def __bool__(self):
        self.bool_calls += 1
        raise RuntimeError("truth hook must not run")

    def __float__(self):
        self.float_calls += 1
        raise RuntimeError("float hook must not run")

    def __int__(self):
        self.int_calls += 1
        raise RuntimeError("int hook must not run")

    def __eq__(self, other):
        self.eq_calls += 1
        raise RuntimeError("equality hook must not run")

    def assert_untouched(self):
        assert self.str_calls == 0
        assert self.repr_calls == 0
        assert self.bool_calls == 0
        assert self.float_calls == 0
        assert self.int_calls == 0
        assert self.eq_calls == 0


def test_stage1546_followup_replay_boundaries_do_not_invoke_hostile_hooks():
    hostile = HostileScalar()

    compressed = replay_compress_metadata({"direct": hostile, "nested": {"payload": hostile}})
    detached = detach_replay_payload_value({"direct": hostile, hostile: "keyed"})
    score, unavailable, reason = finite_replay_score(hostile)
    retain = replay_should_retain({"replay_divergence": hostile, "score": hostile})

    assert compressed["direct"]["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert compressed["direct"]["value"] == "<HostileScalar>"
    assert compressed["nested"]["payload"]["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert detached["direct"]["unavailable_reason"] == "unsupported_replay_payload_value"
    assert detached["direct"]["value_type"] == "HostileScalar"
    assert any(key.startswith("<HostileScalar>#") for key in detached)
    assert (score, unavailable, reason) == (0.0, True, "non_numeric_replay_score")
    assert retain is True
    json.dumps({"compressed": compressed, "detached": detached}, sort_keys=True)
    hostile.assert_untouched()


def test_stage1546_followup_model_text_and_numeric_helpers_do_not_invoke_hostile_hooks():
    hostile = HostileScalar()

    assert safe_cluster_text(hostile, default_text="cluster_unavailable") == "cluster_unavailable"
    assert finite_cluster_metric(hostile, 7.0) == 7.0
    assert profile_safe_text(hostile, replacement="profile_unavailable") == "profile_unavailable"
    assert profile_finite_float(hostile, 3.0) == 3.0
    assert profile_int(hostile, 9) == 9
    graph_text, graph_reason = safe_graph_text_with_reason(hostile, "hostile_graph_text")
    assert graph_text == "unsupported_graph_text_type:HostileScalar"
    assert graph_reason == "hostile_graph_text"
    assert graph_finite_float(hostile, default=2.0, reason="hostile_graph_metric") == (
        2.0,
        "hostile_graph_metric",
    )
    assert coerce_graph_event_time(hostile) == (None, "non_numeric_event_time")
    hostile.assert_untouched()


def test_stage1546_followup_contracts_do_not_invoke_hostile_scalar_hooks():
    hostile = HostileScalar()

    evidence = materialize_model_evidence_record(
        make_model_evidence_record(
            {hostile: hostile, "nested": {"payload": hostile}},
            model_name=hostile,
            evidence_type=hostile,
            model_version=hostile,
        )
    )
    feature_bundle = materialize_model_feature_bundle(
        make_model_feature_bundle({hostile: hostile}, model_version=hostile)
    )
    failure = materialize_model_failure_record(
        make_model_failure_record(
            model_name=hostile,
            failure_type=hostile,
            reason=hostile,
            degraded=hostile,
            output_affecting=hostile,
            affected_fields=[hostile],
            details={hostile: hostile},
            model_version=hostile,
        )
    )
    snapshot = materialize_model_snapshot(
        make_model_snapshot(
            {hostile: hostile},
            model_name=hostile,
            snapshot_type=hostile,
            model_version=hostile,
            ready=hostile,
            degraded=hostile,
            reason=hostile,
        )
    )
    probability = materialize_probability_record(
        make_probability_record(
            ready=hostile,
            probability=hostile,
            support=hostile,
            count=hostile,
            vocab=hostile,
            smoothing=hostile,
            reason=hostile,
            source=hostile,
            target=hostile,
            flow=[hostile],
            model_version=hostile,
        )
    )

    assert evidence["model_name_unavailable_reason"] == "unreadable_model_name"
    assert evidence["<HostileScalar>"]["unavailable_reason"] == "unsupported_model_evidence_value"
    assert evidence["nested"]["payload"]["unavailable_reason"] == "unsupported_model_evidence_value"
    assert feature_bundle["model_version_unavailable_reason"] == "unreadable_model_version"
    assert feature_bundle["<HostileScalar>"]["unavailable_reason"] == "unsupported_model_feature_value"
    assert failure["degraded"] is True
    assert failure["output_affecting"] is True
    assert failure["degraded_unavailable_reason"] == "non_boolean_degraded"
    assert failure["output_affecting_unavailable_reason"] == "non_boolean_output_affecting"
    assert failure["details"]["<HostileScalar>"]["unavailable_reason"] == "unsupported_model_failure_detail_value"
    assert snapshot["values"]["<HostileScalar>"]["unavailable_reason"] == "unsupported_model_snapshot_value"
    assert snapshot["ready_unavailable_reason"] == "non_boolean_ready"
    assert probability["probability_unavailable_reason"] == "non_numeric_probability"
    assert probability["support_unavailable_reason"] == "non_numeric_support_metric"
    assert probability["flow_unavailable_reason"] == "non_text_flow_item"
    json.dumps(
        {
            "evidence": evidence,
            "feature_bundle": feature_bundle,
            "failure": failure,
            "snapshot": snapshot,
            "probability": probability,
        },
        sort_keys=True,
    )
    hostile.assert_untouched()


def test_stage1546_followup_magic_recovery_tags_do_not_stringify_or_compare_hostile_tags():
    hostile = HostileScalar()

    assert is_rpgm_passive_recovered(
        ".png",
        "image",
        "rpgm_mv_encrypted_asset",
        [hostile, "rpgm_encrypted_asset", "rpgm_recovered_magic_png"],
    )
    hostile.assert_untouched()


def test_stage1546_followup_policy_tag_constants_are_immutable():
    policy_sets = (
        evidence_line_rules.DECODE_TAGS,
        evidence_line_rules.EMBEDDED_PAYLOAD_TAGS,
        evidence_line_rules.PICKLE_TAGS,
        magic_extension_tags._IMAGE_RECOVERY_TAGS,
    )

    for policy_set in policy_sets:
        assert isinstance(policy_set, frozenset)
        before = policy_set
        with pytest.raises(AttributeError):
            policy_set.add("stage1546_mutation_probe")
        assert policy_set is before
        assert "stage1546_mutation_probe" not in policy_set


def test_stage1546_followup_final_json_projection_rejects_hostile_text_without_hooks():
    hostile = HostileScalar()

    text, reason = safe_projection_text(hostile)
    signal = bounded_signal_value(hostile)
    tags = canonical_tag_list(["safe", hostile])

    assert text == ""
    assert reason == "final_json_text_unavailable"
    assert signal["model_signal_projection_failed"] is True
    assert signal["reason"] == "final_json_text_unavailable"
    assert "safe" in tags
    assert any("final_json_text_unavailable" in item for item in tags)
    hostile.assert_untouched()


def test_stage1546_followup_runtime_markov_temporal_text_boundaries_reject_hostile_hooks():
    hostile = HostileScalar()

    assert model_state._runtime_model_display_text(hostile).startswith("<unrepresentable:")
    assert model_state._runtime_model_identity_text(hostile) == ("", "unreadable_runtime_model_identity")
    assert model_state._runtime_model_count_with_reason(hostile) == (0, "non_numeric_runtime_model_count")
    assert markov_detached_text(hostile) == ("", "unsupported_markov_text")
    assert temporal_boundary_text(hostile) == TEMPORAL_TEXT_UNAVAILABLE
    assert _model_sequence_detached_text(hostile, default_text="") == ""
    hostile.assert_untouched()
