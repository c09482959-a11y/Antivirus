"""Stage 1519 Phase 1 exact-text public/model boundary regressions."""
from __future__ import annotations

from Virus_Scan.detection.models.failure_state import _unavailable_failure_record
from Virus_Scan.detection.models.stage_value_utils import detection_unavailable_value, safe_detection_text
from Virus_Scan.detection.scoring.adaptive.boundary_values import adaptive_reason_text
from Virus_Scan.detection.scoring.adaptive.public_inputs import adaptive_public_text_with_reason
from Virus_Scan.models.clustering.common import cluster_first_reason, cluster_text_set, safe_cluster_text
from Virus_Scan.models.clustering.snapshots import _cluster_snapshot_identity
from Virus_Scan.models.markov.counters import counter_support, markov_reason_text
from Virus_Scan.contracts.markov_learning import markov_event_transition_key, markov_global_context_key
from Virus_Scan.models.markov.flow import canonical_behavior_flow, safe_markov_text
from Virus_Scan.models.profiles.common import profile_safe_text


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        obj.strip_calls = 0
        obj.str_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves caller-owned __str__ was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves caller-owned strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves caller-owned truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")


def h(value: str) -> HostileText:
    return HostileText(value)


def assert_no_hooks(*values: HostileText) -> None:
    for value in values:
        assert value.bool_calls == 0
        assert value.strip_calls == 0
        assert value.str_calls == 0


def test_stage1519_clustering_text_boundaries_detach_before_strip_or_bool():
    tag = h(" malware ")
    reason = h(" bad_cluster ")
    cid = h(" cluster-1 ")

    assert safe_cluster_text(tag) == "malware"
    assert cluster_text_set([tag]) == {"malware"}
    assert cluster_first_reason(None, reason) == "bad_cluster"
    assert _cluster_snapshot_identity(cid) == "cluster-1"

    assert_no_hooks(tag, reason, cid)


def test_stage1519_markov_text_boundaries_detach_stage_flow_and_counter_keys():
    source = h(" extract ")
    target = h(" score ")
    event = h(" api_CreateFile ")
    reason = h(" cold_start ")

    assert safe_markov_text(source) == "extract"
    assert markov_reason_text(reason) == "cold_start"
    assert canonical_behavior_flow([event]) == ()
    assert markov_event_transition_key(
        context_key=markov_global_context_key(),
        previous_stage="extract",
        source_event="score",
    ) == (
        "markov_event_v2",
        ("global:trusted_benign", "extract", "score"),
    )
    assert counter_support({target: 3}) == (3, 1, "")

    assert_no_hooks(source, target, event, reason)


def test_stage1519_adaptive_detection_profile_text_boundaries_detach_hostile_text():
    text = h(" degraded ")
    reason = h(" unavailable ")
    profile = h(" renpy ")

    assert adaptive_reason_text(reason) == "unavailable"
    assert adaptive_public_text_with_reason(text) == ("degraded", None)
    assert safe_detection_text(text, "fallback") == ("degraded", None)
    assert detection_unavailable_value(reason)["unavailable_reason"] == "unavailable"
    assert profile_safe_text(profile) == "renpy"

    assert_no_hooks(text, reason, profile)


def test_stage1519_detection_failure_state_detaches_hostile_reason_text():
    reason = h(" detection_failure ")
    record = _unavailable_failure_record(reason)

    assert record["message"] == "detection_failure"
    assert record["unavailable_reason"] == "detection_failure"
    assert type(record["message"]) is str
    assert type(record["unavailable_reason"]) is str
    assert_no_hooks(reason)
