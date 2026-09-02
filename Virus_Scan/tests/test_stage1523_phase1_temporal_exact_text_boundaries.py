from __future__ import annotations

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.models.api import temporal_contracts
from Virus_Scan.models.temporal.anomaly import temporal_flat_events
from Virus_Scan.models.temporal.evidence import cache_key
from Virus_Scan.models.temporal.validation import compute_temporal_validation
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


class HostileStr(str):
    def __new__(cls, value: str):
        return str.__new__(cls, value)

    def __str__(self):
        raise AssertionError("caller-owned __str__ executed")

    def strip(self, *args, **kwargs):
        raise AssertionError("caller-owned strip executed")

    def __bool__(self):
        raise AssertionError("caller-owned truthiness executed")


def test_canonical_chain_order_matching_rejects_hostile_text_without_hooks():
    evidence = evaluate_chain_evidence(
        ordered_events=({"tag": HostileStr("encoded_powershell")},),
        match_modes=("ordered",),
    )
    assert evidence.decisions == ()
    assert evidence.failures[0]["reason"] == "chain_event_rejected"


def test_temporal_validation_preserves_hostile_stage_text_as_exact_builtin_string():
    result = compute_temporal_validation(
        HostileStr("node-alpha"), tags=physical_tag_evidence(("network_download",)),
        prev_stage=HostileStr("resource"), curr_stage=HostileStr("execution"),
        markov={
            "transition": 0.0, "rarity": 0.0,
            "pair_anomaly": 0.0, "sequence_anomaly": 0.0,
        },
    )
    assert result["events"][-1]["stage"] == "execution"
    assert type(result["events"][-1]["stage"]) is str


def test_temporal_flat_events_preserves_hostile_stage_and_tag_text():
    events = temporal_flat_events([{
        "time": 1.0, "stage": HostileStr("archive"),
        "tags": (HostileStr("network_download"),),
    }])
    assert events[0].stage == "archive"
    assert events[0].behavior_id == "network_download"
    assert type(events[0].stage) is str
    assert type(events[0].behavior_id) is str


def test_temporal_public_overlay_and_update_preserve_hostile_stage_text():
    overlay = temporal_contracts.transition_probability_overlay(
        prev_stage=HostileStr("asset"),
        tags=("network_download", "process_exec"),
        curr_stage=HostileStr("runtime"),
        ordered_events=(
            {"tag": "network_download", "timestamp": 1.0, "stage": "asset"},
            {"tag": "process_exec", "timestamp": 2.0, "stage": "runtime"},
        ),
    )
    assert overlay["prev_stage"] == "asset"
    assert overlay["curr_stage"] == "runtime"
    assert type(overlay["prev_stage"]) is str
    assert type(overlay["curr_stage"]) is str

    updated = temporal_contracts.update_temporal(
        HostileStr("stage1523-node"), HostileStr("runtime"),
        ("network_download",),
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1523-update",
        ),
    )
    assert updated["stage"] == "runtime"
    assert type(updated["stage"]) is str


def test_temporal_cache_key_detaches_hostile_namespace_and_parts():
    key = cache_key(HostileStr("temporal"), HostileStr("node"), HostileStr("phase"))
    assert key == "temporal:node:phase"
    assert type(key) is str
