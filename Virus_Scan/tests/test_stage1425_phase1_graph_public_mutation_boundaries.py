import pytest

from Virus_Scan.models.graph import (
    phase_matches_from_tags,
    add_method_node,
    emit_stage_event,
    incremental_graph_update,
)
from Virus_Scan.runtime.graph_state import graph_node_snapshot, reset_graph_state
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE


class HostileBoolIterable:
    def __init__(self, values=()):
        self._values = tuple(values)

    def __bool__(self):
        raise RuntimeError("truthiness should not be probed")

    def __iter__(self):
        return iter(self._values)


class HostileIterFailure:
    def __bool__(self):
        raise RuntimeError("truthiness should not be probed")

    def __iter__(self):
        raise RuntimeError("iteration unavailable")


class HostileText:
    def __bool__(self):
        raise RuntimeError("truthiness should not be probed")

    def __str__(self):
        raise RuntimeError("text unavailable")


def test_emit_stage_event_records_degraded_evidence_for_hostile_tags():
    event = emit_stage_event("sample.py", "scan", HostileIterFailure())

    assert event["degraded"] is True
    assert event["graph_unavailable_reason"] == "graph_stage_event_tags_unavailable"
    assert event["final_json_must_record"] is True
    assert event["replay_record_required"] is True
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in event["tags"]
    assert DETECTION_STAGE_DEGRADED_TAG in event["tags"]


def test_graph_public_mutation_paths_do_not_truthiness_probe_hostile_inputs():
    reset_graph_state()

    add_method_node("method-node", HostileIterFailure(), HostileBoolIterable(["CallA", HostileText()]))
    incremental_graph_update("node.exe", tag_evidence=HostileIterFailure())

    method_snapshot = graph_node_snapshot("method-node")
    update_snapshot = graph_node_snapshot("node.exe")

    assert method_snapshot is not None
    assert update_snapshot is not None
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in method_snapshot["tags"]
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in update_snapshot["tags"]


def test_phase_matching_rejects_unknown_iterables_without_crashing_or_iterating():
    attack_graph = {"credential": {"nodes": HostileBoolIterable(["credential_access"])}}

    matches = phase_matches_from_tags(HostileBoolIterable(["credential_access"]), attack_graph=attack_graph)

    assert matches == {}
