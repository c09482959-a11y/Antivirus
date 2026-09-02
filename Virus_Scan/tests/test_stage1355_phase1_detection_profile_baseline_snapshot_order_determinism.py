from unittest.mock import patch
from types import MappingProxyType

from Virus_Scan.detection.profiles import baseline_snapshot


def _materialize(value):
    if isinstance(value, MappingProxyType) or isinstance(value, dict):
        return {key: _materialize(value[key]) for key in value.keys()}
    if isinstance(value, tuple):
        return tuple(_materialize(item) for item in value)
    if isinstance(value, frozenset):
        return tuple(sorted((_materialize(item) for item in value), key=repr))
    return value


def _baseline_one():
    return {
        "files": 4,
        "behavior_buckets": {
            "script": {"tags": {"beta": 1, "alpha": 3}},
        },
        "timeline_baseline": {
            "transition_counts": {"b->c": 1, "a->b": 2},
            "event_counts": {"z": 1, "a": 2},
        },
        "tag_evidence": {
            "unordered": {"gamma", "alpha", "beta"},
            "nested": {"later": {"b": 2, "a": 1}, "earlier": {"d": 4, "c": 3}},
        },
    }


def _baseline_two():
    return {
        "tag_evidence": {
            "nested": {"earlier": {"c": 3, "d": 4}, "later": {"a": 1, "b": 2}},
            "unordered": {"beta", "gamma", "alpha"},
        },
        "timeline_baseline": {
            "event_counts": {"a": 2, "z": 1},
            "transition_counts": {"a->b": 2, "b->c": 1},
        },
        "behavior_buckets": {
            "script": {"tags": {"alpha": 3, "beta": 1}},
        },
        "files": 4,
    }


def test_detection_profile_baseline_snapshot_canonicalizes_nested_mapping_and_set_order():
    with patch.object(baseline_snapshot, "get_extension_baseline", lambda engine, file_path: _baseline_one()):
        first = _materialize(baseline_snapshot.read_extension_baseline_snapshot("renpy", "game.rpy"))

    with patch.object(baseline_snapshot, "get_extension_baseline", lambda engine, file_path: _baseline_two()):
        second = _materialize(baseline_snapshot.read_extension_baseline_snapshot("renpy", "game.rpy"))

    assert first == second
    assert first["tag_evidence"]["unordered"] == ("alpha", "beta", "gamma")
    assert tuple(first["behavior_buckets"]["script"]["tags"].keys()) == ("alpha", "beta")
    assert tuple(first["timeline_baseline"]["event_counts"].keys()) == ("a", "z")


def test_detection_profile_baseline_snapshot_preserves_semantic_list_order():
    baseline = {
        "files": 1,
        "timeline_baseline": {"observed_sequence": ["load", "execute", "write"]},
    }
    with patch.object(baseline_snapshot, "get_extension_baseline", lambda engine, file_path: baseline):
        snapshot = _materialize(baseline_snapshot.read_extension_baseline_snapshot("renpy", "game.rpy"))

    assert snapshot["timeline_baseline"]["observed_sequence"] == ("load", "execute", "write")
