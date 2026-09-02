from __future__ import annotations

from Virus_Scan.models.replay.api import detach_replay_payload_mapping, detach_replay_payload_value


def test_replay_payload_detach_sorts_nested_mapping_keys_for_deterministic_model_input() -> None:
    first = {
        "z": 1,
        "api": {"write_file": True, "connect": False},
        "nested": {"b": {"y": 2, "x": 1}, "a": 0},
    }
    second = {
        "nested": {"a": 0, "b": {"x": 1, "y": 2}},
        "api": {"connect": False, "write_file": True},
        "z": 1,
    }

    detached_first = detach_replay_payload_mapping(first)
    detached_second = detach_replay_payload_mapping(second)

    assert detached_first == detached_second
    assert list(detached_first.keys()) == ["api", "nested", "z"]
    assert list(detached_first["api"].keys()) == ["connect", "write_file"]
    assert list(detached_first["nested"].keys()) == ["a", "b"]
    assert list(detached_first["nested"]["b"].keys()) == ["x", "y"]


def test_replay_payload_detach_sorts_dicts_inside_lists_without_reordering_events() -> None:
    first = [
        {"event": "first", "tags": {"z", "a"}, "metadata": {"b": 2, "a": 1}},
        {"event": "second", "metadata": {"y": 2, "x": 1}},
    ]
    second = [
        {"metadata": {"a": 1, "b": 2}, "tags": {"a", "z"}, "event": "first"},
        {"metadata": {"x": 1, "y": 2}, "event": "second"},
    ]

    detached_first = detach_replay_payload_value(first)
    detached_second = detach_replay_payload_value(second)

    assert detached_first == detached_second
    assert [row["event"] for row in detached_first] == ["first", "second"]
    assert list(detached_first[0].keys()) == ["event", "metadata", "tags"]
    assert list(detached_first[0]["metadata"].keys()) == ["a", "b"]
    assert detached_first[0]["tags"] == ["a", "z"]
