from __future__ import annotations

from Virus_Scan.models.replay_economics import replay_compress_metadata
from Virus_Scan.models.api.replay_economics_contracts import (
    replay_compress_metadata as replay_compress_metadata_contract,
)


def test_replay_compress_metadata_sorts_mapping_keys_for_deterministic_evidence() -> None:
    first = {"z": 1, "A": 2, "m": {"b": 1, "a": 2}}
    second = {"m": {"a": 2, "b": 1}, "A": 2, "z": 1}

    assert replay_compress_metadata(first) == replay_compress_metadata(second)
    assert list(replay_compress_metadata(first).keys()) == ["A", "m", "z"]
    assert list(replay_compress_metadata(first)["m"].keys()) == ["a", "b"]


def test_replay_compress_metadata_truncation_is_independent_of_input_order() -> None:
    forward = {f"k{i:02d}": i for i in range(40)}
    reverse = dict(reversed(list(forward.items())))

    compressed_forward = replay_compress_metadata(forward)
    compressed_reverse = replay_compress_metadata(reverse)

    assert compressed_forward == compressed_reverse
    assert list(compressed_forward.keys()) == [*(f"k{i:02d}" for i in range(32)), "truncated"]
    assert compressed_forward["truncated"] is True


def test_replay_economics_public_contract_preserves_order_determinism() -> None:
    first = {"z": {"y": 1, "x": 2}, "a": 3}
    second = {"a": 3, "z": {"x": 2, "y": 1}}

    assert replay_compress_metadata_contract(first) == replay_compress_metadata_contract(second)
    assert list(replay_compress_metadata_contract(first).keys()) == ["a", "z"]
