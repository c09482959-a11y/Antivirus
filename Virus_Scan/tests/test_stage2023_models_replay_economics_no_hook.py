from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models.replay_economics import (
    ReplayEconomicsConfig,
    replay_compress_metadata,
    replay_should_retain,
)



class HostileDict(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __iter__(self):  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()

    def items(self):  # pragma: no cover - must not execute
        return self._touch()

    def values(self):  # pragma: no cover - must not execute
        return self._touch()


class HostileKey:
    touched = 0

    def __hash__(self) -> int:
        return 2023

    def __eq__(self, _other):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned equality hook was invoked")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


class HostileValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


def test_stage2023_replay_metadata_compresses_hostile_key_value_without_hooks() -> None:
    HostileKey.touched = 0
    HostileValue.touched = 0

    compressed = replay_compress_metadata({HostileKey(): HostileValue()})

    assert compressed == {
        "<unreadable_replay_metadata_key_0>": {
            "value": "<HostileValue>",
            "unavailable_reason": "unsupported_replay_metadata_type",
        }
    }
    assert HostileKey.touched == 0
    assert HostileValue.touched == 0


def test_stage2023_replay_economics_rejects_hostile_mapping_hooks() -> None:
    HostileDict.touched = 0
    mapping = HostileDict({"score": 0, "path": "sample.bin"})

    assert replay_should_retain(
        mapping,
        index=1,
        config=ReplayEconomicsConfig(sample_modulo=10_000, divergence_always_keep=False),
    ) is True
    assert replay_compress_metadata(mapping) == {
        "value": "<HostileDict>",
        "unavailable_reason": "unsupported_replay_metadata_type",
    }
    assert HostileDict.touched == 0


def test_stage2023_replay_economics_unreadable_index_fails_retained_without_hooks() -> None:
    HostileValue.touched = 0

    assert replay_should_retain(
        {},
        index=HostileValue(),
        config=ReplayEconomicsConfig(sample_modulo=10_000, divergence_always_keep=False),
    ) is True
    assert HostileValue.touched == 0


def test_stage2023_replay_economics_source_removed_backlog_hook_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/models/replay_economics.py"))

    forbidden = (
        'f"_{index}"',
        'f"<unreadable_replay_metadata_key{suffix}>"',
        'f"<{no_hook_type_name(key)}>"',
        'f"<{no_hook_type_name(value)}>"',
        "return 0\n",
        "dict.items(meta)",
        "isinstance(meta, dict)",
        "_MAPPING_PROXY_TYPE.items(meta)",
        'key_text = f"{key_text}#{index}"',
    )
    for snippet in forbidden:
        assert snippet not in source
