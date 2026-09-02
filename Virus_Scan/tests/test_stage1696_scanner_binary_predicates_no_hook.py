
"""Stage1696: scanner binary predicate materialization rejects hostile objects."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.scanners.binary_behavior_predicates import (
    _binary_delayed_execution_score,
    _ordered_contains_subsequence,
    _xor_blob_signal,
)


class _HostilePredicateObject:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller hook executed")

    def __bool__(self):
        return self._touch()

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, _format_spec):
        return self._touch()

    def __iter__(self):
        return self._touch()

    def __len__(self):
        return self._touch()

    def __getitem__(self, _key):
        return self._touch()

    def __bytes__(self):
        return self._touch()

    @property
    def tag(self):
        return self._touch()


class _HostileEvent:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("event string hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("event repr hook executed")

    @property
    def tag(self):
        type(self).touched += 1
        raise RuntimeError("event property executed")


class _HostileNeedle:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("needle string hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("needle repr hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("needle iter hook executed")


class _HostileBlob:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("blob bool hook executed")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("blob len hook executed")

    def __getitem__(self, _key):
        type(self).touched += 1
        raise RuntimeError("blob getitem hook executed")

    def __bytes__(self):
        type(self).touched += 1
        raise RuntimeError("blob bytes hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("blob iter hook executed")


def test_stage1696_ordered_subsequence_rejects_hostile_stream_without_hooks() -> None:
    _HostilePredicateObject.reset()
    assert _ordered_contains_subsequence(_HostilePredicateObject(), "download") is False
    assert _HostilePredicateObject.touched == 0


def test_stage1696_ordered_subsequence_rejects_hostile_events_and_needles_without_hooks() -> None:
    _HostileEvent.reset()
    _HostileNeedle.reset()
    assert _ordered_contains_subsequence([_HostileEvent()], _HostileNeedle()) is False
    assert _HostileEvent.touched == 0
    assert _HostileNeedle.touched == 0


def test_stage1696_delayed_execution_score_ignores_hostile_event_without_properties() -> None:
    _HostileEvent.reset()
    score, tags = _binary_delayed_execution_score([_HostileEvent(), {"tag": "powershell_exec"}])
    assert (score, tags) == (0.0, [])
    assert _HostileEvent.touched == 0


def test_stage1696_xor_blob_signal_rejects_hostile_blob_before_bool_len_slice_or_bytes() -> None:
    _HostileBlob.reset()
    with pytest.raises(TypeError, match="unsafe_binary_blob_rejected"):
        _xor_blob_signal(_HostileBlob())
    assert _HostileBlob.touched == 0


def test_stage1696_binary_predicates_preserve_owned_sequence_and_blob_behavior() -> None:
    assert _ordered_contains_subsequence(
        [{"tag": "network_download"}, {"tag": "file_write"}, {"tag": "process_exec"}],
        {"download", "network_download"},
        "file_write",
        {"process_exec", "createprocess"},
    ) is True
    assert _binary_delayed_execution_score([{"tag": "anti_sandbox_sleep"}, {"tag": "powershell_exec"}]) == (
        4.0,
        ["temporal_delayed_execution"],
    )
    assert _xor_blob_signal(b"A" * 512) is False
    assert _xor_blob_signal(bytearray(b"A" * 512)) is False
    assert _xor_blob_signal(memoryview(b"A" * 512)) is False


def test_stage1696_binary_predicates_source_has_no_hostile_materialization_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_behavior_predicates.py"))
    forbidden = (
        "str(item)",
        "str(opt)",
        "events or []",
        "stream or []",
        "if not stream",
        "if not data",
        "set(tags or [])",
    )
    for pattern in forbidden:
        assert pattern not in source
