from __future__ import annotations

import json
from collections.abc import MutableMapping
from pathlib import Path
from types import MappingProxyType
from typing import Iterator

import pytest

from Virus_Scan.publication.json_finalization.streaming import finalize_scan_results, stream_json_mapping


class HostileResultMapping(MutableMapping):
    touched = 0

    def __getitem__(self, key: object) -> object:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("result mapping __getitem__ hook executed")

    def __setitem__(self, key: object, value: object) -> None:  # pragma: no cover - mutable protocol stub
        raise AssertionError("result mapping __setitem__ hook executed")

    def __delitem__(self, key: object) -> None:  # pragma: no cover - mutable protocol stub
        raise AssertionError("result mapping __delitem__ hook executed")

    def __iter__(self) -> Iterator[object]:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("result mapping __iter__ hook executed")

    def __len__(self) -> int:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("result mapping __len__ hook executed")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("result mapping items hook executed")

    def keys(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("result mapping keys hook executed")

    def values(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("result mapping values hook executed")

    def get(self, key: object, default: object = None) -> object:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("result mapping get hook executed")


class HostileDeterministicFlag:
    touched = 0

    def __bool__(self) -> bool:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("deterministic_mode __bool__ hook executed")

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("deterministic_mode __str__ hook executed")

    def __repr__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("deterministic_mode __repr__ hook executed")


def _hostile_proxy() -> MappingProxyType:
    HostileResultMapping.touched = 0
    return MappingProxyType(HostileResultMapping())


def test_stage1746_stream_json_mapping_rejects_mappingproxy_backed_by_hostile_mapping_without_hooks(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"

    with pytest.raises(RuntimeError) as exc_info:
        stream_json_mapping(
            str(output),
            _hostile_proxy(),
            fsync_file=False,
            verify_written=False,
            deterministic_mode=False,
        )

    assert HostileResultMapping.touched == 0
    text = str(exc_info.value)
    assert "final_json_stream_write_failed:path=" in text
    assert "reason=TypeError" in text
    assert not output.exists()
    assert not list(tmp_path.glob("scan_results.json.*.tmp"))


def test_stage1746_deterministic_streaming_rejects_hostile_mappingproxy_without_keys_or_get(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"

    with pytest.raises(RuntimeError, match="final_json_stream_write_failed"):
        stream_json_mapping(
            str(output),
            _hostile_proxy(),
            fsync_file=False,
            verify_written=False,
            deterministic_mode=True,
        )

    assert HostileResultMapping.touched == 0
    assert not output.exists()
    assert not list(tmp_path.glob("scan_results.json.*.tmp"))


def test_stage1746_finalize_scan_results_rejects_hostile_mappingproxy_without_mapping_hooks(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"

    with pytest.raises(RuntimeError, match="final_json_stream_write_failed"):
        finalize_scan_results(
            str(output),
            _hostile_proxy(),
            deterministic_mode=False,
        )

    assert HostileResultMapping.touched == 0
    assert not output.exists()
    assert not list(tmp_path.glob("scan_results.json.*.tmp"))


def test_stage1746_stream_json_mapping_accepts_exact_dict_backed_mappingproxy(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    results = MappingProxyType({"sample": {"classification": "clean", "score": 0.0, "tags": []}})

    assert stream_json_mapping(str(output), results, fsync_file=False, deterministic_mode=True) is True

    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert list(loaded) == ["sample"]
    assert loaded["sample"]["score"] == 0.0
    assert loaded["sample"]["json_schema_version"] == "scan_result_compact_v2"
    assert "tags" in loaded["sample"]


def test_stage1746_streaming_rejects_hostile_deterministic_flag_without_truthiness(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    HostileDeterministicFlag.touched = 0

    with pytest.raises(RuntimeError) as exc_info:
        stream_json_mapping(
            str(output),
            {"sample": {"classification": "clean"}},
            fsync_file=False,
            verify_written=False,
            deterministic_mode=HostileDeterministicFlag(),  # type: ignore[arg-type]
        )

    assert HostileDeterministicFlag.touched == 0
    text = str(exc_info.value)
    assert "final_json_stream_write_failed:path=" in text
    assert "reason=TypeError" in text
    assert not output.exists()
