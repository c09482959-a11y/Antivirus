from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from Virus_Scan.publication.json_finalization.base_projection import (
    canonical_chain_list,
    canonical_tag_list,
    stable_record_path,
)
from Virus_Scan.publication.json_finalization.partial_results import recover_results_from_partial
from Virus_Scan.publication.json_finalization.record_fields import (
    record_extension_mismatch,
    record_filename,
    routing_engine_context,
)
from Virus_Scan.publication.json_finalization.streaming import stream_json_mapping


class HostileBoolText:
    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self) -> str:
        return self._text

    def __bool__(self) -> bool:  # pragma: no cover - the assertion is no call
        raise AssertionError("final JSON boundary must not truth-test caller text")


class HostileBoolIterable:
    def __init__(self, values: tuple[Any, ...]) -> None:
        self._values = values

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __bool__(self) -> bool:  # pragma: no cover - the assertion is no call
        raise AssertionError("final JSON boundary must not truth-test caller iterables")


class HostileBoolMapping(dict):
    def __bool__(self) -> bool:  # pragma: no cover - the assertion is no call
        raise AssertionError("final JSON boundary must not truth-test caller mappings")


def test_stage1485_final_json_identity_helpers_do_not_truth_test_record_values() -> None:
    tags = HostileBoolIterable(("extension_mismatch", "declared_rpy_sniffs_as_zip"))
    record = HostileBoolMapping(
        {
            "path": HostileBoolText("game/archive.rpy"),
            "tags": tags,
            "extension_mismatch": "true",
            "embedded_payloads": HostileBoolIterable(("zip_payload",)),
            "learning_allowed": "false",
        }
    )

    assert stable_record_path(record) == "game/archive.rpy"
    assert record_filename(record) == "archive.rpy"
    assert record_extension_mismatch(record) is True
    context = routing_engine_context(record, list(tags))
    assert context["embedded_payloads"] == ["zip_payload"]
    assert context["learning_allowed"] is False


def test_stage1485_final_json_canonical_lists_iterate_without_truthiness() -> None:
    values = HostileBoolIterable(("beta", "alpha", "beta"))

    assert canonical_tag_list(values) == ["alpha", "beta"]
    assert canonical_chain_list(values) == ["alpha", "beta"]


def test_stage1485_streaming_results_mapping_does_not_truth_test_results(tmp_path: Path) -> None:
    results = HostileBoolMapping(
        {
            "sample": {
                "input_file_path": "sample.rpy",
                "classification": "clean",
                "score": 0.0,
                "tags": [],
            }
        }
    )
    output = tmp_path / "scan_results.json"

    assert stream_json_mapping(str(output), results, deterministic_mode=False) is True
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert list(loaded) == ["sample"]


def test_stage1485_partial_recovery_does_not_truth_test_results(tmp_path: Path) -> None:
    current = HostileBoolMapping({"current": {"classification": "clean"}})

    assert recover_results_from_partial(str(tmp_path / "missing.json"), current) == {
        "current": {"classification": "clean"}
    }
