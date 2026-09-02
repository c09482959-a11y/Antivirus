from __future__ import annotations

import pytest

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.heuristics import evaluate_pickle_execution
from Virus_Scan.persistence import flush_persistent_state
from Virus_Scan.reporting.compact import display_tags_for_result
from Virus_Scan.routing.filetype_tables import (
    ALL_ROUTABLE_EXTENSIONS,
    EXPECTED_MAGIC_TYPES_BY_EXTENSION,
    MAGIC_TYPE_CATEGORY,
    ROUTABLE_EXTENSIONS_BY_CLAIM,
)


class _NonParentRuntime:
    parent_cli = False

    def get(self, *args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("non-parent persistence path must not read cache settings")

    def has(self, *args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("non-parent persistence path must not inspect flush hooks")


class _StrictArgs:
    strict = True


def test_pickle_execution_public_heuristic_reports_reduce_global_callable_chain() -> None:
    result = evaluate_pickle_execution(b"GLOBAL os\n.system REDUCE", source="sample.rpyc")

    assert result["source"] == "sample.rpyc"
    assert result["families"] == ["callable", "global", "reduce"]
    assert "pickle_reduce_opcode" in result["tags"]
    assert "pickle_global_reference" in result["tags"]
    assert "pickle_callable_reference" in result["tags"]
    assert "pickle_dangerous_global" in result["tags"]
    assert "pickle_callable_reduce_chain" not in result["tags"]
    assert "confirmed_pickle_exec_chain" not in result["tags"]
    assert "confirmed_pickle_callable_chain" not in result["tags"]
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(result["tags"])))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:pickle_execution_anchor"
    )
    assert decision.status == "candidate"


def test_routing_filetype_tables_are_immutable_and_cover_engine_media_claims() -> None:
    assert EXPECTED_MAGIC_TYPES_BY_EXTENSION[".rpa"] >= frozenset({"renpy_rpa"})
    assert EXPECTED_MAGIC_TYPES_BY_EXTENSION[".ogg"] == frozenset({"ogg"})
    assert ".rpa" in ROUTABLE_EXTENSIONS_BY_CLAIM["archive"]
    assert ".assets" in ROUTABLE_EXTENSIONS_BY_CLAIM["unity_asset"]
    assert ".ogg" in ROUTABLE_EXTENSIONS_BY_CLAIM["media"]
    assert MAGIC_TYPE_CATEGORY["renpy_rpa"] == "archive"
    assert MAGIC_TYPE_CATEGORY["unity_serialized_asset"] == "unity_asset"
    assert ALL_ROUTABLE_EXTENSIONS >= frozenset({".rpa", ".assets", ".ogg"})

    with pytest.raises(TypeError):
        EXPECTED_MAGIC_TYPES_BY_EXTENSION[".new"] = frozenset({"new_magic"})  # type: ignore[index]
    with pytest.raises(AttributeError):
        ROUTABLE_EXTENSIONS_BY_CLAIM["archive"].add(".evil")  # type: ignore[attr-defined]


def test_compact_reporting_displays_only_medium_plus_non_noisy_tags() -> None:
    result = {
        "tags": [
            "file_seen",
            "ext_py",
            "magic_text",
            "cmd_exec",
            "encoded_powershell",
            "cmd_exec",
        ]
    }

    assert display_tags_for_result(result, 24.99) == []
    assert display_tags_for_result(result, 25.0) == ["cmd_exec", "encoded_powershell"]


def test_persistence_flush_is_noop_for_non_parent_runtime_without_touching_writers() -> None:
    assert flush_persistent_state(_NonParentRuntime(), _StrictArgs()) is None
