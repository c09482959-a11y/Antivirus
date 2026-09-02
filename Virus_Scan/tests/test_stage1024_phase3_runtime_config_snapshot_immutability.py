from __future__ import annotations

import pytest

from Virus_Scan.runtime.config import ArchiveScanLimits, RuntimeConfig, StageConcurrencyLimits


def test_stage1024_runtime_config_direct_init_freezes_json_style_economics_payload() -> None:
    economics = {"budgets": {"archive": [10]}}
    persistence = {"outputs": {"paths": ["scan_results.json"]}}

    cfg = RuntimeConfig(
        archive_limits=ArchiveScanLimits(),
        stage_limits=StageConcurrencyLimits(),
        economics=economics,
        persistence=persistence,
    )
    economics["budgets"]["archive"].append(99)
    persistence["outputs"]["paths"].append("mutated.json")

    assert cfg.economics["budgets"]["archive"] == (10,)
    assert cfg.persistence["outputs"]["paths"] == ("scan_results.json",)
    with pytest.raises(TypeError):
        cfg.economics["new"] = {"blocked": True}


def test_stage1024_runtime_config_as_mapping_returns_mutable_copy_not_snapshot_state() -> None:
    economics = {"budgets": {"archive": [10]}}
    cfg = RuntimeConfig(
        archive_limits=ArchiveScanLimits(),
        stage_limits=StageConcurrencyLimits(),
        economics=economics,
        persistence={"outputs": {"paths": ["scan_results.json"]}},
    )

    mapped = cfg.as_mapping()
    mapped["economics"]["budgets"]["archive"].append(99)
    mapped["persistence"]["outputs"]["paths"].append("mutated.json")

    assert cfg.economics["budgets"]["archive"] == (10,)
    assert cfg.persistence["outputs"]["paths"] == ("scan_results.json",)
    assert cfg.as_mapping()["economics"]["budgets"]["archive"] == [10]


def test_stage1024_runtime_config_preserves_typed_runtime_config_behavior() -> None:
    cfg = RuntimeConfig.from_args()

    mapping = cfg.as_mapping()
    checkpoint = cfg.as_checkpoint_fact()

    assert mapping["archive_limits"]["max_depth"] >= 0
    assert mapping["stage_limits"]["raw"] >= 1
    assert "UMIGE_ARCHIVE_MAX_DEPTH" in cfg.env_mapping()
    assert checkpoint["schema"] == "runtime_config_v1"
    assert "payload" in checkpoint

from Virus_Scan.runtime.readonly import ReadonlyRuntimeView


def test_stage1024_readonly_runtime_view_detaches_json_style_config_payload() -> None:
    config = {"runtime": {"paths": ["work"]}}
    view = ReadonlyRuntimeView({"state": "ok"}, config=config, generation="2")
    config["runtime"]["paths"].append("mutated")

    assert view.config["runtime"]["paths"] == ("work",)
    assert view.generation == 2
    with pytest.raises(TypeError):
        view.config["extra"] = {"blocked": True}

from Virus_Scan.contracts.result_record import ReplayComparableResultSnapshot


def test_stage1024_replay_comparable_result_snapshot_direct_init_freezes_payload() -> None:
    nested = {"tags": ["scanner_failure"]}
    snapshot = ReplayComparableResultSnapshot((("evidence", nested),))
    nested["tags"].append("mutated")

    assert snapshot.digest_payload()["evidence"]["tags"] == ["scanner_failure"]
    assert "mutated" not in snapshot.digest_payload()["evidence"]["tags"]

from Virus_Scan.scanners.binary_pe_sections import PEImportParseResult, PESectionParseResult


def test_stage1024_pe_section_parse_result_deep_freezes_section_records() -> None:
    section = {"name": ".text", "signals": ["entry"]}
    result = PESectionParseResult(sections=(section,), error_tags=["warn"])
    section["signals"].append("mutated")

    assert result.sections[0]["signals"] == ("entry",)
    assert result.error_tags == ("warn",)
    with pytest.raises(TypeError):
        result.sections[0]["new"] = "blocked"


def test_stage1024_pe_import_parse_result_normalizes_direct_constructor_lists() -> None:
    result = PEImportParseResult(imports=[["kernel32.dll", ["CreateFileW"]], ["user32.dll", "MessageBoxW"]], error_tags=["warn"])

    assert result.imports == (("kernel32.dll", ("CreateFileW",)), ("user32.dll", ("MessageBoxW",)))
    assert result.error_tags == ("warn",)
