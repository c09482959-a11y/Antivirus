from __future__ import annotations

from dataclasses import replace

import pytest

from Virus_Scan.scanners.config.loader_policy_binary_archive import load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.config.loader_policy_core import (
    load_engine_policy_snapshot,
    load_filetype_policy_snapshot,
    load_text_policy_snapshot,
)


def test_stage1023_text_policy_direct_init_freezes_nested_api_mappings() -> None:
    base = load_text_policy_snapshot()
    caller_owned = {"process_execution": ["CreateProcessA"]}

    snapshot = replace(
        base,
        api_groups=caller_owned,
        api_specific_tags={"CreateProcessA": ["process_execution"]},
        api_group_tags={"process_execution": ["exec_tag"]},
        api_group_inferred_tags={"process_execution": ["inferred_tag"]},
    )
    caller_owned["process_execution"].append("mutated")

    assert "mutated" not in snapshot.api_groups["process_execution"]
    with pytest.raises(TypeError):
        snapshot.api_groups["extra"] = frozenset({"blocked"})


def test_stage1023_filetype_and_engine_policy_direct_init_freezes_nested_mappings() -> None:
    filetype = load_filetype_policy_snapshot()
    expected_magic = {".sample": ["sample_magic"]}
    routed = {"sample": [".sample"]}

    filetype_snapshot = replace(
        filetype,
        expected_magic_types_by_extension=expected_magic,
        routable_extensions_by_claim=routed,
        magic_type_category={"sample_magic": ["sample_category"]},
    )
    expected_magic[".sample"].append("mutated_magic")
    routed["sample"].append(".mutated")

    assert "mutated_magic" not in filetype_snapshot.expected_magic_types_by_extension[".sample"]
    assert ".mutated" not in filetype_snapshot.routable_extensions_by_claim["sample"]
    with pytest.raises(TypeError):
        filetype_snapshot.magic_type_category["new"] = frozenset({"blocked"})

    engine = load_engine_policy_snapshot()
    cues = {"unity": {"extensions": [".assets"]}}
    engine_snapshot = replace(engine, engine_file_context_cues=cues)
    cues["unity"]["extensions"].append(".mutated")

    assert ".mutated" not in engine_snapshot.engine_file_context_cues["unity"]["extensions"]
    with pytest.raises(TypeError):
        engine_snapshot.engine_file_context_cues["rpgm"] = {"extensions": [".json"]}


def test_stage1023_scanner_limits_policy_direct_init_freezes_nested_mappings() -> None:
    base = load_scanner_limits_policy_snapshot()
    rewrite_map = {"possible_lsb_stego": ["weak_image_stego_observation"]}
    magic_by_extension = {".png": ["png"]}

    snapshot = replace(
        base,
        image_stego_tag_rewrite_map=rewrite_map,
        image_magic_prefixes_by_extension=magic_by_extension,
    )
    rewrite_map["possible_lsb_stego"].append("mutated")
    magic_by_extension[".png"].append("mutated_magic")

    assert "mutated" not in snapshot.image_stego_tag_rewrite_map["possible_lsb_stego"]
    assert "mutated_magic" not in snapshot.image_magic_prefixes_by_extension[".png"]
    with pytest.raises(TypeError):
        snapshot.image_magic_prefixes_by_extension[".jpg"] = frozenset({"jpeg"})

from Virus_Scan.runtime.yara_rules_state import YaraLightSnapshot, YaraRulesSnapshot, YaraRulesState


def test_stage1023_yara_rule_snapshots_detach_json_style_mutable_rule_metadata() -> None:
    mutable_rules = {"groups": ["light"]}
    light = YaraLightSnapshot(rules=mutable_rules, ok=True, loaded_count=1)
    mutable_rules["groups"].append("mutated")

    assert "mutated" not in light.rules["groups"]
    with pytest.raises(TypeError):
        light.rules["new"] = ("blocked",)

    state = YaraRulesState()
    primary_rules = {"groups": ["primary"]}
    state.set_primary_rules(primary_rules, source_path="rules.yar", loaded_count=1)
    primary_rules["groups"].append("mutated")
    primary = state.primary_snapshot()

    assert isinstance(primary, YaraRulesSnapshot)
    assert "mutated" not in primary.rules["groups"]
    with pytest.raises(TypeError):
        primary.rules["new"] = ("blocked",)
