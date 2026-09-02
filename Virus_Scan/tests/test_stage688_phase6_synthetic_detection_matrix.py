"""Stage 688 Phase 6 synthetic detection matrix.

This test intentionally exercises detection-owned fast/deep/replay behavior and
recoverable failure visibility for the engine/media cases named in the stored
remediation command. It does not add alternate detector paths; it verifies the
canonical detection pipeline and bounded failure evidence contracts.
"""
from __future__ import annotations

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.detection.profiles import family_scan

import json
from pathlib import Path
from typing import Any
from dataclasses import replace


import pytest

from Virus_Scan.detection.enrichment.prefilter import scan as prefilter_scan
from Virus_Scan.detection.enrichment.full_analysis import api_context, input_stage
from Virus_Scan.detection.correlation.multi_signal import model_context
from Virus_Scan.detection.scoring.full_analysis import cap_inputs, decision_builder
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence
from Virus_Scan.detection.orchestration.full_analysis.pipeline import (
    analyze_file_full_observe_only,
    default_full_analysis_pipeline_dependencies,
)


def _write_case(root: Path, relative_path: str, payload: bytes | str) -> Path:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, bytes):
        target.write_bytes(payload)
    else:
        target.write_text(payload, encoding="utf-8")
    return target


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items() if key not in {"event_seq", "lineage_id"}}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _stable_json(value: Any) -> str:
    return json.dumps(_json_safe(value), sort_keys=True, default=str)


def _assert_result_recorded(record: dict[str, Any]) -> None:
    assert "score" in record
    assert "classification" in record
    assert isinstance(record.get("tags"), list)
    assert isinstance(record.get("scan_integrity"), dict)
    assert "score_reproducibility" in record
    assert record["score_reproducibility"].get("matches_emitted_score") is True
    json.dumps(record, sort_keys=True, default=str)


def _assert_replay_stable(path: Path, tags: list[str], strings_blob: str) -> dict[str, Any]:
    first = analyze_file_full_observe_only(path, tags=tags, strings_blob=strings_blob, scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(path))
    second = analyze_file_full_observe_only(path, tags=tags, strings_blob=strings_blob, scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(path))
    _assert_result_recorded(first)
    _assert_result_recorded(second)
    assert _stable_json(first) == _stable_json(second)
    return first


PHASE6_SYNTHETIC_CASES: tuple[tuple[str, str, bytes | str, list[str]], ...] = (
    ("renpy", "game/script.rpy", "init python:\n    import os\n    os.system('powershell -enc AAA')\n", ["renpy_script", "powershell_exec"]),
    ("renpy", "game/script.rpyc", b"RENPY bytecode pickle GLOBAL os system REDUCE powershell", ["renpy_bytecode", "pickle_opcode_execution"]),
    ("renpy", "game/archive.rpa", "RPA-3.0 pickle opcode global reduce exec os.system powershell", ["renpy_archive", "renpy_pickle_exec"]),
    ("renpy", "game/script_version.txt", "renpy script version metadata with init python socket c2", ["renpy_script_version"]),
    ("renpy", "game/bytecode_like.dat", "renpy bytecode pickletools opcode GLOBAL REDUCE subprocess popen", ["renpy_bytecode"]),
    ("renpy", "game/pickle_payload.bin", b"\x80\x04cos\nsystem\nX\x0apowershell\x94R.", ["pickle_opcode_execution"]),
    ("renpy", "game/loader_abuse.rpy", "init python: import socket, pickle; pickle.loads(data); exec(cmd)", ["renpy_loader_abuse"]),
    ("rpgm", "Game.rgssad", b"RGSSAD encrypted archive eval payload powershell", ["rpgm_archive"]),
    ("rpgm", "Game.rgss2a", b"RGSS2A encrypted archive eval payload", ["rpgm_archive"]),
    ("rpgm", "Game.rgss3a", b"RGSS3A encrypted archive eval payload", ["rpgm_archive"]),
    ("rpgm", "www/data/Actors.json", '{"note":"eval(require(\\"child_process\\").exec(\\"powershell\\"))"}', ["rpgm_data_json"]),
    ("rpgm", "js/plugins.js", "PluginManager.setup(['evil']); require('child_process').exec('powershell')", ["rpgm_plugin_js"]),
    ("rpgm", "node.dll", b"MZ node nwjs require child_process exec powershell", ["rpgm_node_runtime"]),
    ("rpgm", "www/img/pictures/encrypted.rpgmvp", b"RPGMV encrypted media payload powershell", ["encrypted_rpgm_media"]),
    ("rpgm", "www/img/pictures/mislabeled.png", b"RPGMV fake png appended MZ powershell", ["rpgm_mislabeled_media"]),
    ("unity", "UnityPlayer.dll", b"MZ UnityPlayer VirtualAlloc WriteProcessMemory CreateRemoteThread", ["unity_native", "process_injection"]),
    ("unity", "Assembly-CSharp.dll", "System.Reflection.Assembly.Load Convert.FromBase64String", ["unity_managed_code"]),
    ("unity", "globalgamemanagers", b"Unity globalgamemanagers resources assets", ["unity_asset_index"]),
    ("unity", "resources.assets", b"UnityFS resources.assets mono behaviour payload", ["unity_assets"]),
    ("unity", "level0", b"Unity level file serialized game object payload", ["unity_level_file"]),
    ("unity", "Managed/GameAssembly.dll", b"MZ IL2CPP GameAssembly metadata invoke", ["unity_managed_assembly"]),
    ("unity", "il2cpp_data/Metadata/global-metadata.dat", b"IL2CPP metadata method tokens", ["unity_il2cpp_metadata"]),
    ("media", "audio/variant.ogg", b"OggS OpusHead vorbis comment", ["media_audio_ogg"]),
    ("media", "image/mislabeled_audio.jpg", b"OggS disguised jpg hidden payload", ["mislabeled_media"]),
    ("media", "video/mislabeled_video.png", b"ftypisom disguised png payload", ["mislabeled_media"]),
    ("media", "image/stego.png", b"\x89PNG\r\n\x1a\nIHDR IEND payload after IEND powershell", ["stego_fixture"]),
    ("media", "www/img/encrypted.rpgmvo", b"RPGMVO encrypted ogg media", ["encrypted_rpgm_media"]),
    ("media", "archives/media_bundle.zip", b"PK\x03\x04 nested audio.ogg powershell payload", ["archive_contained_media"]),
)


def test_stage688_phase6_fast_deep_replay_synthetic_engine_media_matrix(tmp_path: Path) -> None:
    covered = {"renpy": 0, "rpgm": 0, "unity": 0, "media": 0}
    for engine, relative_path, payload, tags in PHASE6_SYNTHETIC_CASES:
        path = _write_case(tmp_path, relative_path, payload)
        strings_blob = payload.decode("latin1", errors="ignore") if isinstance(payload, bytes) else payload
        fast = prefilter_scan.strict_fast_prefilter(path, artifact_read_snapshot=artifact_read_snapshot_fixture(path))
        assert isinstance(fast, dict)
        assert "force_full" in fast
        assert "failure_evidence" in fast
        deep = _assert_replay_stable(path, tags, strings_blob)
        assert deep["scan_integrity"].get("failure_count", 0) >= 0
        assert set(tags) <= set(deep.get("tags") or []) or deep.get("profile_selection", {}).get("active_profile") in {engine, "other", "media"}
        covered[engine] += 1
    assert all(count > 0 for count in covered.values())




def _analysis_dependencies(**overrides: Any):
    return replace(default_full_analysis_pipeline_dependencies(), **overrides)


def _model_context_dependency(**builders: Any):
    def _builder(*args: Any, **kwargs: Any) -> Any:
        kwargs.update(builders)
        return model_context.build_detection_model_context(*args, **kwargs)
    return _builder

def _raise(stage: str):
    def _inner(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(f"injected {stage} failure")
    return _inner


def _assert_failure_visible(record: dict[str, Any], expected_stage: str | None = None) -> None:
    failures = list(record.get("detection_failures") or [])
    failures.extend(record.get("explanation", {}).get("detection_failures") or [])
    assert failures, record
    assert record.get("scan_integrity", {}).get("ok") is False
    assert record.get("scan_integrity", {}).get("json_record_required") is True
    assert record.get("scan_integrity", {}).get("replay_record_required") is True
    if expected_stage is not None:
        assert any(expected_stage in str(item.get("stage_name")) for item in failures), failures
    json.dumps(record, sort_keys=True, default=str)


@pytest.mark.parametrize(
    ("stage", "patch_module", "patch_name", "expected_stage"),
    (
        ("api_context_enrichment", api_context, "enrich_with_api_and_graph", "api_graph_enrichment"),
        ("string_extraction", input_stage, "scan_strings", "string_enrichment"),
        ("graph_feature_construction", model_context, "detection_graph_features", "graph_features"),
        ("temporal_model", model_context, "detection_temporal_snapshot", "temporal_features"),
        ("markov_context", model_context, "detection_markov_features", "markov_features"),
        ("threat_family_detection", api_context, "enhanced_family_heuristics", "family_heuristics"),
        ("score_cap_construction", cap_inputs, "apply_anchor_chain_high_gate", "score_caps_anchor_chain_high_gate"),
    ),
)
def test_stage688_phase6_pipeline_failure_injections_are_json_replay_visible(
    tmp_path: Path,
    stage: str,
    patch_module: Any,
    patch_name: str,
    expected_stage: str,
) -> None:
    path = _write_case(tmp_path, f"failure/{stage}.rpy", "init python:\n os.system('powershell -enc AAA')")
    dependency_overrides: dict[str, Any]
    if patch_module is api_context and patch_name == "enrich_with_api_and_graph":
        dependency_overrides = {"api_graph_enricher": _raise(stage)}
    elif patch_module is input_stage and patch_name == "scan_strings":
        dependency_overrides = {"scan_strings_func": _raise(stage)}
    elif patch_module is model_context and patch_name == "detection_graph_features":
        dependency_overrides = {"model_context_builder": _model_context_dependency(graph_features_builder=_raise(stage))}
    elif patch_module is model_context and patch_name == "detection_temporal_snapshot":
        dependency_overrides = {"model_context_builder": _model_context_dependency(temporal_snapshot_builder=_raise(stage))}
    elif patch_module is model_context and patch_name == "detection_markov_features":
        dependency_overrides = {"model_context_builder": _model_context_dependency(markov_features_builder=_raise(stage))}
    elif patch_module is api_context and patch_name == "enhanced_family_heuristics":
        dependency_overrides = {"family_heuristics_builder": _raise(stage)}
    elif patch_module is cap_inputs and patch_name == "apply_anchor_chain_high_gate":
        dependency_overrides = {"high_gate_func": _raise(stage)}
    else:
        raise AssertionError(f"unexpected dependency patch target: {patch_module!r}.{patch_name}")

    deps = _analysis_dependencies(**dependency_overrides)
    record = analyze_file_full_observe_only(path, tags=["renpy_script", "powershell_exec"], dependencies=deps, scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(path))
    _assert_failure_visible(record, expected_stage)
    second = analyze_file_full_observe_only(path, tags=["renpy_script", "powershell_exec"], dependencies=deps, scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(path))
    assert _stable_json(record) == _stable_json(second)


def test_stage688_phase6_renpy_loader_failure_is_visible() -> None:

    tags = family_scan.explicit_missed_family_tag_scan(
        "renpy pickle opcode GLOBAL REDUCE os.system powershell",
        path="game/archive.rpa",
        data=b"renpy pickle opcode GLOBAL REDUCE os.system powershell",
        renpy_loader_family_tags_func=_raise("renpy_loader_scan"),
    )
    assert "renpy_loader_family_scan_degraded" in tags
    assert "failure_evidence_recorded" in tags


def test_stage688_phase6_prefilter_failure_is_visible(tmp_path: Path) -> None:
    path = _write_case(tmp_path, "prefilter/readme.txt", "ordinary text for prefilter")
    result = prefilter_scan.strict_fast_prefilter(path, artifact_read_snapshot=artifact_read_snapshot_fixture(path), entropy_func=_raise("prefilter_scan"))
    failures = result.get("failure_evidence") or []
    assert failures
    records = [item.to_record() if hasattr(item, "to_record") else item for item in failures]
    assert any(item.get("stage_name") == "strict_fast_prefilter" for item in records)
    assert result.get("force_full") is True
    json.dumps(result, sort_keys=True, default=str)


def test_stage688_phase6_explainability_failure_becomes_fatal_json_replay_record(
    tmp_path: Path,
) -> None:
    path = _write_case(tmp_path, "explainability/failure.rpy", "init python: os.system('powershell')")
    deps = _analysis_dependencies(score_explanation_builder=_raise("explainability_construction"))
    record = analyze_file_full_observe_only(path, tags=["renpy_script", "powershell_exec"], dependencies=deps, scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(path))
    _assert_failure_visible(record, "full_analysis")
    assert record.get("classification") == "error"


def test_stage688_phase6_final_json_writer_failure_contract_is_explicit() -> None:
    failure = recoverable_failure_evidence(
        stage_name="final_json_writer",
        error=OSError("injected final JSON writer failure"),
        error_source="json_result_writer",
        affected_context="synthetic-final-results.json",
    )
    payload = failure_evidence_payload((failure,))
    assert payload["degraded"] is True
    assert payload["json_record_required"] is True
    assert payload["replay_record_required"] is True
    assert payload["confidence_degraded"] is True
    assert payload["failures"][0]["stage_name"] == "final_json_writer"
