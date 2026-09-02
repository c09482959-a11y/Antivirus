from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.routing.scanner_execution_plan import (
    SCANNER_EXECUTION_CAPABILITY_REGISTRY,
    ScannerExecutionPlan,
    build_scanner_execution_plan,
    scanner_execution_capability_registry_digest,
    scanner_execution_capability_registry_record,
)
from Virus_Scan.routing.magic import sniff_file_identity_from_snapshot
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.utils.stages import choose_effective_stage, normalize_stage


def _plan(target: Path, *, identity: dict[str, object] | None = None, disabled: tuple[str, ...] = (), unavailable: tuple[str, ...] = ()) -> ScannerExecutionPlan:
    snapshot = build_artifact_read_snapshot(target)
    owned_identity = sniff_file_identity_from_snapshot(target, snapshot) if identity is None else identity
    ext_stage = normalize_stage(snapshot.extension)
    effective_stage = choose_effective_stage(ext_stage, owned_identity)
    return build_scanner_execution_plan(
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=snapshot,
        extension=snapshot.extension,
        effective_stage=effective_stage,
        identity=owned_identity,
        archive_depth=0,
        disabled_scanners=disabled,
        unavailable_scanners=unavailable,
    )


def test_phase10_registry_is_complete_immutable_and_digest_stable() -> None:
    expected = {
        "archive_graph",
        "asset_string",
        "batch_cmd_static_analysis",
        "binary_embedded_pickle",
        "binary_static",
        "csharp_graph",
        "dotnet_il_static_analysis",
        "font_asset",
        "generic_archive",
        "image_static",
        "image_string",
        "javascript_typescript_static_analysis",
        "media_asset",
        "native_elf_x86_64_static_analysis",
        "other_string",
        "pickle_embedded_payload",
        "powershell_static_analysis",
        "python_renpy_static_analysis",
        "rpa_archive",
        "runtime_context",
        "runtime_decoded",
        "shell_static_analysis",
        "unity_asset",
    }

    assert set(SCANNER_EXECUTION_CAPABILITY_REGISTRY) == expected
    assert scanner_execution_capability_registry_digest() == scanner_execution_capability_registry_digest()
    record = scanner_execution_capability_registry_record()
    assert record["registry_digest"] == scanner_execution_capability_registry_digest()
    assert len(record["capabilities"]) == len(expected)
    for capability in SCANNER_EXECUTION_CAPABILITY_REGISTRY.values():
        assert capability.required_views
        assert capability.expected_observation_families
        assert capability.cache_dependencies
        assert capability.cost_class in {"low", "medium", "high"}
        assert capability.concurrency_class in {"inline", "intrastage", "external_session"}
        assert capability.modality in {"static_control_flow", "static_string", "static_structure", "verified_rule_match"}
    with pytest.raises(TypeError):
        SCANNER_EXECUTION_CAPABILITY_REGISTRY["new"] = SCANNER_EXECUTION_CAPABILITY_REGISTRY["binary_static"]  # type: ignore[index]


def test_phase10_binary_plan_selects_only_binary_scanner_families(tmp_path: Path) -> None:
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 512)

    plan = _plan(target)

    assert plan.decision("binary_static").plan_status == "selected"
    assert plan.decision("binary_embedded_pickle").plan_status == "selected"
    assert plan.decision("dotnet_il_static_analysis").plan_status == "selected"
    assert plan.decision("image_static").outcome_status == "not_applicable"
    assert plan.decision("runtime_context").outcome_status == "not_applicable"
    assert plan.decision("other_string").outcome_status == "not_applicable"


def test_phase10_magic_overrides_extension_before_applicability(tmp_path: Path) -> None:
    target = tmp_path / "misnamed.txt"
    target.write_bytes(b"MZ" + b"\x00" * 512)

    plan = _plan(target)

    assert plan.effective_stage == "binary"
    assert plan.decision("binary_static").plan_status == "selected"
    assert plan.decision("asset_string").plan_status == "not_applicable"


def test_phase10_rpa_and_generic_archive_are_mutually_exclusive(tmp_path: Path) -> None:
    target = tmp_path / "archive.rpa"
    target.write_bytes(b"RPA-3.0 0000000000000000 00000000\n")
    identity = {
        "magic_type": "renpy_rpa",
        "actual_category": "archive",
        "magic_stage": "archive",
        "confidence": 1.0,
        "tags": (),
    }

    plan = _plan(target, identity=identity)

    assert plan.decision("archive_graph").plan_status == "selected"
    assert plan.decision("rpa_archive").plan_status == "selected"
    assert plan.decision("generic_archive").plan_status == "not_applicable"
    assert plan.decision("generic_archive").plan_reason == "identity_explicitly_excluded"


def test_phase10_runtime_plan_marks_context_and_decoded_collectors(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text("print('hello')\n", encoding="utf-8")

    plan = _plan(target)

    assert plan.effective_stage == "runtime"
    assert plan.decision("python_renpy_static_analysis").plan_status == "selected"
    assert plan.decision("runtime_context").plan_status == "selected"
    assert plan.decision("runtime_decoded").plan_status == "selected"
    assert plan.decision("binary_static").outcome_status == "not_applicable"
    assert plan.decision("image_static").outcome_status == "not_applicable"


def test_phase10_powershell_plan_selects_only_its_static_frontend(tmp_path: Path) -> None:
    target = tmp_path / "sample.ps1"
    target.write_text("Write-Output 'hello'\n", encoding="utf-8")

    plan = _plan(target)

    assert plan.effective_stage == "runtime"
    assert plan.decision("powershell_static_analysis").plan_status == "selected"
    assert plan.decision("python_renpy_static_analysis").outcome_status == "not_applicable"


def test_phase10_conditional_string_scanners_are_explicit(tmp_path: Path) -> None:
    image = tmp_path / "sample.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 128)
    media = tmp_path / "sample.mp3"
    media.write_bytes(b"ID3" + b"\x00" * 128)

    image_plan = _plan(image)
    media_plan = _plan(media)

    assert image_plan.decision("image_static").plan_status == "selected"
    assert image_plan.decision("image_string").plan_status == "conditional"
    assert media_plan.decision("media_asset").plan_status == "selected"
    assert media_plan.decision("asset_string").plan_status == "conditional"


def test_phase10_disabled_and_unavailable_are_non_error_plan_outcomes(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text("print('hello')\n", encoding="utf-8")

    plan = _plan(
        target,
        disabled=("runtime_context",),
        unavailable=("runtime_decoded",),
    )

    assert plan.decision("runtime_context").plan_status == "disabled"
    assert plan.decision("runtime_context").outcome_status == "disabled"
    assert plan.decision("runtime_decoded").plan_status == "unavailable"
    assert plan.decision("runtime_decoded").outcome_status == "unavailable"
    with pytest.raises(ValueError, match="scanner_plan_unknown_scanner"):
        _plan(target, disabled=("not_registered",))


def test_phase10_missing_artifact_marks_applicable_scanners_unavailable(tmp_path: Path) -> None:
    target = tmp_path / "missing.py"
    snapshot = build_artifact_read_snapshot(target)

    plan = build_scanner_execution_plan(
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=snapshot,
        extension=".py",
        effective_stage="runtime",
        identity={"magic_type": "", "actual_category": ""},
        archive_depth=0,
    )

    assert plan.decision("runtime_context").plan_status == "unavailable"
    assert plan.decision("runtime_context").outcome_status == "unavailable"
    assert plan.decision("binary_static").outcome_status == "not_applicable"


def test_phase10_router_publishes_complete_explicit_plan_without_pending_scanners(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text("print('phase10')\n", encoding="utf-8")
    snapshot = build_artifact_read_snapshot(target)

    outcome = scan_file_by_type(
        str(target),
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=snapshot,
    )
    identity = route_identity_record(outcome.identity)

    assert identity is not None
    plan = identity["scanner_execution_plan"]
    assert plan["schema_version"] == "scanner_execution_plan_v2"
    assert plan["content_sha256"] == snapshot.content_sha256
    decisions = {item["scanner_id"]: item for item in plan["decisions"]}
    assert decisions["python_renpy_static_analysis"]["outcome_status"] in {
        "complete_no_observation",
        "complete_with_observation",
        "partial",
        "truncated",
        "unavailable",
        "failed",
    }
    assert decisions["runtime_context"]["outcome_status"] in {
        "complete_no_observation",
        "complete_with_observation",
        "partial",
        "truncated",
        "unavailable",
        "failed",
    }
    assert decisions["runtime_decoded"]["outcome_status"] != "pending"
    assert all(item["outcome_status"] != "pending" for item in decisions.values())
    assert "scanner_execution_plan_incomplete" not in outcome.tags


def test_phase10_missing_route_publishes_unavailable_plan(tmp_path: Path) -> None:
    target = tmp_path / "missing.py"
    snapshot = build_artifact_read_snapshot(target)

    outcome = scan_file_by_type(
        str(target),
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=snapshot,
    )
    identity = route_identity_record(outcome.identity)

    assert identity is not None
    decisions = {
        item["scanner_id"]: item
        for item in identity["scanner_execution_plan"]["decisions"]
    }
    assert decisions["runtime_context"]["outcome_status"] == "unavailable"
    assert decisions["runtime_decoded"]["outcome_status"] == "unavailable"
    assert "missing_file" in outcome.tags


def test_phase10_javascript_typescript_plan_selects_single_static_frontend(tmp_path: Path) -> None:
    target = tmp_path / "sample.ts"
    target.write_text("const value: string = 'safe';\n", encoding="utf-8")
    plan = _plan(target)
    assert plan.decision("javascript_typescript_static_analysis").plan_status == "selected"
    assert plan.decision("powershell_static_analysis").outcome_status == "not_applicable"
    assert plan.decision("batch_cmd_static_analysis").outcome_status == "not_applicable"
    assert plan.decision("shell_static_analysis").outcome_status == "not_applicable"
    assert plan.decision("dotnet_il_static_analysis").outcome_status == "not_applicable"
    assert plan.decision("python_renpy_static_analysis").outcome_status == "not_applicable"
