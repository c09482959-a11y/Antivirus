from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.runtime_platform_identity import (
    RuntimePlatformIdentity,
    runtime_platform_target_key,
    supported_runtime_target_keys,
)
from Virus_Scan.routing import scanner_execution_plan as execution_plan_module
from Virus_Scan.routing.magic import sniff_file_identity_from_snapshot
from Virus_Scan.routing.scanner_execution_plan import (
    SCANNER_EXECUTION_CAPABILITY_REGISTRY,
    SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION,
    SCANNER_EXECUTION_PLAN_SCHEMA_VERSION,
    ScannerExecutionCapability,
    build_scanner_execution_plan,
    scanner_execution_capability_registry_digest,
)
from Virus_Scan.scanners.static_program_analysis.frontend_registry import (
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    STATIC_PROGRAM_ANALYSIS_FRONTENDS,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
)
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.utils.stages import choose_effective_stage, normalize_stage


_ROUTING_ROOT = Path(__file__).resolve().parents[1] / "routing"
_ROUTING_EXECUTION_SOURCES = (
    _ROUTING_ROOT / "extension_scan_router.py",
    _ROUTING_ROOT / "extension_scan_handlers.py",
)


def _literal_execution_scanner_ids(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    scanner_ids: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"allows", "decision", "with_outcome"} or not node.args:
            continue
        scanner_id = node.args[0]
        if isinstance(scanner_id, ast.Constant) and type(scanner_id.value) is str:
            scanner_ids.add(scanner_id.value)
    return scanner_ids


def _plan_for(
    target: Path,
    *,
    archive_depth: int = 0,
    runtime_platform: RuntimePlatformIdentity | None = None,
):
    snapshot = build_artifact_read_snapshot(target)
    identity = sniff_file_identity_from_snapshot(target, snapshot)
    stage = choose_effective_stage(normalize_stage(snapshot.extension), identity)
    session = scan_session_snapshot_fixture(runtime_platform_override=runtime_platform)
    plan = build_scanner_execution_plan(
        scan_session_snapshot=session,
        artifact_read_snapshot=snapshot,
        extension=snapshot.extension,
        effective_stage=stage,
        identity=identity,
        archive_depth=archive_depth,
    )
    return session, snapshot, plan


def _platform(
    *, operating_system: str, architecture: str, abi: str, binary_format: str,
) -> RuntimePlatformIdentity:
    return RuntimePlatformIdentity(
        operating_system=operating_system,
        architecture=architecture,
        abi=abi,
        binary_format=binary_format,
        python_implementation="cpython",
        python_version="3.13.5",
        python_abi="cpython-313-test",
        byteorder="little",
        pointer_bits=64,
    )


def test_phase14_execution_registry_exactly_covers_reachable_scanner_families() -> None:
    literal_ids: set[str] = set()
    for source in _ROUTING_EXECUTION_SOURCES:
        literal_ids.update(_literal_execution_scanner_ids(source))
    static_ids = {frontend.scanner_id for frontend in STATIC_PROGRAM_ANALYSIS_FRONTENDS}
    reachable_ids = literal_ids | static_ids

    assert len(reachable_ids) == 23
    assert reachable_ids == set(SCANNER_EXECUTION_CAPABILITY_REGISTRY)
    assert len(SCANNER_EXECUTION_CAPABILITY_REGISTRY) == 23


def test_phase14_execution_registry_has_one_unambiguous_current_owner() -> None:
    assert SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION == (
        "scanner_execution_capability_registry_v2"
    )
    assert SCANNER_EXECUTION_PLAN_SCHEMA_VERSION == "scanner_execution_plan_v2"
    assert not hasattr(execution_plan_module, "SCANNER_CAPABILITY_REGISTRY")
    assert not hasattr(execution_plan_module, "ScannerCapability")
    assert not hasattr(execution_plan_module, "scanner_capability_registry_digest")
    assert all(
        type(capability) is ScannerExecutionCapability
        for capability in SCANNER_EXECUTION_CAPABILITY_REGISTRY.values()
    )


def test_phase14_static_frontend_registry_owns_selectors_limits_and_frontend_identity() -> None:
    assert STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION == (
        "static_program_analysis_parser_registry_v13"
    )
    for scanner_id, frontend in STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID.items():
        capability = SCANNER_EXECUTION_CAPABILITY_REGISTRY[scanner_id]
        assert capability.accepted_extensions == frontend.extensions
        assert capability.accepted_magic_types == frontend.magic_types
        assert capability.maximum_size_bytes == frontend.maximum_source_bytes
        assert "static_frontend:" + frontend.frontend_digest in capability.cache_dependencies


def test_phase14_all_execution_capabilities_bind_declared_first_class_runtime_targets() -> None:
    expected = supported_runtime_target_keys()
    assert expected == (
        "linux|x86_64|manylinux_2_17_x86_64|elf",
        "windows|x86_64|win_amd64|pe",
    )
    for capability in SCANNER_EXECUTION_CAPABILITY_REGISTRY.values():
        assert capability.supported_runtime_targets == expected


def test_phase14_plan_is_bound_to_frozen_session_generation_and_runtime_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "sample.py"
    target.write_text("print('safe')\n", encoding="utf-8")

    session, snapshot, plan = _plan_for(target)

    assert plan.session_generation_id == session.generation_id
    assert plan.runtime_target_key == runtime_platform_target_key(session.runtime_platform)
    assert plan.content_sha256 == snapshot.content_sha256
    assert plan.registry_digest == scanner_execution_capability_registry_digest()
    assert plan.archive_depth == 0


def test_phase14_oversized_python_is_applicable_but_unavailable_before_parser_execution(
    tmp_path: Path,
) -> None:
    frontend = STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID[
        "python_renpy_static_analysis"
    ]
    target = tmp_path / "oversized.py"
    target.write_bytes(b"#" * (frontend.maximum_source_bytes + 1))

    _session, _snapshot, plan = _plan_for(target)
    decision = plan.decision("python_renpy_static_analysis")

    assert decision.plan_status == "unavailable"
    assert decision.plan_reason == "artifact_size_limit_exceeded"
    assert decision.outcome_status == "unavailable"
    assert decision.outcome_reason == "artifact_size_limit_exceeded"
    assert plan.decision("runtime_context").plan_status == "selected"
    assert plan.decision("runtime_decoded").plan_status == "selected"


def test_phase14_archive_depth_limit_is_executable_applicability_policy(tmp_path: Path) -> None:
    target = tmp_path / "nested.zip"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 128)
    session = scan_session_snapshot_fixture()
    snapshot = build_artifact_read_snapshot(target)
    plan = build_scanner_execution_plan(
        scan_session_snapshot=session,
        artifact_read_snapshot=snapshot,
        extension=".zip",
        effective_stage="archive",
        identity={"magic_type": "zip", "actual_category": "archive"},
        archive_depth=9,
    )

    for scanner_id in ("archive_graph", "generic_archive"):
        decision = plan.decision(scanner_id)
        assert decision.plan_status == "unavailable"
        assert decision.plan_reason == "archive_nesting_limit_exceeded"
        assert decision.outcome_status == "unavailable"


def test_phase14_supported_windows_uses_same_execution_registry_without_degraded_path(
    tmp_path: Path,
) -> None:
    windows = _platform(
        operating_system="windows",
        architecture="x86_64",
        abi="win_amd64",
        binary_format="pe",
    )
    target = tmp_path / "windows_scan.py"
    target.write_text("print('safe')\n", encoding="utf-8")

    _session, _snapshot, plan = _plan_for(target, runtime_platform=windows)

    assert plan.runtime_target_key == "windows|x86_64|win_amd64|pe"
    assert plan.decision("python_renpy_static_analysis").plan_status == "selected"
    assert plan.decision("runtime_context").plan_status == "selected"
    assert plan.decision("runtime_decoded").plan_status == "selected"


def test_phase14_undeclared_runtime_target_fails_closed_as_unavailable_not_negative(
    tmp_path: Path,
) -> None:
    undeclared = _platform(
        operating_system="macos",
        architecture="aarch64",
        abi="unsupported",
        binary_format="macho",
    )
    target = tmp_path / "unsupported_host.py"
    target.write_text("print('safe')\n", encoding="utf-8")

    _session, _snapshot, plan = _plan_for(target, runtime_platform=undeclared)

    assert plan.runtime_target_key == "macos|aarch64|unsupported|macho"
    for scanner_id in (
        "python_renpy_static_analysis",
        "runtime_context",
        "runtime_decoded",
    ):
        decision = plan.decision(scanner_id)
        assert decision.plan_status == "unavailable"
        assert decision.plan_reason == "runtime_target_unsupported"
        assert decision.outcome_status == "unavailable"


def test_phase14_planner_rejects_stale_session_registry_identity(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    snapshot = build_artifact_read_snapshot(target)
    identity = sniff_file_identity_from_snapshot(target, snapshot)
    stage = choose_effective_stage(normalize_stage(snapshot.extension), identity)
    session = scan_session_snapshot_fixture()

    # A different runtime object is not enough to manufacture a valid stale session generation;
    # the planner must accept the exact canonical ScanSessionSnapshot type and current digest.
    with pytest.raises(TypeError, match="scanner_plan_scan_session_snapshot_required"):
        build_scanner_execution_plan(
            scan_session_snapshot=session.to_record(),
            artifact_read_snapshot=snapshot,
            extension=snapshot.extension,
            effective_stage=stage,
            identity=identity,
            archive_depth=0,
        )
