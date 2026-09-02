"""Stage 952 repository-wide test-audit coverage for root entrypoint contracts.

These tests lock real package-level public behavior after inspecting the
root modules and their canonical owners. They cover package-level surfaces named
by the repository-wide audit command without adding production shims or changing
runtime behavior.
"""
from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.dotnet as root_dotnet
import Virus_Scan.engine_route as engine_route
import Virus_Scan.engine_routing as engine_routing
import Virus_Scan.exception_contracts as exception_contracts
import Virus_Scan.stego as root_stego
from Virus_Scan.scanners.api import dotnet_contracts
from Virus_Scan.scanners.api import image_contracts
from Virus_Scan.utils import media_stego


ROOT_STATIC_ENTRYPOINTS = (
    "Virus_Scan/dotnet.py",
    "Virus_Scan/stego.py",
    "Virus_Scan/engine_route.py",
    "Virus_Scan/engine_routing.py",
    "Virus_Scan/persistence.py",
)


def _module_ast(relative_path: str) -> ast.Module:
    source = Path(relative_path).read_text(encoding="utf-8")
    return ast.parse(source, filename=relative_path)


def test_stage952_root_static_entrypoints_do_not_use_dynamic_or_function_scope_imports():
    """Root package entrypoints remain static public-contract surfaces."""
    for relative_path in ROOT_STATIC_ENTRYPOINTS:
        module = _module_ast(relative_path)
        for node in ast.walk(module):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                assert isinstance(getattr(node, "parent", None), ast.Module) or node in module.body
            if isinstance(node, ast.Call):
                called = node.func
                assert not (
                    isinstance(called, ast.Name) and called.id == "__import__"
                ), f"dynamic __import__ call in {relative_path}:{node.lineno}"
                assert not (
                    isinstance(called, ast.Attribute)
                    and isinstance(called.value, ast.Name)
                    and called.value.id == "importlib"
                ), f"importlib runtime load in {relative_path}:{node.lineno}"


def test_stage952_exception_contracts_do_not_capture_fatal_base_exits():
    """Recoverable exception tuples must not erase process-control failures."""
    fatal = {BaseException, SystemExit, KeyboardInterrupt, GeneratorExit, MemoryError}
    for name in (
        "RECOVERABLE_RUNTIME_ERRORS",
        "IO_CONFIGURATION_ERRORS",
        "TELEMETRY_FAILURE_ERRORS",
        "SCAN_CONTENT_ERRORS",
    ):
        contract = tuple(getattr(exception_contracts, name))
        assert contract
        assert not any(exc in fatal for exc in contract), name
        assert all(issubclass(exc, Exception) for exc in contract), name

    assert set(exception_contracts.IO_CONFIGURATION_ERRORS).issubset(
        set(exception_contracts.SCAN_CONTENT_ERRORS)
    )
    assert RuntimeError in exception_contracts.RECOVERABLE_RUNTIME_ERRORS
    assert SyntaxError in exception_contracts.SCAN_CONTENT_ERRORS


def test_stage952_engine_route_and_engine_routing_publish_identical_canonical_surface():
    """Both root routing aliases must point at the same canonical objects."""
    assert tuple(engine_route.__all__) == tuple(engine_routing.__all__)
    required = {
        "build_baseline_route",
        "resolve_scan_engine_hint",
        "sniff_file_identity",
        "artifact_engine_from_identity",
        "MagicRouter",
    }
    assert required.issubset(set(engine_route.__all__))

    for name in required:
        assert getattr(engine_route, name) is getattr(engine_routing, name)


def test_stage952_root_dotnet_contract_delegates_to_scanner_api_and_preserves_behavior():
    """The package-level .NET entrypoint is the scanner-owned public contract."""
    assert root_dotnet.scan_unity_dotnet_layered_file is dotnet_contracts.scan_unity_dotnet_layered_file
    assert root_dotnet.unity_ilspy_should_run is dotnet_contracts.unity_ilspy_should_run
    assert root_dotnet.dotnet_metadata_present("MScoree.dll #Strings Assembly.Load") is True
    assert root_dotnet.dotnet_extension_tags(".bytes") == [
        "extension_mismatch",
        "binary_failover_dotnet_metadata",
    ]
    assert {"assembly_load", "network_download", "process_exec"}.issubset(
        set(root_dotnet.dotnet_behavior_tags("Assembly.Load WebClient Process.Start"))
    )


def test_stage952_root_stego_contract_delegates_to_image_api_and_returns_policy_copy():
    """The package-level stego entrypoint preserves scanner/media-owned helpers."""
    assert root_stego.scan_image_file is image_contracts.scan_image_file
    assert root_stego.scan_image_stego is image_contracts.scan_image_stego
    assert root_stego.bits_to_bytes([0, 1, 0, 0, 0, 0, 0, 1]) == b"A"
    assert root_stego.image_is_jpeg(data=b"\xff\xd8\xffrest") is True

    policy = root_stego.canonical_stego_tag_rewrite_map()
    policy["possible_lsb_stego"] = "mutated_in_test"
    assert media_stego.canonical_stego_tag_rewrite_map()["possible_lsb_stego"] == (
        "weak_image_stego_observation"
    )
