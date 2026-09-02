from pathlib import Path
import tempfile

from Virus_Scan.orchestration.bootstrap_initialization import initialize_runtime
from Virus_Scan.runtime import scan_dependencies as deps
from Virus_Scan.runtime.scan_dependencies import ScanDependencyRegistry
from Virus_Scan.routing.engine_detect import detect_target_engine_context as routing_engine_context


def test_runtime_dependency_registry_has_no_superseded_yara_cache_port():
    registry = ScanDependencyRegistry()
    assert not hasattr(registry, "yara_cache_provider")
    assert not hasattr(deps, "call_yara_cache_provider")


def test_runtime_dependency_providers_are_bootstrap_owned_in_fresh_process():
    state = initialize_runtime()
    registry = ScanDependencyRegistry()
    registry.set_single("engine_context_detector", routing_engine_context)
    with tempfile.TemporaryDirectory() as scan_root:
        Path(scan_root, "sample.txt").write_text("plain", encoding="utf-8")
        context = deps.detect_target_engine_context(scan_root, registry=registry)
    assert bool(state.get("BOOTSTRAP_DEPENDENCY_PROVIDERS_REGISTERED")) is True
    assert sorted(context) == ["media", "renpy", "rpgm", "unity", "unknown"]
    assert not hasattr(deps, "register_yara_cache_provider")
