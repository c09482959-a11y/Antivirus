from __future__ import annotations

import inspect

from Virus_Scan.tests import conftest as test_conftest
from Virus_Scan.tests import test_stage1764_phase12_architecture_regressions as stage1764_architecture
from Virus_Scan.tests.support import static_inventory


def test_stage2067_module_mutable_guard_uses_cached_static_inventory_helper() -> None:
    guard_source = inspect.getsource(
        stage1764_architecture.test_stage1764_architecture_forbids_raw_module_policy_mutables
    )
    helper_source = inspect.getsource(static_inventory.module_level_mutable_assignment_findings)

    assert "module_level_mutable_assignment_findings(path)" in guard_source
    assert "_production_tree_for(path)" not in guard_source
    assert "_source_needs_module_mutable_ast_scan(source)" in helper_source


def test_stage2067_static_inventory_cache_clear_releases_module_mutable_findings() -> None:
    clear_source = inspect.getsource(static_inventory.clear_static_inventory_cache)

    assert "module_level_mutable_assignment_findings.cache_clear()" in clear_source


def test_stage2067_full_suite_source_scan_caches_are_session_bounded_without_interval_scans() -> None:
    pressure_source = inspect.getsource(test_conftest.bound_cumulative_source_scan_cache_pressure)
    sessionfinish_source = inspect.getsource(test_conftest.pytest_sessionfinish)

    assert "session-finish hook remains the" in pressure_source
    assert "_release_test_source_scan_cache_registry()" in sessionfinish_source

def test_stage2098_source_scan_cache_clear_does_not_force_unbounded_gc_collect() -> None:
    clear_source = inspect.getsource(test_conftest._clear_bounded_source_scan_caches)

    assert "clear_static_inventory_cache()" in clear_source
    assert "_clear_test_source_scan_caches()" in clear_source
    assert "gc.collect" not in clear_source

