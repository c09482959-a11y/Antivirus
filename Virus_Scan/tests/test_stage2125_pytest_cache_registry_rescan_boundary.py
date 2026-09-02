from __future__ import annotations

import inspect

from Virus_Scan.tests import conftest as test_conftest


def test_stage2125_bounded_cache_fixture_does_not_scan_or_clear_per_test() -> None:
    pressure_source = inspect.getsource(test_conftest.bound_cumulative_source_scan_cache_pressure)
    sessionfinish_source = inspect.getsource(test_conftest.pytest_sessionfinish)

    assert "yield" in pressure_source
    assert "_clear_bounded_source_scan_caches()" not in pressure_source
    assert "for module_name, module in tuple(sys.modules.items())" not in pressure_source
    assert "_release_test_source_scan_cache_registry()" in sessionfinish_source


def test_stage2125_cache_registry_still_has_explicit_session_release_owner() -> None:
    release_source = inspect.getsource(test_conftest._release_test_source_scan_cache_registry)
    collection_finish_source = inspect.getsource(test_conftest.pytest_collection_finish)

    assert "_refresh_test_source_scan_cache_clearers()" in collection_finish_source
    assert "_TEST_SOURCE_CACHE_CLEARERS = ()" in release_source
    assert "_TEST_SOURCE_CACHE_MODULES = frozenset()" in release_source
    assert "_TEST_SOURCE_CACHE_REGISTRY_REFRESHED = False" in release_source


def test_stage2125_scheduler_helper_cleanup_is_interval_bounded() -> None:
    fixture_source = inspect.getsource(test_conftest.reset_scheduler_multiprocessing_helpers)
    due_source = inspect.getsource(test_conftest._scheduler_helper_cleanup_due)

    assert "_SCHEDULER_HELPER_CLEANUP_INTERVAL" in due_source
    assert "_scheduler_helper_cleanup_due()" in fixture_source
    assert "per-test wait amplification" in fixture_source


def test_stage2125_scan_integrity_fixture_uses_session_state_clear_boundary() -> None:
    fixture_source = inspect.getsource(test_conftest.explicit_runtime_scan_integrity_state)

    assert "_TEST_SCAN_INTEGRITY_STATE.clear_all()" in fixture_source
    assert "session-owned state" in fixture_source
    assert "ContextVar" in fixture_source
