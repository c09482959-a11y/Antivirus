from __future__ import annotations

import inspect

from Virus_Scan.tests import conftest as test_conftest


def test_stage2123_source_scan_pressure_is_session_bounded_without_interval_parse_thrash() -> None:
    pressure_source = inspect.getsource(test_conftest.bound_cumulative_source_scan_cache_pressure)
    sessionfinish_source = inspect.getsource(test_conftest.pytest_sessionfinish)

    assert "session-finish hook remains the" in pressure_source
    assert "_clear_bounded_source_scan_caches()" not in pressure_source
    assert "_release_test_source_scan_cache_registry()" in sessionfinish_source
