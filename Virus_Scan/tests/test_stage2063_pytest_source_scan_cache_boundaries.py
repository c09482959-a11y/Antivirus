from __future__ import annotations

import inspect
from pathlib import Path

from Virus_Scan.tests import conftest as test_conftest
from Virus_Scan.tests.support import static_inventory


def test_stage2063_static_inventory_clear_covers_all_source_scan_caches() -> None:
    source = inspect.getsource(static_inventory.clear_static_inventory_cache)

    assert "from_imported_names.cache_clear()" in source
    assert "bare_or_broad_exception_findings.cache_clear()" in source


def test_stage2063_full_suite_source_scan_uses_explicit_static_inventory_not_path_monkeypatch() -> None:
    conftest_source = inspect.getsource(test_conftest)
    fixture_source = inspect.getsource(test_conftest.keep_test_source_scan_caches_session_bounded)

    assert "Path.read_text =" not in conftest_source
    assert "cache lifetime is safely bounded by" in fixture_source
    assert "_clear_test_source_scan_caches_for_module" not in fixture_source


def test_stage2063_sessionfinish_releases_static_inventory_without_module_graph_rescan() -> None:
    sessionfinish_source = inspect.getsource(test_conftest.pytest_sessionfinish)

    assert "_release_test_source_scan_cache_registry()" in sessionfinish_source
    assert "_clear_test_source_scan_caches()" not in sessionfinish_source

def test_stage2063_full_suite_disables_unused_third_party_reporting_plugins() -> None:
    pytest_ini = Path("pytest.ini").read_text(encoding="utf-8")

    assert "-p no:pytest_jsonreport" in pytest_ini
    assert "-p no:faker" in pytest_ini
    assert "-p no:pytest_asyncio" in pytest_ini
    assert "-p no:asyncio" in pytest_ini
    assert "-p no:anyio" in pytest_ini
