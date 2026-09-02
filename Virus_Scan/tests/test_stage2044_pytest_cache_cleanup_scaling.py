from __future__ import annotations

import inspect

from Virus_Scan.tests import conftest as test_conftest
from Virus_Scan.tests import test_stage1764_phase12_architecture_regressions as stage1764_architecture
from Virus_Scan.tests.support import static_inventory
from Virus_Scan.tests import test_stage161_phase3_registration_side_effects as stage161
from Virus_Scan.tests import test_stage1669_detection_text_pathlike_no_hook as stage1669
from Virus_Scan.tests import test_stage1727_scheduler_queue_listdir_failure_evidence as stage1727
from Virus_Scan.tests import test_stage67_architecture as stage67_architecture
from Virus_Scan.tests import test_stage838_scheduler_private_import_public_contracts as stage838
from Virus_Scan.tests import test_stage839_scheduler_duplicate_helper_continuation as stage839
from Virus_Scan.tests import test_stage97_error_handling_forensic_validation as stage97
from Virus_Scan.tests import test_stage993_phase1_json_safe_set_determinism as stage993
from Virus_Scan.tests import test_stage992_phase1_raw_queue_identity_lock_determinism as stage992


def test_stage2044_source_scan_caches_are_session_bounded_not_per_test() -> None:
    fixture_source = inspect.getsource(test_conftest.keep_test_source_scan_caches_session_bounded)
    module_clear_source = inspect.getsource(test_conftest._clear_test_source_scan_caches_for_module)

    assert "os.chdir(REPOSITORY_ROOT)" in fixture_source
    assert "cache lifetime is safely bounded by" in fixture_source
    assert "_clear_test_source_scan_caches_for_module" not in fixture_source
    assert "tuple(vars(module).values())" in module_clear_source
    assert "for module_name, module in tuple(sys.modules.items())" not in fixture_source
    pressure_source = inspect.getsource(test_conftest.bound_cumulative_source_scan_cache_pressure)
    assert "session-finish hook remains the" in pressure_source
    assert "yield" in pressure_source


def test_stage2091_scheduler_multiprocessing_helpers_are_interval_and_session_bounded() -> None:
    fixture_source = inspect.getsource(test_conftest.reset_scheduler_multiprocessing_helpers)
    sessionfinish_source = inspect.getsource(test_conftest.pytest_sessionfinish)

    assert "shutdown_scheduler_multiprocessing_context_runtime()" in fixture_source
    assert "_scheduler_helper_cleanup_due()" in fixture_source
    assert "try:" in fixture_source
    assert "finally:" in fixture_source
    assert "shutdown_scheduler_multiprocessing_context_runtime()" in sessionfinish_source


def test_stage2636_11020_collected_pytest_graph_is_frozen_without_disabling_gc() -> None:
    freeze_source = inspect.getsource(test_conftest._freeze_collected_pytest_object_graph)
    collection_finish_source = inspect.getsource(test_conftest.pytest_collection_finish)
    conftest_source = inspect.getsource(test_conftest)

    assert "gc.freeze()" in freeze_source
    assert "gc.disable()" not in freeze_source
    assert collection_finish_source.index("_refresh_test_source_scan_cache_clearers()") < collection_finish_source.index("_freeze_collected_pytest_object_graph()")
    assert "gc.disable()" not in conftest_source
    assert "gc.unfreeze()" not in conftest_source


def test_stage2044_source_scan_cache_registry_is_released_at_session_finish() -> None:
    sessionfinish_source = inspect.getsource(test_conftest.pytest_sessionfinish)
    release_source = inspect.getsource(test_conftest._release_test_source_scan_cache_registry)

    assert "_release_test_source_scan_cache_registry()" in sessionfinish_source
    assert "_TEST_SOURCE_CACHE_CLEARERS = ()" in release_source
    assert "_TEST_SOURCE_CACHE_MODULES = frozenset()" in release_source


def test_stage2044_cache_clearer_discovery_avoids_hostile_getattr() -> None:
    module_clear_source = inspect.getsource(test_conftest._clear_test_source_scan_caches_for_module)

    assert "type(value) is _TEST_SOURCE_LRU_CACHE_WRAPPER_TYPE" in module_clear_source
    assert 'getattr(value, "cache_clear", None)' not in module_clear_source


def test_stage2044_terminal_summary_returns_exact_exit_status() -> None:
    terminal_summary_source = inspect.getsource(test_conftest.pytest_terminal_summary)
    cleanup_source = inspect.getsource(test_conftest._cleanup_pytest_owned_basetemp)

    assert "@pytest.hookimpl(trylast=True)" in inspect.getsource(test_conftest)
    assert "Stage2044 bounded pytest exit status" in terminal_summary_source
    assert terminal_summary_source.index("_cleanup_pytest_owned_basetemp(config)") < terminal_summary_source.index("os._exit(int(exitstatus))")
    assert "factory._given_basetemp is not None" in cleanup_source
    assert "shutil.rmtree(basetemp, ignore_errors=True)" in cleanup_source


def test_stage2044_stage67_duplicate_policy_guard_filters_before_hashing() -> None:
    source = inspect.getsource(
        stage67_architecture.test_stage67_cross_layer_duplicate_policy_helpers_stay_zero
    )
    name_filter_index = source.index("if node.name not in policy_names:")
    body_hash_index = source.index("hashlib.sha256")

    assert name_filter_index < body_hash_index
    assert "names & policy_names" not in source


def test_stage2044_stage1764_production_ast_scan_reuses_source_backed_cache() -> None:
    source = inspect.getsource(
        stage1764_architecture.test_stage1764_architecture_forbids_raw_module_policy_mutables
    )
    helper_source = inspect.getsource(static_inventory.module_level_mutable_assignment_findings)
    prefilter_source = inspect.getsource(static_inventory._source_needs_module_mutable_ast_scan)
    module_source = inspect.getsource(stage1764_architecture)

    assert "module_level_mutable_assignment_findings(path)" in source
    assert "parse_python_file(path)" in helper_source
    assert "_source_needs_module_mutable_ast_scan(source)" in helper_source
    assert "for line in source.splitlines()" in prefilter_source
    assert "read_python_file(Path(path_text))" in module_source
    assert "path.read_text" not in source
    assert "@lru_cache" not in module_source


def test_stage2044_scheduler_import_guards_prefilter_before_static_inventory_parse() -> None:
    stage838_source = inspect.getsource(
        stage838.test_stage838_no_cross_subdomain_private_scheduler_imports_remain
    )
    stage839_source = inspect.getsource(
        stage839.test_stage839_no_scheduler_module_imports_private_timeout_inspection_helpers
    )

    assert stage838_source.index('if "from Virus_Scan.scheduler." not in source:') < stage838_source.index("parse_python_file(path)")
    assert stage839_source.index("if target_module not in source:") < stage839_source.index("parse_python_file(path)")
    assert "ast.parse(source" not in stage838_source
    assert "ast.parse(source" not in stage839_source


def test_stage2044_stage97_concurrency_regression_is_bounded() -> None:
    source = inspect.getsource(stage97.test_concurrent_verified_queue_writes_are_strict_json)

    assert "ThreadPoolExecutor(max_workers=8)" in source
    assert "range(128)" in source
    assert "max_workers=32" not in source
    assert "range(512)" not in source


def test_stage2044_stage993_hash_seed_guard_is_in_process_and_bounded() -> None:
    source = inspect.getsource(stage993.test_queue_json_safe_set_order_is_stable_across_hash_seeds)

    assert "subprocess" not in source
    assert "queue_make_json_safe" in source
    assert "frozenset" in source
    assert "set(reversed" in source


def test_stage2044_stage992_identity_digest_guard_is_in_process_and_bounded() -> None:
    source = inspect.getsource(stage992.test_identity_lock_digest_is_full_sha256_and_deterministic)

    assert "subprocess" not in source
    assert "hashlib.sha256" in source
    assert "hexdigest" in source
    assert "len(decision.lock_path.stem) == 64" in source


def test_stage2044_stage161_bootstrap_registration_is_in_process_and_registry_explicit() -> None:
    module_source = inspect.getsource(stage161)
    first_source = inspect.getsource(stage161.test_runtime_dependency_providers_are_bootstrap_owned_in_fresh_process)

    assert "subprocess" not in module_source
    assert "ScanDependencyRegistry()" in first_source
    assert "registry=registry" in first_source


def test_stage2044_stage1669_static_guard_prefilters_before_ast_parse() -> None:
    source = inspect.getsource(stage1669.test_stage1669_detection_utils_text_boundaries_have_static_no_fspath_guard)
    teardown_source = inspect.getsource(stage1669.teardown_module)

    assert '"os.fspath" not in text' in source
    assert source.index('"os.fspath" not in text') < source.index("_static_guard_tree")
    assert "_static_guard_tree.cache_clear()" in teardown_source


def test_stage2044_stage1727_static_scheduler_listdir_guard_prefilters_before_static_inventory_parse() -> None:
    source = inspect.getsource(stage1727.test_stage1727_production_listdir_consumers_use_the_canonical_failure_gate)
    helper_source = inspect.getsource(stage1727._scheduler_tree)

    assert '"safe_queue_listdir" not in source' in source
    assert source.index('"safe_queue_listdir" not in source') < source.index("_scheduler_tree")
    assert "parse_python_file(path)" in helper_source
    assert "path.read_text" not in source


def test_stage2044_stage1764_unsafe_pattern_guard_prefilters_and_avoids_parent_maps() -> None:
    source = inspect.getsource(
        stage1764_architecture.test_stage1764_architecture_forbids_hybrid_graph_and_unsafe_import_patterns
    )
    collector_source = inspect.getsource(stage1764_architecture._collect_unsafe_pattern_offenders)
    prefilter_source = inspect.getsource(stage1764_architecture._source_needs_unsafe_pattern_ast_scan)

    assert "parents: dict" not in collector_source
    assert "parents[child]" not in collector_source
    assert "ast.walk" not in collector_source
    assert "_source_needs_unsafe_pattern_ast_scan(source)" in collector_source
    assert collector_source.index("_source_needs_unsafe_pattern_ast_scan(source)") < collector_source.index("_production_tree_for(path)")
    assert "for line in source.splitlines()" in prefilter_source
    assert "_collect_unsafe_pattern_offenders(path)" in source
