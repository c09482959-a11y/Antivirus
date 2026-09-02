"""Pytest bootstrap for repository-root-relative tests.

The test suite imports the package as ``Virus_Scan`` and source-inspection
regression tests use repository-root-relative paths, so pytest must normalize
execution to the parent directory even when it is launched from inside the
package directory.
"""
from __future__ import annotations

import gc
import hashlib
import linecache
import os
import shutil
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from types import ModuleType

import pytest


from Virus_Scan.runtime.config_state import (
    configure_deep_scan_mode,
    configure_ilspy_path,
    configure_profile_corruption_policy,
    configure_profiles_dir,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parent


def _seed_conftest_source_linecache() -> None:
    """Keep conftest source inspectable when pytest's loader cannot provide it."""
    source_path = Path(__file__).resolve()
    try:
        source_text = source_path.read_text(encoding="utf-8")
        source_stat = source_path.stat()
    except OSError:
        return
    cache_entry = (
        source_stat.st_size,
        source_stat.st_mtime,
        source_text.splitlines(keepends=True),
        str(source_path),
    )
    linecache.cache[str(source_path)] = cache_entry
    linecache.cache[__file__] = cache_entry


_seed_conftest_source_linecache()


repository_root_text = str(REPOSITORY_ROOT)
if repository_root_text not in sys.path:
    sys.path.insert(0, repository_root_text)

# Stage2041 pytest-runtime guard: validation subprocesses must not read or
# write stale copied bytecode while proving current source.  Keep the parent
# interpreter and all child Python import probes source-backed.
sys.dont_write_bytecode = True
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

from Virus_Scan.runtime.scan_integrity_state import (  # noqa: E402
    RuntimeScanIntegrityState,
    configure_runtime_scan_integrity_state,
)
from Virus_Scan.runtime.provenance import reset_provenance_epoch  # noqa: E402
from Virus_Scan.runtime.structured_failures import clear_failure_records  # noqa: E402
from Virus_Scan.tests.support.static_inventory import clear_static_inventory_cache  # noqa: E402
from Virus_Scan.scheduler.runtime.multiprocessing_context import shutdown_scheduler_multiprocessing_context_runtime  # noqa: E402
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state  # noqa: E402
from Virus_Scan.storage import (  # noqa: E402
    authoritative_model_state,
    scan_cache_repository,
    sqlite_lifecycle,
)

# Keep source-inspection tests deterministic regardless of the shell cwd used
# to invoke pytest.  This is test harness normalization only; production runtime
# path ownership is unchanged.
os.chdir(REPOSITORY_ROOT)

_TEST_SCAN_INTEGRITY_STATE = RuntimeScanIntegrityState()
configure_runtime_scan_integrity_state(_TEST_SCAN_INTEGRITY_STATE)

# Pytest must never use the checked-in/live worktree as its implicit writable
# model/cache authority.  Many integration tests intentionally exercise final
# model publication while other tests mutate runtime model state.  If the
# per-test runtime configuration were reset to ``None``, the next persistence
# boundary would resolve back to ``<repository>/profiles`` and could durably
# publish test-only state into the continuation worktree.  Keep one session
# sandbox outside the repository and allocate a deterministic per-test profiles
# root beneath it.  Tests that intentionally configure another temporary root
# remain free to do so; the harness merely owns the safe default boundary.
_TEST_WRITABLE_STATE_ROOT = Path(
    tempfile.mkdtemp(prefix="umige-pytest-writable-state-")
).resolve()


def _pytest_profiles_dir(nodeid: str) -> Path:
    digest = hashlib.sha256(nodeid.encode("utf-8")).hexdigest()[:24]
    return _TEST_WRITABLE_STATE_ROOT / "cases" / digest / "profiles"


def _bind_pytest_profiles_dir(profiles_dir: Path) -> None:
    """Bind every canonical SQLite/profile owner to one test-only root."""
    configure_profiles_dir(profiles_dir)
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    authoritative_model_state().configure(profiles_dir)
    scan_cache_repository().configure(profiles_dir, enabled=False)


@pytest.fixture(autouse=True)
def explicit_runtime_scan_integrity_state():
    """Keep scan-integrity state isolated without per-test ContextVar churn.

    Scheduler internals require an explicitly configured runtime scan-integrity
    owner.  Rebinding the ContextVar for every test made the exact full suite
    retain and traverse a growing context history.  The test harness binds one
    session-owned state and clears its entries at each test boundary instead.
    """
    _TEST_SCAN_INTEGRITY_STATE.clear_all()
    try:
        yield
    finally:
        _TEST_SCAN_INTEGRITY_STATE.clear_all()



def _reset_runtime_config_owner_for_test(profiles_dir: Path) -> None:
    configure_deep_scan_mode("auto")
    configure_ilspy_path(None)
    configure_profile_corruption_policy("hard-fail")
    _bind_pytest_profiles_dir(profiles_dir)


@pytest.fixture(autouse=True)
def reset_runtime_config_owner(request):
    """Keep runtime configuration owner state isolated between tests."""
    profiles_dir = _pytest_profiles_dir(request.node.nodeid)
    _reset_runtime_config_owner_for_test(profiles_dir)
    try:
        yield
    finally:
        # Keep the same test-owned persistence root active through teardown so
        # later fixture finalizers cannot fall back to the live worktree.
        _reset_runtime_config_owner_for_test(profiles_dir)


@pytest.fixture(autouse=True)
def reset_runtime_forensic_state():
    """Isolate global forensic ledgers between tests.

    Several scheduler/runtime tests intentionally append provenance and structured
    failure evidence.  Leaving those bounded ledgers populated across thousands
    of tests makes later full-suite validation pay for unrelated historical
    records and can turn baseline pytest into a timeout.  Resetting before and
    after each test preserves per-test behavior while preventing cross-test
    validation stalls.
    """
    reset_provenance_epoch()
    clear_failure_records()
    try:
        yield
    finally:
        clear_failure_records()
        reset_provenance_epoch()


def _scheduler_helper_cleanup_due() -> bool:
    """Return whether this test boundary should run helper cleanup."""
    return _SCHEDULER_HELPER_CLEANUP_TEST_COUNT % _SCHEDULER_HELPER_CLEANUP_INTERVAL == 0


@pytest.fixture(autouse=True)
def reset_scheduler_multiprocessing_helpers():
    """Keep scheduler multiprocessing helpers bounded without per-test waits.

    Process-scheduler tests can start stdlib forkserver/resource-tracker helpers.
    Calling the helper shutdown owner before and after every one of thousands of
    tests can repeatedly enter bounded signal/reap waits after a helper owner has
    been started, turning the exact full-suite command into a validation timeout.
    The harness now performs coarse interval cleanup plus session-finish cleanup,
    preserving a bounded lifecycle while avoiding per-test wait amplification.
    """
    global _SCHEDULER_HELPER_CLEANUP_TEST_COUNT

    _SCHEDULER_HELPER_CLEANUP_TEST_COUNT += 1
    if _scheduler_helper_cleanup_due():
        shutdown_scheduler_multiprocessing_context_runtime()
    try:
        yield
    finally:
        if _scheduler_helper_cleanup_due():
            shutdown_scheduler_multiprocessing_context_runtime()


_TEST_SOURCE_LRU_CACHE_WRAPPER_TYPE = type(lru_cache(maxsize=1)(lambda: None))
_TEST_SOURCE_CACHE_CLEARERS: tuple[object, ...] = ()
_TEST_SOURCE_CACHE_MODULES: frozenset[str] = frozenset()
_TEST_SOURCE_CACHE_REGISTRY_REFRESHED = False
_TEST_SOURCE_CACHE_TEST_COUNT = 0
_TEST_SOURCE_CACHE_PRESSURE_INTERVAL = 500
_SCHEDULER_HELPER_CLEANUP_TEST_COUNT = 0
_SCHEDULER_HELPER_CLEANUP_INTERVAL = 100


def _refresh_test_source_scan_cache_clearers() -> None:
    """Register source-inspection cache clearers without hostile getattr hooks."""
    global _TEST_SOURCE_CACHE_CLEARERS
    global _TEST_SOURCE_CACHE_MODULES
    global _TEST_SOURCE_CACHE_REGISTRY_REFRESHED

    if _TEST_SOURCE_CACHE_REGISTRY_REFRESHED:
        return

    discovered_clearers: list[object] = []
    discovered_modules: set[str] = set()
    for module_name, module in tuple(sys.modules.items()):
        if module is None or module_name in _TEST_SOURCE_CACHE_MODULES:
            continue
        if not (
            module_name.startswith("Virus_Scan.tests.test_stage")
            or module_name.startswith("test_stage")
        ):
            continue
        discovered_modules.add(module_name)
        for value in tuple(vars(module).values()):
            if type(value) is _TEST_SOURCE_LRU_CACHE_WRAPPER_TYPE:
                discovered_clearers.append(value.cache_clear)

    if discovered_clearers:
        _TEST_SOURCE_CACHE_CLEARERS = (
            *_TEST_SOURCE_CACHE_CLEARERS,
            *tuple(discovered_clearers),
        )
    if discovered_modules:
        _TEST_SOURCE_CACHE_MODULES = frozenset((
            *_TEST_SOURCE_CACHE_MODULES,
            *tuple(discovered_modules),
        ))
    _TEST_SOURCE_CACHE_REGISTRY_REFRESHED = True


def _clear_test_source_scan_caches() -> None:
    """Release registered source-scan caches without repeated graph rescans."""
    _refresh_test_source_scan_cache_clearers()
    for cache_clear in _TEST_SOURCE_CACHE_CLEARERS:
        if callable(cache_clear):
            cache_clear()


def _clear_test_source_scan_caches_for_module(module: ModuleType | None) -> None:
    """Clear lru source-scan caches owned by one test module only."""
    if type(module) is not ModuleType:
        return
    module_name = module.__name__
    if not (
        module_name.startswith("Virus_Scan.tests.test_stage")
        or module_name.startswith("test_stage")
    ):
        return
    for value in tuple(vars(module).values()):
        if type(value) is _TEST_SOURCE_LRU_CACHE_WRAPPER_TYPE:
            value.cache_clear()


def _clear_bounded_source_scan_caches() -> None:
    """Release cumulative source-scan cache payloads without graph rescans.

    Full-suite collection imports every test module before execution.  The
    bounded cache-pressure path must clear each registered source-scan payload,
    but it must not drop the registration table during the run: doing so forces
    repeated whole-session ``sys.modules`` rescans and turns the exact full suite
    into a validation timeout.  Registry references are released once at
    ``pytest_sessionfinish`` after the exact pytest result is known.  Avoid
    explicit global garbage collection because it can execute arbitrary finalizers
    and convert a valid pytest run into a teardown stall.
    """
    clear_static_inventory_cache()
    _clear_test_source_scan_caches()


@pytest.fixture(autouse=True)
def bound_cumulative_source_scan_cache_pressure():
    """Keep source-scan cache pressure session-bounded without per-test scans.

    Full-suite collection imports all test modules before execution.  Earlier
    interval clearing repeatedly walked or cleared thousands of source-scan cache
    owners during dense no-hook/source-inspection ranges and prevented the exact
    full-suite command from completing.  The session-finish hook remains the
    release boundary; the per-test fixture is intentionally a no-op beyond
    preserving the explicit lifecycle hook point for future bounded owners.
    """
    yield


def _release_test_source_scan_cache_registry() -> None:
    """Release session-owned cache-clearer registry references before exit."""
    global _TEST_SOURCE_CACHE_CLEARERS
    global _TEST_SOURCE_CACHE_MODULES
    global _TEST_SOURCE_CACHE_REGISTRY_REFRESHED

    _TEST_SOURCE_CACHE_CLEARERS = ()
    _TEST_SOURCE_CACHE_MODULES = frozenset()
    _TEST_SOURCE_CACHE_REGISTRY_REFRESHED = False


@pytest.fixture(autouse=True)
def keep_test_source_scan_caches_session_bounded():
    """Keep source-scan caches available during a pytest session.

    Architecture tests repeatedly parse the same current-source files.  Clearing
    those lru caches after every individual test turns exact selector validation
    into repeated repository-wide parsing.  Source files do not change during a
    pytest invocation, so the cache lifetime is safely bounded by
    pytest_sessionfinish instead.
    """
    os.chdir(REPOSITORY_ROOT)
    try:
        yield
    finally:
        os.chdir(REPOSITORY_ROOT)




def _freeze_collected_pytest_object_graph() -> None:
    """Exclude the immutable collected-item graph from later cyclic scans.

    Full collection retains thousands of pytest item, fixture, and module
    objects for the session.  They are immutable after collection and can make
    an automatic generation scan traverse the entire test graph during an
    unrelated source audit.  ``gc.freeze()`` moves only the already collected
    graph to the permanent generation while keeping cyclic collection enabled
    for every object created by test execution.

    The process-owned terminal-summary boundary exits without interpreter
    finalizer traversal, so the frozen graph needs no unsafe mid-session
    unfreeze or explicit full collection.
    """
    gc.freeze()


def pytest_collection_finish(session) -> None:
    """Finalize session-owned cache and GC boundaries after collection."""
    _refresh_test_source_scan_cache_clearers()
    _freeze_collected_pytest_object_graph()


def pytest_sessionfinish(session, exitstatus):
    """Close scheduler-owned multiprocessing helpers and release test caches."""
    _release_test_source_scan_cache_registry()
    shutdown_scheduler_multiprocessing_context_runtime()
    sqlite_lifecycle().close()
    shutil.rmtree(_TEST_WRITABLE_STATE_ROOT, ignore_errors=True)
    return None


def _cleanup_pytest_owned_basetemp(config) -> None:
    """Remove this session's auto-generated pytest temp tree before ``os._exit``.

    Pytest normally performs numbered-temp retention through an ``atexit``
    handler.  The bounded terminal path below intentionally uses ``os._exit``
    to avoid unrelated interpreter-finalizer stalls, so that handler cannot run.
    Remove only pytest's automatically allocated basetemp here; an explicit
    user-provided ``--basetemp`` remains caller-owned and is never deleted.
    """
    factory = config._tmp_path_factory
    if factory._given_basetemp is not None:
        return
    basetemp = factory._basetemp
    if basetemp is None:
        return
    shutil.rmtree(basetemp, ignore_errors=True)


@pytest.hookimpl(trylast=True)
def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    """Return exact pytest status after terminal reporting instead of teardown stalls.

    pytest_sessionfinish performs scheduler-owned cleanup first.  Some cumulative
    scheduler validation runs still leave stdlib multiprocessing atexit handlers
    waiting after pytest has already reported the exact result.  Exiting here
    preserves the pytest exit status and prevents a passed run from being
    converted into an unbounded teardown timeout.
    """
    terminalreporter.write_sep("=", f"Stage2044 bounded pytest exit status {int(exitstatus)}")
    try:
        terminalreporter._tw.flush()
    except AttributeError:
        pass
    _cleanup_pytest_owned_basetemp(config)
    os._exit(int(exitstatus))
