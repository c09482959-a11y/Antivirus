"""Stage2010 core init failure-boundary regressions."""
from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.core.init_parts import cache_init, paths_logging_init


class _ChildEnvironment:
    def any_bool_flag(self, _names):
        return True

    def is_process_shard(self):
        return False

    def publish_defaults(self, values):
        self.values = values


class _RuntimeEnvironmentFactory:
    last: _ChildEnvironment | None = None

    def __call__(self):
        self.last = _ChildEnvironment()
        return self.last


class _HostileSignalModule:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __getattribute__(self, name):  # pragma: no cover - test fails if reached
        if name in {"__class__", "touched", "reset"}:
            return object.__getattribute__(self, name)
        type(self).touched += 1
        raise AssertionError("signal attribute hook executed")


def test_stage2010_cache_init_publishes_exact_dict_items_without_mapping_method_guard() -> None:
    source = Path(cache_init.__file__).read_text(encoding="utf-8")

    assert "publish_init_values(tuple(dict.items(cache_state)))" in source
    assert "publish_init_values(cache_state.items())" not in source


def test_stage2010_console_handler_recorder_failure_is_visible() -> None:
    def fail_record(*_args, **_kwargs):
        raise ValueError("record failed")

    original_record = paths_logging_init.record_suppressed_failure
    try:
        paths_logging_init.record_suppressed_failure = fail_record
        with pytest.raises(ValueError):
            paths_logging_init._record_console_handler_failure(TypeError("install failed"))
    finally:
        paths_logging_init.record_suppressed_failure = original_record


def test_stage2010_signal_break_lookup_rejects_hostile_signal_object_without_getattr() -> None:
    recorded: list[tuple[str, str]] = []
    _HostileSignalModule.reset()

    original_owner = paths_logging_init.RuntimeEnvironmentOwner
    original_signal = paths_logging_init.signal
    original_record = paths_logging_init.record_suppressed_failure
    try:
        paths_logging_init.RuntimeEnvironmentOwner = _ChildEnvironment
        paths_logging_init.signal = _HostileSignalModule()
        paths_logging_init.record_suppressed_failure = lambda where, exc, **_kwargs: recorded.append((where, type(exc).__name__))
        assert paths_logging_init._umige_install_child_console_handlers() is None
    finally:
        paths_logging_init.RuntimeEnvironmentOwner = original_owner
        paths_logging_init.signal = original_signal
        paths_logging_init.record_suppressed_failure = original_record

    assert recorded == [
        ("console_handler_install_failed", "TypeError"),
        ("console_handler_install_failed", "TypeError"),
    ]
    assert _HostileSignalModule.touched == 0


def test_stage2010_run_id_uses_primitive_time_ns_and_pid() -> None:
    factory = _RuntimeEnvironmentFactory()

    original_install = paths_logging_init._umige_install_child_console_handlers
    original_owner = paths_logging_init.RuntimeEnvironmentOwner
    original_base = paths_logging_init._umige_runtime_base_dir
    original_time_ns = paths_logging_init.time.time_ns
    original_getpid = paths_logging_init.os.getpid
    try:
        paths_logging_init._umige_install_child_console_handlers = lambda: None
        paths_logging_init.RuntimeEnvironmentOwner = factory
        paths_logging_init._umige_runtime_base_dir = lambda: "base"
        paths_logging_init.time.time_ns = lambda: 1_234_567_890_000
        paths_logging_init.os.getpid = lambda: 42
        published = paths_logging_init.init_paths_logging()
    finally:
        paths_logging_init._umige_install_child_console_handlers = original_install
        paths_logging_init.RuntimeEnvironmentOwner = original_owner
        paths_logging_init._umige_runtime_base_dir = original_base
        paths_logging_init.time.time_ns = original_time_ns
        paths_logging_init.os.getpid = original_getpid

    assert factory.last is not None
    assert factory.last.values["UMIGE_RUN_ID"] == "1234567_42"
    assert dict(published)["BASE_DIR"] == "base"


def test_stage2010_paths_logging_source_has_no_getattr_or_run_id_fstring() -> None:
    source = Path(paths_logging_init.__file__).read_text(encoding="utf-8")

    assert "getattr(signal" not in source
    assert 'f"{int(time.time() * 1000)}_{os.getpid()}"' not in source
    assert "return\n" not in source
