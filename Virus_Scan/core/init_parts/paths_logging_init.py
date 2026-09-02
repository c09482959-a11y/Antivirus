"""Initialize core runtime paths, console isolation, logging, and base environment."""

import logging
import os
import signal
import sys
import time
from threading import RLock
from types import ModuleType

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.runtime.init_state import publish_init_values
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.runtime.environment import RuntimeEnvironmentOwner
from Virus_Scan.core.paths import _umige_runtime_base_dir


def _record_console_handler_failure(exc: BaseException) -> None:
    record_suppressed_failure("console_handler_install_failed", exc, domain="runtime")


def _signal_module_value(name: str) -> object:
    if type(signal) is not ModuleType:
        raise TypeError("signal_module_rejected")
    signal_values = vars(signal)
    return signal_values[name] if name in signal_values else None


def _umige_install_child_console_handlers() -> None:
    """Install child-process console handlers without mutating unrelated runtime state."""
    try:
        is_child = RuntimeEnvironmentOwner().any_bool_flag(("UMIGE_PROCESS_SHARD", "UMIGE_PROCESS_QUEUE", "UMIGE_INMEMORY_WORKER"))
    except IO_CONFIGURATION_ERRORS:
        is_child = False
    if is_child:
        try:
            signal_func = _signal_module_value("signal")
            sigint = _signal_module_value("SIGINT")
            sigign = _signal_module_value("SIG_IGN")
            if signal_func is None or sigint is None or sigign is None:
                raise TypeError("signal_handler_contract_missing")
            signal_func(sigint, sigign)
        except IO_CONFIGURATION_ERRORS as exc:
            _record_console_handler_failure(exc)
        try:
            sigbreak = _signal_module_value("SIGBREAK")
            if sigbreak is not None:
                signal_func = _signal_module_value("signal")
                sigign = _signal_module_value("SIG_IGN")
                if signal_func is None or sigign is None:
                    raise TypeError("signal_handler_contract_missing")
                signal_func(sigbreak, sigign)
        except IO_CONFIGURATION_ERRORS as exc:
            _record_console_handler_failure(exc)


def _runtime_run_id() -> str:
    millis = time.time_ns() // 1_000_000
    return str.__add__(int.__str__(millis), str.__add__("_", int.__str__(os.getpid())))




def init_paths_logging() -> object:
    sys.dont_write_bytecode = True
    queue_identity_index_cache = {}
    try:
        queue_identity_index_lock = RLock()
    except IO_CONFIGURATION_ERRORS:
        queue_identity_index_lock = None

    _umige_install_child_console_handlers()
    runtime_environment = RuntimeEnvironmentOwner()
    process_shard_console = runtime_environment.is_process_shard()
    logging.basicConfig(
        level=logging.ERROR if process_shard_console else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    base_dir = _umige_runtime_base_dir()
    runtime_environment.publish_defaults({
        "UMIGE_BASE_DIR": base_dir,
        "UMIGE_RUN_ID": _runtime_run_id(),
    })
    return publish_init_values((
        ("yara", None),
        ("QUEUE_IDENTITY_INDEX_CACHE", queue_identity_index_cache),
        ("QUEUE_IDENTITY_INDEX_LOCK", queue_identity_index_lock),
        ("_UMIGE_PROCESS_SHARD_CONSOLE", process_shard_console),
        ("BASE_DIR", base_dir),
    ))


__all__ = ("init_paths_logging",)
