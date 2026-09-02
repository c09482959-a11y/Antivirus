"""Execution-owned child console handler installation."""

from __future__ import annotations

from typing import Callable, Mapping

_CHILD_CONSOLE_EXCEPTIONS = (OSError, ValueError, RuntimeError, TypeError, AttributeError)


def is_queue_child_process(*, environ: Mapping[str, str]) -> bool:
    return str(environ.get("UMIGE_QUEUE_CHILD", "0")).lower() in {"1", "true", "yes", "on"}


def install_child_console_handlers(*, environ: Mapping[str, str], signal_module: object, record_suppressed: Callable[[str, BaseException], object]) -> None:
    """Install worker-owned console suppression for queue child processes."""
    if not is_queue_child_process(environ=environ):
        return
    try:
        signal_module.signal(signal_module.SIGINT, signal_module.SIG_IGN)
    except _CHILD_CONSOLE_EXCEPTIONS as exc:
        try:
            record_suppressed("suppressed_exception", exc)
        except _CHILD_CONSOLE_EXCEPTIONS as report_exc:
            _ = report_exc
    try:
        if hasattr(signal_module, "SIGBREAK"):
            signal_module.signal(signal_module.SIGBREAK, signal_module.SIG_IGN)
    except _CHILD_CONSOLE_EXCEPTIONS as exc:
        try:
            record_suppressed("suppressed_exception", exc)
        except _CHILD_CONSOLE_EXCEPTIONS as report_exc:
            _ = report_exc


__all__ = ("is_queue_child_process", "install_child_console_handlers")
