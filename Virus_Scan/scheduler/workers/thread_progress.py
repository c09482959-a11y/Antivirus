"""Worker-owned thread progress callback lifecycle."""

from __future__ import annotations

from typing import Callable

_PROGRESS_CALLBACK_EXCEPTIONS = (OSError, ValueError, RuntimeError, TypeError, AttributeError)


def set_thread_progress_callback(cb: Callable[..., object], *, set_progress_callback: Callable[[Callable[..., object]], object], record_suppressed: Callable[[str, BaseException], object]) -> None:
    try:
        set_progress_callback(cb)
    except _PROGRESS_CALLBACK_EXCEPTIONS as exc:
        try:
            record_suppressed("suppressed_exception", exc)
        except _PROGRESS_CALLBACK_EXCEPTIONS as report_exc:
            _ = report_exc


def clear_thread_progress_callback(*, clear_progress_callback: Callable[[], object], record_suppressed: Callable[[str, BaseException], object]) -> None:
    try:
        clear_progress_callback()
    except _PROGRESS_CALLBACK_EXCEPTIONS as exc:
        try:
            record_suppressed("suppressed_exception", exc)
        except _PROGRESS_CALLBACK_EXCEPTIONS as report_exc:
            _ = report_exc


__all__ = ("set_thread_progress_callback", "clear_thread_progress_callback")
