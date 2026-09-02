"""Canonical exact identity for module-native functions in the active runtime.

CPython and Nuitka expose module functions through different concrete runtime
classes.  Security and ownership boundaries must compare against the function
class produced by the active application runtime, not against a CPython-specific function class.
"""
from __future__ import annotations


def _runtime_native_function_probe() -> None:
    """Provide the exact module-function class for this application runtime."""


RUNTIME_NATIVE_FUNCTION_TYPE = type(_runtime_native_function_probe)


def is_runtime_native_function(value: object) -> bool:
    """Return whether *value* is an exact module-native function."""
    return type(value) is RUNTIME_NATIVE_FUNCTION_TYPE


__all__ = ("RUNTIME_NATIVE_FUNCTION_TYPE", "is_runtime_native_function")
