"""Scanner-owned binary exception classification."""
from __future__ import annotations


def is_binary_programmer_error(exc: BaseException) -> bool:
    """Return whether an exception is an implementation defect rather than malformed input."""
    return isinstance(exc, (AssertionError, AttributeError, ImportError, ModuleNotFoundError, NameError, TypeError))


__all__ = ("is_binary_programmer_error",)
