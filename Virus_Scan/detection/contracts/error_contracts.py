"""Detection-owned recoverable exception contracts."""
from __future__ import annotations

RECOVERABLE_RUNTIME_ERRORS = (
    OSError,
    ValueError,
    TypeError,
    AttributeError,
    KeyError,
    IndexError,
    UnicodeError,
    ImportError,
    LookupError,
    RuntimeError,
)
IO_CONFIGURATION_ERRORS = (
    OSError,
    ValueError,
    TypeError,
    UnicodeError,
    ImportError,
)
SCAN_CONTENT_ERRORS = (
    OSError,
    ValueError,
    TypeError,
    AttributeError,
    KeyError,
    IndexError,
    UnicodeError,
    LookupError,
    RuntimeError,
    SyntaxError,
    ImportError,
)
TAG_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError,
    ValueError,
    TypeError,
    RuntimeError,
    KeyError,
    AttributeError,
    UnicodeError,
)
TAG_SCAN_TELEMETRY_EXCEPTIONS = (OSError, RuntimeError, ValueError, TypeError, AttributeError)

__all__ = (
    "IO_CONFIGURATION_ERRORS",
    "RECOVERABLE_RUNTIME_ERRORS",
    "SCAN_CONTENT_ERRORS",
    "TAG_SCAN_RECOVERABLE_EXCEPTIONS",
    "TAG_SCAN_TELEMETRY_EXCEPTIONS",
)
