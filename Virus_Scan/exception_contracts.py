"""Explicit exception contracts for recoverable runtime boundaries.

Phase A exception-transparency hardening: these tuples replace broad
``except Exception`` handlers at recovery/telemetry/scan boundaries so fatal
conditions are not hidden behind catch-all suppression.
"""
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

TELEMETRY_FAILURE_ERRORS = (
    OSError,
    ValueError,
    TypeError,
    UnicodeError,
    RuntimeError,
    SyntaxError,
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
