"""Canonical ownership boundary for the optional yara-python dependency.

The dependency is resolved once by a direct top-level import attempt.  This keeps
YARA cache and match execution paths free of dynamic imports while preserving the
original import failure as explicit configuration evidence.
"""
from __future__ import annotations

from typing import Optional, Tuple, TYPE_CHECKING

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.yara.no_hook import yara_message

if TYPE_CHECKING:
    from types import ModuleType

try:
    import yara as _YARA_PYTHON_MODULE
except IO_CONFIGURATION_ERRORS as exc:
    YARA_MODULE: Optional[ModuleType] = None
    YARA_IMPORT_ERROR: Optional[BaseException] = exc
else:
    YARA_MODULE = _YARA_PYTHON_MODULE
    YARA_IMPORT_ERROR = None


def yara_dependency() -> Tuple[Optional[ModuleType], Optional[BaseException]]:
    """Return the resolved yara-python module and import failure evidence."""
    return YARA_MODULE, YARA_IMPORT_ERROR


def require_yara_dependency() -> ModuleType:
    """Return yara-python or raise a deterministic startup/load error."""
    if YARA_MODULE is None:
        raise RuntimeError(yara_message("yara-python unavailable: ", YARA_IMPORT_ERROR))
    return YARA_MODULE

def _required_yara_callable(module: ModuleType, member_name: str) -> object:
    """Return a required callable from yara-python with explicit evidence."""
    member = getattr(module, member_name, None)
    if not callable(member):
        raise RuntimeError(yara_message("yara-python missing callable: ", member_name))
    return member


def yara_compile(module: ModuleType, **compile_kwargs: object) -> object:
    """Compile YARA rules through the optional-dependency boundary."""
    compile_callable = _required_yara_callable(module, "compile")
    return compile_callable(**compile_kwargs)


def yara_load(module: ModuleType, cache_path: object) -> object:
    """Load compiled YARA rules through the optional-dependency boundary."""
    load_callable = _required_yara_callable(module, "load")
    return load_callable(cache_path)

