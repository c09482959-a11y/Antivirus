"""ILSpy runtime seam for later decompiler isolation."""
from __future__ import annotations

from typing import TypeAlias


from Virus_Scan.runtime.config_state import get_ilspy_path

_IlspyRuntimeBoundaryTypes: TypeAlias = tuple[type[object], ...]
_ILSPY_RUNTIME_BOUNDARY_TYPES: _IlspyRuntimeBoundaryTypes = ()


def resolve_ilspy_path(default: str | None = None) -> str | None:
    return get_ilspy_path(default)
