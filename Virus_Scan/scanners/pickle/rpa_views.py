"""Scanner-owned Ren'Py RPA member byte-view facade for pickle scanning.

Concrete ownership is split into:
- rpa_index.py for RPA header/index parsing.
- rpa_member_payloads.py for bounded member payload views.
"""
from __future__ import annotations

from Virus_Scan.scanners.pickle.rpa_index import (
    RPA_INDEX_MAX_BYTES,
    RPA_MEMBER_MAX_BYTES,
    RPA_MEMBER_MAX_COUNT,
    _safe_load_rpa_index,
)
from Virus_Scan.scanners.pickle.rpa_member_payloads import iter_renpy_rpa_members, _iter_renpy_rpa_members

__all__ = (
    'RPA_INDEX_MAX_BYTES',
    'RPA_MEMBER_MAX_BYTES',
    'RPA_MEMBER_MAX_COUNT',
    '_iter_renpy_rpa_members',
    '_safe_load_rpa_index',
    'iter_renpy_rpa_members',
)
