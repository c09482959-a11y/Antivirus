"""Bounded RPA member expansion for Ren'Py pickle byte views."""
from __future__ import annotations

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.contracts import scanner_contract_join, scanner_contract_text
from Virus_Scan.scanners.pickle.rpa_views import RPA_MEMBER_MAX_COUNT, iter_renpy_rpa_members
from Virus_Scan.scanners.pickle.rpyc_chunks import PICKLE_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scanners.pickle.rpyc_emit import _pickle_view_emit


def _iter_rpa_recursive_views(
    seen: object,
    blob: object,
    path: object,
    recursive_viewer: object,
) -> object:
    members = list(iter_renpy_rpa_members(blob, path=path) or [])[:RPA_MEMBER_MAX_COUNT]
    for member_name, member_blob, _metadata in members:
        safe_member = scanner_contract_text(member_name, replacement='').replace('\\', '/')
        item = _pickle_view_emit(seen, scanner_contract_join('rpa_member:', safe_member), member_blob)
        if item:
            yield item
        if safe_member.lower().endswith(('.rpyc', '.rpyb', '.rpymc', '.rpy', '.rpym')):
            for sub_kind, sub_payload in recursive_viewer(member_blob, path=safe_member):
                nested_kind = scanner_contract_join(
                    'rpa_member:', safe_member, '::', scanner_contract_text(sub_kind, replacement=''),
                )
                item = _pickle_view_emit(seen, nested_kind, sub_payload)
                if item:
                    yield item


def iter_optional_rpa_views(
    seen: object,
    blob: object,
    path: object,
    extension: object,
    recursive_viewer: object,
) -> object:
    """Yield recursive RPA views only for RPA-scoped input."""
    if extension == '.rpa' or blob.startswith(b'RPA-'):
        try:
            yield from _iter_rpa_recursive_views(seen, blob, path, recursive_viewer)
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', suppressed_exc, domain='runtime')
            except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
                _ = reporting_exc


__all__ = ('iter_optional_rpa_views',)
