from __future__ import annotations

from Virus_Scan.scanners.pickle.rpyc_compression import _iter_pickle_compressed_views
from Virus_Scan.scanners.pickle.rpyc_emit import _iter_pickle_view_with_nested_compression
from Virus_Scan.scanners.pickle.rpyc_views import iter_rpyc_pickle_byte_views
from Virus_Scan.scanners.raw_chunk_headers import il2cpp_header


class _BadBytes:
    def __bool__(self):
        return True

    def __bytes__(self):
        raise ValueError("bad bytes conversion")


class _BadSlice:
    def __bool__(self):
        return True

    def __getitem__(self, _key):
        raise ValueError("bad slice conversion")


def test_compressed_view_conversion_failure_is_explicit_view():
    views = list(_iter_pickle_compressed_views(_BadBytes(), kind_prefix="stage921"))
    assert views == [("stage921+compressed_scan_failure", b"pickle_compressed_offset_scan_failure")]


def test_nested_rpyc_payload_conversion_failure_is_explicit_view():
    views = list(_iter_pickle_view_with_nested_compression(set(), "stage921", _BadSlice()))
    kinds = [kind for kind, _payload in views]
    assert "pickle_view_emit_failure" in kinds
    assert "stage921+nested_payload_conversion_failure" in kinds


def test_rpyc_input_conversion_failure_is_explicit_view():
    views = list(iter_rpyc_pickle_byte_views(_BadSlice(), path="bad.rpyc"))
    assert views == [("rpyc_input_conversion_failure", b"rpyc_input_conversion_failure")]


def test_raw_il2cpp_read_failure_returns_evidence_without_empty_byte_fallback():
    def _bad_read(_path, *, max_size):
        raise OSError("cannot read")

    result = il2cpp_header("bad.bin", read_file_bytes=_bad_read)
    tags = result["tags"]
    assert "raw_il2cpp_header_read_failed" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "il2cpp_binary" not in tags
