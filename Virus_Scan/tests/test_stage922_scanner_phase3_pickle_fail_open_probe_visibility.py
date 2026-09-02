from __future__ import annotations

import pytest

from Virus_Scan.scanners.pickle.escalation import pickle_fast_escalation_prefilter
from Virus_Scan.scanners.pickle.escalation_base64 import _pickle_fast_protocol_hint
from Virus_Scan.scanners.pickle.rpyc_chunks import (
    _pickle_container_magic_present,
    _pickle_container_magic_status,
)
from Virus_Scan.scanners.pickle.rpyc_views import (
    _renpy_like_pickle_view_status,
    iter_rpyc_pickle_byte_views,
)
from Virus_Scan.scanners.pickle.source_detection import (
    _is_renpy_pickle_path,
    renpy_pickle_path_status,
)


class _BadBytes:
    def __bool__(self):
        return True

    def __bytes__(self):
        raise ValueError("bad bytes")


class _BadSlice:
    def __bool__(self):
        return True

    def __getitem__(self, _key):
        raise ValueError("bad slice")


class _BadPath:
    def __bool__(self):
        return True

    def __str__(self):
        raise ValueError("bad path")


def test_pickle_fast_protocol_hint_does_not_fail_open_to_true():
    with pytest.raises(ValueError):
        _pickle_fast_protocol_hint(_BadBytes())


def test_pickle_fast_prefilter_records_protocol_probe_failure():
    info = pickle_fast_escalation_prefilter("game/script.rpyc", data=_BadBytes(), text="")
    assert info["force_full"] is True
    assert "pickle_fast_prefilter_error" in info["hits"]
    assert "scanner_failure_evidence_recorded" in info["tags"]


def test_pickle_container_magic_probe_failure_is_explicit_status_not_present():
    assert _pickle_container_magic_status(_BadSlice()) == "probe_error"
    assert _pickle_container_magic_present(_BadSlice()) is False


def test_rpyc_view_probe_failure_is_explicit_view():
    in_scope, status = _renpy_like_pickle_view_status("", "plain.bin", _BadSlice())
    assert in_scope is False
    assert status == "probe_error"
    views = list(iter_rpyc_pickle_byte_views(_BadSlice(), path="plain.bin"))
    assert views == [("rpyc_input_conversion_failure", b"rpyc_input_conversion_failure")]


def test_renpy_path_probe_failure_is_status_not_fail_open():
    assert renpy_pickle_path_status(_BadPath()) == "probe_error"
    assert _is_renpy_pickle_path(_BadPath()) is False
