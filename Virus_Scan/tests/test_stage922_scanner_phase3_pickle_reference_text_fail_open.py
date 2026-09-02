from __future__ import annotations

from Virus_Scan.scanners.pickle.global_references import (
    _pickle_is_suspicious_reference_global,
    pickle_reference_global_status,
)
from Virus_Scan.scanners.pickle.text_evidence import (
    _pickle_decode_interesting_text,
    pickle_decode_interesting_text_status,
)


class _BadText:
    def __bool__(self):
        return True

    def __str__(self):
        raise ValueError("bad text")


def test_pickle_global_reference_probe_failure_is_not_suspicious_fail_open():
    assert pickle_reference_global_status(_BadText()) == "probe_error"
    assert _pickle_is_suspicious_reference_global(_BadText()) is False


def test_pickle_decode_interesting_text_probe_failure_is_not_interesting_fail_open():
    assert pickle_decode_interesting_text_status(_BadText()) == "probe_error"
    assert _pickle_decode_interesting_text(_BadText()) is False
