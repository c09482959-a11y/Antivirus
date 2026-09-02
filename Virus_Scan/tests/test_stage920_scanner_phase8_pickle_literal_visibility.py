"""Stage 920 Phase 3/8: pickle literal byte conversion failures must stay visible."""
from __future__ import annotations

import pytest

from Virus_Scan.scanners.pickle.literals import _pickle_arg_to_bytes


class _BadPickleLiteral:
    def __str__(self):
        raise ValueError("pickle literal string conversion failed")


def test_pickle_arg_to_bytes_failure_is_not_empty_bytes() -> None:
    with pytest.raises(ValueError, match="pickle literal string conversion failed") as exc_info:
        _pickle_arg_to_bytes(_BadPickleLiteral())

    assert "pickle literal string conversion failed" in str(exc_info.value)
