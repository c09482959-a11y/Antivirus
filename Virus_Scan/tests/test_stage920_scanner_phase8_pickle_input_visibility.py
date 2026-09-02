"""Stage 920 Phase 3/8: pickle input conversion failures must not become clean empty samples."""
from __future__ import annotations

import pytest

from Virus_Scan.scanners.pickle.opcode_analysis import analyze_pickle_opcode_graph
from Virus_Scan.scanners.pickle.protocol import has_pickle_protocol_header, pickle_protocol_offsets


class _BadPickleInput:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        return True

    def __getitem__(self, _item):
        type(self).touched += 1
        raise TypeError("pickle sample slice failed")

    def __bytes__(self):
        type(self).touched += 1
        raise TypeError("pickle sample bytes failed")


def test_protocol_header_conversion_failure_is_visible() -> None:
    _BadPickleInput.reset()
    with pytest.raises(ValueError, match="unsafe_pickle_protocol_input_rejected"):
        has_pickle_protocol_header(_BadPickleInput(), max_bytes=64)
    assert _BadPickleInput.touched == 0


def test_protocol_offsets_conversion_failure_is_visible() -> None:
    _BadPickleInput.reset()
    with pytest.raises(ValueError, match="unsafe_pickle_protocol_input_rejected"):
        pickle_protocol_offsets(_BadPickleInput(), max_offsets=4, max_bytes=64)
    assert _BadPickleInput.touched == 0


def test_opcode_graph_conversion_failure_emits_failure_evidence() -> None:
    _BadPickleInput.reset()
    summary = analyze_pickle_opcode_graph(_BadPickleInput())
    assert summary["errors"] >= 1
    assert "pickle_opcode_input_conversion_error" in summary.get("error_tags", [])
    evidence = summary.get("failure_evidence", [])
    assert evidence
    assert evidence[0]["downstream_final_json_required"] is True
    assert _BadPickleInput.touched == 0
