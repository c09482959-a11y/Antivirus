"""Stage 920 Phase 10: binary string evidence rejects hostile falsey objects."""
from __future__ import annotations

from Virus_Scan.scanners.binary_io import binary_string_evidence_tags


class _FalseyBinaryString:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


def test_binary_string_evidence_rejects_falsey_hostile_content_without_hooks() -> None:
    _FalseyBinaryString.touched = 0

    tags = binary_string_evidence_tags(_FalseyBinaryString())

    assert _FalseyBinaryString.touched == 0
    assert "binary_string_input_rejected" in tags
    assert "binary_final_json_must_record" in tags
    assert "scanner_failure_evidence:binary:binary_string_evidence" in tags
