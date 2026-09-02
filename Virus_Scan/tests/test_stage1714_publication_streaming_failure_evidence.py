from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.publication.json_finalization.streaming import (
    stream_json_mapping,
    write_partial_scan_results,
)


def _raise_value_error(_value: object) -> object:
    raise ValueError("forced stage1714 serialization failure")


def test_stage1714_stream_json_mapping_failure_raises_explicit_evidence_not_false(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"

    with pytest.raises(RuntimeError) as exc_info:
        stream_json_mapping(
            str(output),
            {"sample": {"classification": "clean"}},
            make_json_safe=_raise_value_error,
            fsync_file=False,
            verify_written=False,
        )

    text = str(exc_info.value)
    assert "final_json_stream_write_failed:path=" in text
    assert "reason=ValueError" in text
    assert not output.exists()
    assert not list(tmp_path.glob("scan_results.json.*.tmp"))


def test_stage1714_write_partial_scan_results_failure_raises_explicit_evidence_not_false(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.partial.json"

    with pytest.raises(RuntimeError, match="final_json_stream_write_failed"):
        write_partial_scan_results(
            str(output),
            {"sample": {"classification": "clean"}},
            make_json_safe=_raise_value_error,
        )

    assert not output.exists()
    assert not list(tmp_path.glob("scan_results.partial.json.*.tmp"))
