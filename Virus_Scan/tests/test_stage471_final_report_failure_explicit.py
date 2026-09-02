from __future__ import annotations

import pytest

from Virus_Scan.publication.json_writer import finalize_scan_results


def _raise_value_error(_value):
    raise ValueError("forced serialization failure")


def test_final_scan_results_write_failure_is_explicit(tmp_path) -> None:
    output_path = tmp_path / "scan_results.json"
    with pytest.raises(RuntimeError, match="final scan_results.json write failed") as exc_info:
        finalize_scan_results(str(output_path), {"sample.bin": {"score": 0, "classification": "Clean"}}, make_json_safe=_raise_value_error)

    assert "final scan_results.json write failed" in str(exc_info.value)
