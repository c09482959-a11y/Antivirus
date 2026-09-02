import pytest

from Virus_Scan.cli.exit_codes import (
    completed_scan_final_status, exit_code_for_score, score_from_result,
)
import Virus_Scan.cli.exit_codes as exit_codes


def test_stage1072_score_extraction_uses_public_export_only():
    assert exit_codes.__all__ == (
        "completed_scan_final_status", "exit_code_for_score", "score_from_result",
    )
    assert not hasattr(exit_codes, "_score_from_result")
    assert score_from_result({"score": 25}) == 25.0
    assert exit_code_for_score(score_from_result({"layers": {"x": {"score": 55}}})) == 2


def test_stage1072_malformed_declared_score_still_fails_closed():
    with pytest.raises(ValueError):
        score_from_result({"score": object(), "layers": {"fallback": {"score": 0}}})


def test_stage1072_completed_scan_exit_status_is_exact_and_fail_closed():
    assert tuple(completed_scan_final_status(value) for value in range(5)) == (
        "completed",
        "completed_nonzero_exit",
        "completed_nonzero_exit",
        "completed_nonzero_exit",
        None,
    )
    assert completed_scan_final_status(True) is None
    assert completed_scan_final_status(1.0) is None
