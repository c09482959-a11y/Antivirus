from pathlib import Path

from Virus_Scan.detection.enrichment.prefilter.scan import _apply_terminal_prefilter, TERMINAL_PREFILTER_FAILED
from Virus_Scan.detection.enrichment.prefilter.state import new_prefilter_info


def test_terminal_prefilter_failure_records_evidence_and_cannot_be_truthiness_hidden(tmp_path: Path):
    target = tmp_path / "sample.txt"
    target.write_text("normal text", encoding="utf-8")
    info = new_prefilter_info()

    def boom(**_kwargs):
        raise ValueError("terminal probe failed")

    result = _apply_terminal_prefilter(
        target,
        "normal text",
        info,
        reason="test_reason",
        version="test_version",
        confidence=0.1,
        attack_hit="test_attack",
        stage_name="prefilter_game_engine_terminal",
        terminal_func=boom,
    )

    assert result is TERMINAL_PREFILTER_FAILED
    assert info["fast_result"] is None
    assert info["force_full"] is True
    assert info["failure_evidence"]
    assert getattr(info["failure_evidence"][0], "stage_name") == "prefilter_game_engine_terminal"
