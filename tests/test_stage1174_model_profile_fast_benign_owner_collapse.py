from pathlib import Path

from Virus_Scan.models import profiles
from Virus_Scan.detection.scoring.prefilter.fast_benign_bypass import (
    extremely_strict_fast_benign_bypass_after_prefilter,
)


def test_profile_model_no_longer_owns_fast_benign_detection_result():
    assert not hasattr(profiles, "extremely_strict_fast_benign_bypass")
    for name in (
        "STRICT_FAST_BENIGN_EXTENSIONS",
        "STRICT_FAST_BENIGN_MAX_BYTES",
        "STRICT_FAST_BENIGN_BINARY_MAGIC",
        "STRICT_FAST_BENIGN_DENY_TOKENS",
        "STRICT_FAST_BENIGN_BYPASS_VERSION",
    ):
        assert not hasattr(profiles, name)


def test_fast_benign_detection_remains_in_detection_prefilter_owner(tmp_path: Path):
    sample = tmp_path / "boring.txt"
    sample.write_text("hello world\nsmall harmless text\n", encoding="utf-8")

    result = extremely_strict_fast_benign_bypass_after_prefilter(
        sample,
        tags=["text_file"],
        suspicious=False,
        yara_hits=[],
        compiled_rules=None,
    )

    assert result["fast_path"] is True
    assert result["classification"] == "benign_clean"
    assert result["learn_eligible"] is False
    assert "strict_fast_benign_bypass_after_prefilter" in result["explanation"]["reasons"]
