import inspect
from pathlib import Path

from Virus_Scan.detection.scoring.adaptive import log_odds_fusion
from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.models import temporal
from Virus_Scan.utils import probability


def test_stage1167_adaptive_scoring_uses_canonical_score_probability_helper():
    source = inspect.getsource(log_odds_fusion)

    assert "def _score_to_probability" not in source
    assert "def _sigmoid01" not in source
    assert "import math" not in source
    assert "score_to_probability(raw, midpoint=50.0, scale=16.0)" in source
    assert model_score.score_to_probability is probability.score_to_probability


def test_stage1167_temporal_v5_uses_canonical_probability_clamp_without_sigmoid_duplication():
    source = "\n".join(path.read_text(encoding="utf-8") for path in Path("Virus_Scan/models/temporal").glob("*.py"))

    assert "def _sigmoid01" not in source
    assert "centered_sigmoid_probability" not in source
    assert "safe_probability_score" in source
    assert probability.safe_probability_score(1.5) == 1.0
    assert probability.safe_probability_score("bad") == 0.0


def test_stage1167_canonical_score_probability_stays_bounded_for_bad_input():
    assert probability.score_to_probability("not-a-score") == 0.0
    assert 0.0 <= probability.score_to_probability(100.0) <= 1.0
