from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from collections.abc import Mapping
from pathlib import Path

import pytest

from Virus_Scan.detection.scoring.stress.scoring_framework import (
    IterationScoreProfile,
    SCORE_FIELDS,
    ScorePenalty,
)



def test_stress_scoring_framework_lives_under_detection_scoring_owner():
    root = Path(__file__).resolve().parents[2]
    assert not (root / "Virus_Scan" / "stress" / "scoring_framework.py").exists()
    assert (root / "Virus_Scan" / "detection" / "scoring" / "stress" / "scoring_framework.py").exists()


def test_stress_scoring_profile_preserves_penalty_behavior():
    profile = IterationScoreProfile()
    assert set(profile.scores) == set(SCORE_FIELDS)
    profile.penalize(
        ScorePenalty(
            field="retry_logic_score",
            penalty=1.25,
            subsystem="stress",
            reason="stage984 canonical owner regression",
            trigger="unit",
        )
    )
    record = profile.as_record_fields()
    assert record["scores"]["retry_logic_score"] == 8.75
    assert 0 <= record["aggregate_score"] <= 10
    assert record["score_events"][0]["subsystem"] == "stress"


class HostileField:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("stress field __str__ must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("stress field __repr__ must not execute")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("stress field __format__ must not execute")


class HostileNumber:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("stress number __float__ must not execute")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("stress number __int__ must not execute")


class HostileScoreMapping(Mapping):
    touched = 0

    def __getitem__(self, _key):
        type(self).touched += 1
        raise RuntimeError("stress score mapping lookup must not execute")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("stress score mapping iter must not execute")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("stress score mapping len must not execute")

    def values(self):
        type(self).touched += 1
        raise RuntimeError("stress score mapping values must not execute")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("stress score mapping items must not execute")


def test_stress_scoring_rejects_hostile_field_and_number_without_hooks():
    HostileField.touched = 0
    HostileNumber.touched = 0
    profile = IterationScoreProfile()

    with pytest.raises(KeyError, match="unknown score field"):
        profile.penalize(ScorePenalty(HostileField(), 1.0, "stress", "bad field", "unit"))
    profile.penalize(ScorePenalty("retry_logic_score", HostileNumber(), "stress", "bad number", "unit"))

    assert profile.scores["retry_logic_score"] == 10.0
    assert HostileField.touched == 0
    assert HostileNumber.touched == 0


def test_stress_scoring_records_reject_hostile_score_mappings_without_hooks():
    HostileScoreMapping.touched = 0
    profile = IterationScoreProfile()
    profile.scores = HostileScoreMapping()
    profile.confidence = HostileScoreMapping()

    record = profile.as_record_fields()

    assert record["scores"]["retry_logic_score"] == 10.0
    assert record["confidence"]["retry_logic_score"] == 0.92
    assert record["aggregate_score"] == 10.0
    assert HostileScoreMapping.touched == 0


def test_stress_scoring_source_removes_hookable_mapping_and_fstring_snippets():
    source = read_python_file(Path("Virus_Scan/detection/scoring/stress/scoring_framework.py"))
    tree = ast.parse(source)
    forbidden = (
        "raise KeyError(f'unknown score field: {event.field}')",
        "worst = min(self.scores.values())",
        "mean = sum(self.scores.values()) / max(1, len(self.scores))",
        "'scores': {k: clamp_score(v) for k, v in self.scores.items()},",
        "'confidence': {k: round(v, 3) for k, v in self.confidence.items()},",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
