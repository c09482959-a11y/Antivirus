from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.markov.counters import counter_target_count, markov_first_reason, markov_reason_text
from Virus_Scan.models.markov.flow import canonical_behavior_flow, safe_markov_stage_name, safe_markov_text
from Virus_Scan.models.markov.text_boundary import markov_detached_text, markov_text


class HostileMarkovText:
    touched = 0

    def __str__(self):  # pragma: no cover - regression proves no caller hook
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover - regression proves no caller hook
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, _spec):  # pragma: no cover - regression proves no caller hook
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")


def test_stage1998_markov_default_text_boundaries_reject_hostile_hooks() -> None:
    HostileMarkovText.touched = 0
    hostile = HostileMarkovText()

    assert markov_detached_text(hostile, default_text="markov_default") == ("markov_default", "")
    assert markov_text(hostile, default_text="markov_default") == "markov_default"
    assert markov_reason_text(hostile, default_text="markov_reason") == "markov_reason"
    assert markov_first_reason("", hostile, default_text="markov_reason") == "markov_reason"
    assert safe_markov_text(hostile, default_text="markov_safe") == "markov_safe"
    assert safe_markov_stage_name(hostile) == "unknown"
    assert canonical_behavior_flow((hostile,)) == ()
    assert counter_target_count({"exec": hostile}, "exec") == (0, "non_numeric_markov_count")
    assert HostileMarkovText.touched == 0


def test_stage1998_markov_sources_remove_legacy_fallback_keyword_path() -> None:
    for source_path in (
        Path("Virus_Scan/models/markov/text_boundary.py"),
        Path("Virus_Scan/models/markov/counters.py"),
        Path("Virus_Scan/models/markov/flow.py"),
        Path("Virus_Scan/models/markov/features.py"),
        Path("Virus_Scan/models/markov/probability.py"),
    ):
        source = source_path.read_text(encoding="utf-8")
        assert "fallback=" not in source
        assert "fallback:" not in source
        assert "fallback " not in source
