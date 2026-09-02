from pathlib import Path

import pytest

from Virus_Scan.contracts.temporal_event import TemporalEvent


class HostileNumeric:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __float__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned float hook was invoked")


def test_stage2023_temporal_v5_event_rejects_hostile_numeric_hooks() -> None:
    HostileNumeric.touched = 0
    event = TemporalEvent(
        event_id="event-1",
        source_evidence_id="source-1",
        behavior_id="download",
        stage="runtime",
        timestamp_value=HostileNumeric(),
        timestamp_kind="observed",
        clock_domain="fixture",
        ordering_confidence=1.0,
        source_ordinal=0,
        provenance=(("source", "stage2023"),),
    )

    with pytest.raises(ValueError, match="temporal timestamp unavailable"):
        event.validate()
    assert HostileNumeric.touched == 0


def test_stage2023_superseded_temporal_evidence_values_owner_is_removed() -> None:
    assert not Path("Virus_Scan/models/temporal/evidence_values.py").exists()
    for path in Path("Virus_Scan").rglob("*.py"):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "Virus_Scan.models.temporal.evidence_values" not in source
