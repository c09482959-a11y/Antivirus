from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.temporal import anomaly



class HostileFlow:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned iteration hook was invoked")


def test_stage2023_temporal_anomaly_delegates_after_no_hook_materialization() -> None:
    HostileFlow.touched = 0
    seen = {}

    def fake_pair(flow, *, prev_stage):
        seen["pair"] = (prev_stage, flow)
        return 0.25

    with patch.object(anomaly, "tag_pair_anomaly", fake_pair):
        assert anomaly.temporal_pair_anomaly("asset", HostileFlow()) == 0.25

    assert seen == {"pair": ("asset", ())}
    assert HostileFlow.touched == 0


def test_stage2023_temporal_anomaly_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/models/temporal/anomaly.py"))

    forbidden = (
        "return safe_clamp(tag_pair_anomaly(_temporal_sequence_values(flow)))",
        "Temporal does not own a local clean/zero fallback",
        "return safe_clamp(markov_transition_score",
        "return safe_clamp(markov_known_chain_score(_temporal_sequence_values(flow)))",
    )
    for snippet in forbidden:
        assert snippet not in source
