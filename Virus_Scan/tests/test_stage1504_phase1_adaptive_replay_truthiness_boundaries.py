from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.scoring.adaptive import availability, confidence
from Virus_Scan.models.api import adaptive_signals, replay_comparison_contracts


class HostileReason:
    def __init__(self, text: str):
        self.text = text
        self.bool_calls = 0
        self.str_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned reason truthiness was probed")

    def __str__(self):  # pragma: no cover - must not be invoked
        self.str_calls += 1
        raise AssertionError("caller-owned reason __str__ was probed")


class HostileFlag:
    def __init__(self):
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned flag truthiness was probed")


class HostileFloat(float):
    def __new__(cls, value: float):
        return float.__new__(cls, value)

    def __init__(self, value: float):
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned numeric truthiness was probed")



def test_stage1504_adaptive_numeric_evidence_does_not_probe_truthiness():
    value = HostileFloat(0.375)

    assert adaptive_signals.adaptive_signal_float_field({"risk": value}, "risk") == 0.375
    assert value.bool_calls == 0



def test_stage1504_replay_comparison_reason_does_not_probe_truthiness():
    reason = HostileReason("manual_replay_reason")

    record = replay_comparison_contracts.compare_model_evidence(
        model_name="markov",
        expected={"probability": 0.5},
        actual={"probability": 0.5},
        reason=reason,
    )

    assert record["reason"] == "manual_replay_reason"
    assert reason.bool_calls == 0



def test_stage1504_model_signal_reason_and_flags_do_not_probe_truthiness():
    reason = HostileReason("profile_unavailable")
    degraded = HostileFlag()

    assert confidence.model_signal_unavailable_reason({"unavailable_reason": reason}) == "unreadable_model_signal_reason"
    assert reason.bool_calls == 0
    assert reason.str_calls == 0
    assert confidence.model_signal_unavailable_reason({"degraded": degraded}) == "invalid_degraded_flag"
    assert degraded.bool_calls == 0



def test_stage1504_probability_feature_reason_and_flags_do_not_probe_truthiness():
    direct_reason = HostileReason("graph_missing")
    mapped_reason = HostileReason("graph_not_ready")
    degraded = HostileFlag()

    assert availability.probability_feature_unavailable_reason(
        {},
        "p_graph",
        unavailable_reason=direct_reason,
    ) == "unreadable_model_signal_reason"
    assert availability.probability_feature_unavailable_reason(
        {"p_graph_unavailable_reason": mapped_reason},
        "p_graph",
    ) == "unreadable_model_signal_reason"
    assert availability.probability_feature_unavailable_reason(
        {"degraded": degraded},
        "p_graph",
    ) == "invalid_degraded_flag"
    assert direct_reason.bool_calls == 0
    assert direct_reason.str_calls == 0
    assert mapped_reason.bool_calls == 0
    assert mapped_reason.str_calls == 0
    assert degraded.bool_calls == 0



def test_stage1504_repaired_sources_do_not_contain_targeted_truthiness_fallbacks():
    sources = {
        Path("Virus_Scan/models/api/adaptive_signals.py"): (
            'evidence.get("risk", 0.0) or 0.0',
            "evidence.get('risk', 0.0) or 0.0",
        ),
        Path("Virus_Scan/models/api/replay_comparison_contracts.py"): (
            "reason or expected_reason or actual_reason",
        ),
        Path("Virus_Scan/detection/scoring/adaptive/confidence.py"): (
            "if value:",
            "if record.get('degraded'):",
            "if record.get('confidence_degraded'):",
        ),
        Path("Virus_Scan/detection/scoring/adaptive/availability.py"): (
            "if unavailable_reason:",
            "if value:",
            "default_reason or",
            "feature_probs.get(f'{base}_degraded') or feature_probs.get('degraded')",
        ),
    }
    for path, forbidden_snippets in sources.items():
        source = path.read_text(encoding="utf-8")
        for snippet in forbidden_snippets:
            assert snippet not in source, f"{snippet!r} still present in {path}"
