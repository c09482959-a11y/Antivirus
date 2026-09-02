from __future__ import annotations

from Virus_Scan.publication.json_finalization.signal_projection import signal_summary


class HostileSignalValue:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("signal summary iter hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("signal summary str hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("signal summary repr hook executed")


def test_stage1711_signal_summary_rejects_unsupported_signal_without_empty_default() -> None:
    HostileSignalValue.touched = 0

    projected = signal_summary({"graph_signals": HostileSignalValue()}, "graph_signals")

    assert HostileSignalValue.touched == 0
    assert projected["model_signal_projection_failed"] is True
    assert projected["reason"] == "unsupported_model_signal_value"
    assert projected["source_field"] == "graph_signals"
    assert projected["value_type"] == "HostileSignalValue"


def test_stage1711_signal_summary_absent_signals_emit_explicit_unavailable_evidence() -> None:
    projected = signal_summary({}, "graph_signals", "graph_features")

    assert projected["model_signal_projection_failed"] is True
    assert projected["reason"] == "graph_unavailable"
    assert projected["source_field"] == "graph_signals"
