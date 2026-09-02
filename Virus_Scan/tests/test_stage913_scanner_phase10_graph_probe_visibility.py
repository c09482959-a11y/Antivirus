"""Stage 913 Phase 10 graph-probe failure visibility tests."""
from __future__ import annotations

from Virus_Scan.scanners.binary_behavior_predicates import _xor_blob_signal

from Virus_Scan.scanners.binary_behavior_detectors import detect_evasion_signals
from Virus_Scan.scanners.binary_graph_context import binary_node_edge_status, binary_node_has_edges


class _BadGraphNode:
    def edges(self):
        raise ValueError("graph edge probe failed")


class _EdgeGraphNode:
    def edges(self):
        return ["edge"]


def test_graph_probe_failure_has_explicit_status_not_clean_empty() -> None:
    status, has_edges = binary_node_edge_status(_BadGraphNode())
    assert status == "probe_error"
    assert has_edges is False
    assert binary_node_has_edges(_BadGraphNode()) is False


def test_graph_probe_failure_does_not_score_as_missing_edges() -> None:
    failure_score = detect_evasion_signals(["process_exec"], node=_BadGraphNode())
    empty_score = detect_evasion_signals(["process_exec"], node={"edges": []})
    edge_score = detect_evasion_signals(["process_exec"], node=_EdgeGraphNode())
    assert failure_score < empty_score
    assert edge_score < empty_score

class _BadVisibilityPayload:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("visibility hook executed")

    def __len__(self):
        return self._touch()

    def __getitem__(self, key):
        return self._touch()

    def __bytes__(self):
        return self._touch()

    def __iter__(self):
        return self._touch()

    def __bool__(self):
        return self._touch()


def test_xor_blob_signal_visibility_error_is_not_hidden() -> None:

    _BadVisibilityPayload.reset()
    try:
        _xor_blob_signal(_BadVisibilityPayload())
    except TypeError as exc:
        assert "unsafe_binary_blob_rejected" in str(exc)
    else:
        raise AssertionError("binary visibility helper failure was hidden as a clean no-hit")
    assert _BadVisibilityPayload.touched == 0
