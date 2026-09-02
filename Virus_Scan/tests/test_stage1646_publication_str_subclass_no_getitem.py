from __future__ import annotations

from Virus_Scan.publication.json_finalization.base_projection import bounded_signal_value
from Virus_Scan.publication.json_finalization.scheduler_projection import timeout_evidence_projection


class HostileFinalJsonText(str):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - failure proves slicing hook returned
        type(self).touched += 1
        raise AssertionError("final JSON string subclass __getitem__ touched")

    def __str__(self):  # pragma: no cover - failure proves string hook returned
        type(self).touched += 1
        raise AssertionError("final JSON string subclass __str__ touched")

    def __repr__(self):  # pragma: no cover - failure proves repr hook returned
        type(self).touched += 1
        raise AssertionError("final JSON string subclass __repr__ touched")


def _reset() -> None:
    HostileFinalJsonText.touched = 0


def test_stage1646_bounded_signal_value_detaches_str_subclass_without_getitem_hook() -> None:
    _reset()
    value = HostileFinalJsonText("worker_state")

    assert bounded_signal_value(value) == "worker_state"
    assert HostileFinalJsonText.touched == 0


def test_stage1646_timeout_evidence_projection_detaches_required_str_subclass_values() -> None:
    _reset()
    value = HostileFinalJsonText("active_timeout")

    projected = timeout_evidence_projection({"timeout_reason": value})

    assert projected == {"timeout_reason": "active_timeout"}
    assert HostileFinalJsonText.touched == 0


def test_stage1646_timeout_evidence_projection_detaches_tail_str_subclass_values() -> None:
    _reset()
    value = HostileFinalJsonText("tail_value")

    projected = timeout_evidence_projection({"auxiliary_status": value})

    assert projected == {"auxiliary_status": "tail_value"}
    assert HostileFinalJsonText.touched == 0
