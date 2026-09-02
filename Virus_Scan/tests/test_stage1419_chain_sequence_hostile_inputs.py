from __future__ import annotations

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence


class _HostileText:
    touched = 0
    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("hostile text")


class _HostileIterable:
    touched = 0
    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("hostile iterator")
    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("hostile bool")


def test_stage1419_canonical_event_materialization_rejects_hostile_containers_without_hooks() -> None:
    _HostileIterable.touched = 0
    evidence = evaluate_chain_evidence(
        ordered_events=_HostileIterable(), api_calls=_HostileIterable(), match_modes=("ordered",),
    )
    assert evidence.decisions == ()
    assert evidence.failures
    assert _HostileIterable.touched == 0


def test_stage1419_canonical_event_materialization_skips_hostile_items_without_text_hooks() -> None:
    _HostileText.touched = 0
    evidence = evaluate_chain_evidence(
        ordered_events=[_HostileText(), "network_download", "process_exec"],
        match_modes=("ordered",),
    )
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "execution.download_execute"
    )
    assert decision.status == "candidate"
    assert decision.candidate.order_class == "observed_order"
    assert _HostileText.touched == 0
