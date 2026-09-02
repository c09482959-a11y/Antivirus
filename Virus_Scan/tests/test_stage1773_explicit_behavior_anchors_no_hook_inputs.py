from pathlib import Path

from Virus_Scan.detection.chains.execution import anchors


class HostileBoolIterable:
    bool_calls = 0
    iter_calls = 0
    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile bool must not execute")
    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("hostile iter must not execute")


class HostileText:
    str_calls = 0
    repr_calls = 0
    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile str must not execute")
    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("hostile repr must not execute")


def _reset() -> None:
    HostileBoolIterable.bool_calls = 0
    HostileBoolIterable.iter_calls = 0
    HostileText.str_calls = 0
    HostileText.repr_calls = 0


def test_canonical_anchor_inputs_do_not_truth_test_hostile_iterables() -> None:
    _reset()
    evidence = anchors.evaluate_chain_evidence(
        tags=HostileBoolIterable(),
        api_calls=HostileBoolIterable(),
        ordered_events=HostileBoolIterable(),
    )
    assert evidence.decisions == ()
    assert evidence.failures
    assert HostileBoolIterable.bool_calls == 0
    assert HostileBoolIterable.iter_calls == 0


def test_canonical_timeline_uses_no_hook_event_materialization() -> None:
    _reset()
    evidence = anchors.evaluate_chain_evidence(
        ordered_events=[HostileText(), "network_download", "process_exec"],
        match_modes=("ordered",),
    )
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "execution.download_execute"
    )
    assert decision.status == "candidate"
    assert decision.candidate.order_class == "observed_order"
    assert evidence.confirmed == ()
    assert evidence.failures
    assert HostileText.str_calls == 0
    assert HostileText.repr_calls == 0


def test_single_canonical_anchor_source_replaces_both_superseded_modules() -> None:
    assert Path("Virus_Scan/detection/chains/execution/anchors.py").exists()
    assert not Path("Virus_Scan/detection/chains/execution/behavior_anchors.py").exists()
    assert not Path("Virus_Scan/detection/chains/execution/explicit_anchors.py").exists()
