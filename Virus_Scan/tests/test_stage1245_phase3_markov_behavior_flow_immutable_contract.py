from __future__ import annotations

import pytest

from Virus_Scan.models.api import adaptive_signals, markov_contracts
from Virus_Scan.models import markov


def test_stage1245_markov_canonical_behavior_flow_returns_immutable_tuple() -> None:
    flow = markov.canonical_behavior_flow([
        {"tag": "api_LoadURL"},
        {"tag": "api_LoadURL"},
        {"behavior": "tag_process_spawn"},
        {"event": "network_download"},
    ])

    assert flow == ("loadurl", "process_spawn", "network_download")
    assert isinstance(flow, tuple)
    with pytest.raises(AttributeError):
        flow.append("mutated")  # type: ignore[attr-defined]


def test_stage1245_public_markov_contract_preserves_immutable_flow_boundary() -> None:
    flow = markov_contracts.canonical_behavior_flow(["download", "download", "exec"])
    adaptive_flow = adaptive_signals.canonical_behavior_flow(["download", "download", "exec"])

    assert flow == ("download", "exec")
    assert adaptive_flow == flow
    assert isinstance(flow, tuple)
    assert isinstance(adaptive_flow, tuple)
