from __future__ import annotations

from types import MappingProxyType

import pytest

from Virus_Scan.scheduler.contracts import phase_output
from Virus_Scan.scheduler.contracts.phase_output import SchedulerPhaseOutput
from Virus_Scan.scheduler.contracts.queue_snapshot import QueueSnapshot


def test_stage1005_phase_payload_registry_is_immutable_mapping_proxy() -> None:
    registry = phase_output._PHASE_PAYLOAD_BY_NAME

    assert isinstance(registry, MappingProxyType)
    assert registry["QueueSnapshot"] is QueueSnapshot
    with pytest.raises(TypeError):
        registry["QueueSnapshot"] = object  # type: ignore[index]


def test_stage1005_phase_payload_registry_still_round_trips_payloads() -> None:
    output = SchedulerPhaseOutput(
        phase="phase1",
        domain="queue",
        status="ok",
        payload=QueueSnapshot(phase="claim", pending=1),
    )

    decoded = SchedulerPhaseOutput.from_mapping(output.as_dict())

    payload = decoded.payload
    assert isinstance(payload, QueueSnapshot)
    payload_dict = payload.as_dict()
    assert payload_dict["pending"] == 1
    assert payload_dict["phase"] == "claim"
