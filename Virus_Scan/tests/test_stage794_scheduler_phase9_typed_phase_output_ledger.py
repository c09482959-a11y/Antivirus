from __future__ import annotations

import pytest

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.phase_output import SchedulerPhaseOutput, SchedulerPhaseOutputLedger
from Virus_Scan.scheduler.contracts.queue_snapshot import QueueSnapshot
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult


def test_phase9_typed_phase_output_ledger_round_trips_and_freezes_payloads() -> None:
    metadata = {"jobs": ["a.bin"]}
    evidence_context = {"source": ["queue"]}
    evidence = SchedulerEvidenceRecord(stage="queue", context=evidence_context, queue_id="q1")
    output = SchedulerPhaseOutput(
        phase="phase9",
        domain="queue",
        status="degraded",
        sequence=2,
        payload=QueueSnapshot(phase="claim", pending=1, metadata=metadata, evidence=({"failure": ["stalled"]},)),
        evidence=(evidence,),
    )
    ledger = SchedulerPhaseOutputLedger(outputs=(output,))
    result = SchedulerResult(status="degraded", phase_outputs=ledger, evidence=(evidence,))

    metadata["jobs"].append("mutated.bin")
    evidence_context["source"].append("mutated")

    encoded = result.as_dict()
    decoded = SchedulerResult.from_mapping(encoded)
    replay_snapshot = decoded.as_replay_snapshot("phase9-final")

    assert decoded.phase_outputs is not None
    assert decoded.phase_outputs.outputs[0].payload.metadata["jobs"] == ("a.bin",)
    assert decoded.phase_outputs.outputs[0].evidence[0].context["source"] == ("queue",)
    assert encoded["phase_outputs"]["outputs"][0]["payload_type"] == "QueueSnapshot"
    assert replay_snapshot.records[1]["payload"]["metadata"]["jobs"] == ("a.bin",)


def test_phase9_phase_output_rejects_untyped_mutable_payloads_and_evidence() -> None:
    with pytest.raises(TypeError):
        SchedulerPhaseOutput(phase="phase9", domain="queue", status="ok", payload={"queue": "mutable"})
    with pytest.raises(TypeError):
        SchedulerPhaseOutput(
            phase="phase9",
            domain="queue",
            status="ok",
            payload=QueueSnapshot(),
            evidence=({"not": "typed evidence"},),  # type: ignore[arg-type]
        )


def test_phase9_phase_output_ledger_sorts_deterministically_for_replay() -> None:
    second = SchedulerPhaseOutput(phase="phase9", domain="worker", status="ok", sequence=2, payload=QueueSnapshot(phase="worker"))
    first = SchedulerPhaseOutput(phase="phase9", domain="queue", status="ok", sequence=1, payload=QueueSnapshot(phase="queue"))

    ledger = SchedulerPhaseOutputLedger(outputs=(second, first))

    assert [output.domain for output in ledger.outputs] == ["queue", "worker"]
