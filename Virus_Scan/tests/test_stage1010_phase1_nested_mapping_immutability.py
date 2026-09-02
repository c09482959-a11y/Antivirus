from __future__ import annotations

from types import MappingProxyType

import pytest

from Virus_Scan.contracts import analytical_evidence as analytical_contract
from Virus_Scan.runtime import analytical_calibration as runtime_calibration
from Virus_Scan.detection.scoring.calibration import analytical_bundle as detection_calibration
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.timeout.process_queue_stall_evidence import stall_escalation_evidence


def test_stage1010_format_baselines_are_contract_owned_and_deeply_immutable():
    baselines = analytical_contract.FORMAT_ODDITY_BASELINES
    assert isinstance(baselines, MappingProxyType)
    assert isinstance(baselines["png"], MappingProxyType)
    assert baselines["png"]["entropy_mean"] == 7.25
    assert baselines["png"]["entropy_std"] == 0.45
    with pytest.raises(TypeError):
        baselines["png"]["entropy_mean"] = 0.0
    with pytest.raises(TypeError):
        baselines["png"]["entropy_std"] = 99.0


def test_stage1010_runtime_and_detection_do_not_republish_format_baseline_state():
    assert not hasattr(runtime_calibration, "_DEFAULT_FORMAT_BASELINES")
    assert not hasattr(detection_calibration, "_DEFAULT_FORMAT_BASELINES")
    assert runtime_calibration.format_oddity_snapshot("asset.png", entropy=7.25)["mean"] == 7.25
    assert detection_calibration.format_oddity_snapshot("asset.png", entropy=7.25)["std"] == 0.45


def test_stage1010_stall_escalation_record_context_is_deeply_immutable():
    evidence = stall_escalation_evidence(
        worker_idx=3,
        pid=44,
        action="terminate",
        reason="stalled",
        error="no progress",
        source="monitor",
        elapsed_sec=9.5,
    )
    record = evidence.as_record()
    assert isinstance(record, MappingProxyType)
    assert isinstance(record["context"], MappingProxyType)
    with pytest.raises(TypeError):
        record["context"]["reason"] = "changed"
    assert materialize_scheduler_mapping(record)["context"] == {
        "worker_idx": 3,
        "pid": 44,
        "action": "terminate",
        "reason": "stalled",
        "elapsed_sec": 9.5,
    }
