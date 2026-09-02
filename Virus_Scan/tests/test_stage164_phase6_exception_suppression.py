import json
from pathlib import Path

import pytest

from Virus_Scan.cli.exit_codes import exit_code_for_score, score_from_result
from Virus_Scan.contracts import DetectionObservation
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload


def test_contract_detection_observation_import_is_explicit():
    assert DetectionObservation is not None


def test_exit_code_score_parse_uses_typed_failure_boundary():
    assert exit_code_for_score(object()) == 4
    with pytest.raises(ValueError):
        score_from_result({"score": object()})


def test_worker_output_cleanup_failure_boundary_is_typed(tmp_path):
    out = tmp_path / "worker.json"
    assert write_worker_output_payload(str(out), {"score": 1.0}) is True
    assert json.loads(out.read_text(encoding="utf-8"))["score"] == 1.0
    bad = tmp_path / "existing_directory"
    bad.mkdir()
    assert write_worker_output_payload(str(bad), {"score": 2.0}) is False
    assert bad.is_dir()
