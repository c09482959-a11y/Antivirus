import json
from pathlib import Path

from Virus_Scan.reporting.output import clear_scan_results_before_scan
from Virus_Scan.publication.json_writer import finalize_scan_results, recover_results_from_partial


def test_scan_start_clears_stale_partial_checkpoint(tmp_path):
    output = tmp_path / "scan_results.json"
    partial = Path(str(output) + ".partial")
    output.write_text(json.dumps({"old": {"score": 1}}), encoding="utf-8")
    partial.write_text(json.dumps({"old": {"score": 99}, "older": {"score": 3}}), encoding="utf-8")

    clear_scan_results_before_scan(str(output), preserve=False)

    assert json.loads(output.read_text(encoding="utf-8")) == {}
    assert not partial.exists()
    assert recover_results_from_partial(str(output), {"new": {"score": 2}}) == {"new": {"score": 2}}


def test_final_report_removes_partial_checkpoint_after_success(tmp_path):
    output = tmp_path / "scan_results.json"
    partial = Path(str(output) + ".partial")
    partial.write_text(json.dumps({"stale": {"score": 9}}), encoding="utf-8")

    assert finalize_scan_results(str(output), {"current": {"file": "current", "score": 1.0}})

    assert not partial.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert list(data.keys()) == ["current"]
