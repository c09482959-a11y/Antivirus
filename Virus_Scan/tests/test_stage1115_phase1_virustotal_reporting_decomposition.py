import ast
from pathlib import Path

from Virus_Scan.virustotal import reporting as virustotal
from Virus_Scan.virustotal.client import VirusTotalClient
from Virus_Scan.virustotal.config import VirusTotalConfig


def _function_lengths(path: str) -> dict[str, int]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and getattr(node, "end_lineno", None) is not None
    }


def test_stage1115_virustotal_reporting_functions_are_bounded() -> None:
    lengths = _function_lengths("Virus_Scan/virustotal/reporting.py")
    offenders = {name: length for name, length in lengths.items() if length > 75}
    assert offenders == {}
    assert lengths["run_virustotal_reporting"] < 75
    assert lengths["_vt_poll_until_full_results"] < 75


def test_stage1115_virustotal_poll_preserves_timeout_evidence() -> None:
    now = iter([0.0, 2.0])

    def time_owner() -> float:
        return next(now)

    def call_owner(_client: VirusTotalClient, _analysis_id: str):
        return {"data": {"attributes": {"status": "queued", "stats": {}}}}, None

    client = VirusTotalClient(
        config=VirusTotalConfig(
            enabled=True,
            poll_interval_sec=1.0,
            poll_max_wait_sec=1.0,
            poll_stable_checks=2,
        ),
        api_key="test-key",
    )
    row = {"file": "timeout.bin"}
    report, error = virustotal._vt_poll_until_full_results(
        client,
        "analysis-id",
        row,
        print_to_cli=False,
        call_owner=call_owner,
        sleep_owner=lambda _seconds: None,
        time_owner=time_owner,
    )
    assert error is None
    assert report == {"data": {"attributes": {"status": "queued", "stats": {}}}}
    assert row["vt_completed"] is False
    assert row["vt_stats_populated"] is False
    assert row["vt_stats_stable"] is False
    assert row["vt_poll_attempts_used"] == 1
    assert "poll_max_wait_sec=1.0" in row["error"]
