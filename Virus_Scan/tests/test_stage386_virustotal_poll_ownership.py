import inspect

from Virus_Scan.virustotal import reporting as vt
from Virus_Scan.virustotal.client import VirusTotalClient
from Virus_Scan.virustotal.config import VirusTotalConfig


def _completed_empty_report() -> dict[str, object]:
    return {
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 0,
                    "harmless": 0,
                    "timeout": 0,
                    "failure": 0,
                    "type-unsupported": 0,
                },
                "results": {},
            }
        }
    }


def test_stage386_virustotal_non_full_poll_uses_canonical_bounded_attempts() -> None:
    calls: list[str] = []

    def call_owner(_client: VirusTotalClient, analysis_id: str):
        calls.append(analysis_id)
        return _completed_empty_report(), None

    client = VirusTotalClient(
        config=VirusTotalConfig(
            enabled=True,
            wait_for_full_report=False,
            poll_attempts=2,
            poll_interval_sec=1.0,
            poll_stable_checks=3,
            poll_max_wait_sec=0.0,
        ),
        api_key="test-key",
    )
    row = {"file": "sample.bin"}
    report, error = vt._vt_poll_until_full_results(
        client,
        "analysis-id",
        row,
        print_to_cli=False,
        call_owner=call_owner,
        sleep_owner=lambda _seconds: None,
    )
    assert error is None
    assert report is not None
    assert len(calls) == 2
    assert row["vt_poll_attempts_used"] == 2
    assert row["vt_completed"] is True
    assert row["vt_stats_populated"] is False
    assert row["vt_stats_stable"] is False


def test_stage386_virustotal_poll_code_has_one_bounded_attempt_owner() -> None:
    source = inspect.getsource(vt._vt_poll_until_full_results)
    assert "poll_attempts" not in source
    assert "bounded_attempts" not in source
    assert "_poll_terminal" in source
