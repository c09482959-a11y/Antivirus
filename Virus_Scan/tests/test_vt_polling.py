from Virus_Scan.virustotal.client import VirusTotalClient
from Virus_Scan.virustotal.config import VirusTotalConfig
from Virus_Scan.virustotal.reporting import _vt_poll_until_full_results


def _completed_report(malicious: int = 1) -> dict[str, object]:
    return {
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {"malicious": malicious, "suspicious": 0, "undetected": 2},
                "results": {"engine-a": {}, "engine-b": {}},
            }
        }
    }


def test_vt_polling_waits_for_stable_populated_completed_results() -> None:
    reports = [_completed_report(1), _completed_report(1)]

    def call_owner(_client: VirusTotalClient, _analysis_id: str):
        return reports.pop(0), None

    client = VirusTotalClient(
        config=VirusTotalConfig(
            enabled=True,
            poll_interval_sec=1.0,
            poll_max_wait_sec=10.0,
            poll_stable_checks=2,
        ),
        api_key="test-key",
    )
    row = {"file": "sample.bin"}
    report, error = _vt_poll_until_full_results(
        client,
        "analysis-id",
        row,
        print_to_cli=False,
        call_owner=call_owner,
        sleep_owner=lambda _seconds: None,
        time_owner=lambda: 0.0,
    )
    assert error is None
    assert report == _completed_report(1)
    assert row["vt_completed"] is True
    assert row["vt_stats_populated"] is True
    assert row["vt_stats_stable"] is True
    assert row["vt_poll_attempts_used"] == 2
