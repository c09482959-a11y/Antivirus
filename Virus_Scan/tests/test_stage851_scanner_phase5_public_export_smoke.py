from Virus_Scan.scanners.binary import should_binary_failover
from Virus_Scan.scanners.ci.public_export_smoke import run_public_export_smoke


def test_phase5_public_export_smoke_gate_is_clean(tmp_path):
    result = run_public_export_smoke(tmp_path / "public_export_smoke")

    assert result.missing_smoke_cases == ()
    assert result.unexpected_errors == ()
    assert result.ok is True
    assert len(result.exports) >= 100
    assert len(result.records) >= 100


def test_public_binary_failover_handles_malformed_identity_with_evidence():
    tags = []

    assert should_binary_failover("unknown", "unknown", "not-a-mapping", [], tags) is True

    assert "binary_failover_identity_malformed" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:binary:should_binary_failover_identity" in tags
