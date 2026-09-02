from pathlib import Path

from Virus_Scan.scanners.payload_decode import safe_decode_payloads as scanner_safe_decode_payloads
from Virus_Scan.scanners.ci.payload_authority_audit import audit_payload_authority


def test_detection_payload_decode_shim_is_removed_after_call_site_proof():
    assert not Path("Virus_Scan/detection/evidence/payload_decode.py").exists()


def test_scanner_payload_decode_remains_canonical_authority():
    candidate = "cG93ZXJzaGVsbCBjYWxjLmV4ZSBjcmVhdGVwcm9jZXNzIGV4ZWM="
    records = scanner_safe_decode_payloads(f"prefix {candidate} suffix", max_depth=1)
    assert isinstance(records, list)
    assert any("powershell" in str(record.get("text") or "").lower() for record in records)


def test_payload_authority_audit_passes_without_detection_payload_shim():
    result = audit_payload_authority(".")
    assert result.ok, result.to_record()
