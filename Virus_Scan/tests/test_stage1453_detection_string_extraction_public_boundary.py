from __future__ import annotations

from Virus_Scan.detection.contracts import string_extraction
from Virus_Scan.scanners.api import payload_contracts


def test_stage1453_string_extraction_exports_public_observed_payload_owner():
    assert "observed_decoded_payload_texts" in string_extraction.__all__
    assert "_observed_decoded_payload_texts" not in string_extraction.__all__
    assert not hasattr(string_extraction, "_observed_decoded_payload_texts")


def test_stage1453_observed_decoded_payload_texts_preserves_scanner_observation_boundary():
    records = payload_contracts.safe_decode_payloads("cG93ZXJzaGVsbCBjbWQuZXhl")
    observed = string_extraction.observed_decoded_payload_texts(records)
    assert any("powershell" in item.lower() for item in observed)

    view = string_extraction.build_extraction_view("", decoded_payloads=records)
    assert "powershell" in view.lower()
