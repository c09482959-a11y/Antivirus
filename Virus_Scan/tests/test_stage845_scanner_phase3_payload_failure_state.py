from Virus_Scan.scanners import text

from Virus_Scan.scanners import payload_decode
from Virus_Scan.scanners.payload.base64_policy import _strict_b64_decode_result
from Virus_Scan.scanners.pickle.payload_records import _try_decode_pickle_literal
from Virus_Scan.scanners.contracts.payload_result import PayloadDecodeResult
from unittest.mock import patch


def test_payload_base64_decode_failure_is_immutable_evidence():
    def boom(*_args, **_kwargs):
        raise ValueError("decoder exploded")

    candidate = "cG93ZXJzaGVsbCBjbWQuZXhl"  # plausible base64: powershell cmd.exe

    result = _strict_b64_decode_result(candidate, depth=2, b64decode=boom, urlsafe_b64decode=boom)

    assert isinstance(result, PayloadDecodeResult)
    assert result.ok is False
    assert "payload_decode_failed" in result.failure_tags
    assert "scanner_failure_evidence_recorded" in result.failure_tags
    assert result.failure_evidence[0]["scanner_stage"] == "base64_decode"
    assert result.failure_evidence[0]["decode_depth"] == 2


def test_safe_decode_payloads_publishes_base64_failure_evidence():
    def boom(*_args, **_kwargs):
        raise ValueError("decoder exploded")

    records = payload_decode.safe_decode_payloads("prefix cG93ZXJzaGVsbCBjbWQuZXhl suffix", b64decode=boom, urlsafe_b64decode=boom)

    failures = [r for r in records if r.get("failure_evidence")]
    assert failures
    assert "payload_decode_failed" in failures[0]["failure_tags"]
    assert failures[0]["failure_evidence"][0]["error_category"] == "malformed_payload_decode"


def test_text_payload_decode_wrapper_publishes_base64_failure_evidence():

    def boom(*_args, **_kwargs):
        raise ValueError("text decoder exploded")

    records = text.safe_decode_payloads("prefix cG93ZXJzaGVsbCBjbWQuZXhl suffix", b64decode=boom, urlsafe_b64decode=boom)

    failures = [r for r in records if r.get("failure_evidence")]
    assert failures
    assert "payload_decode_failed" in failures[0]["failure_tags"]
    assert failures[0]["failure_evidence"][0]["scanner_name"] == "payload_decode"


def test_pickle_literal_base64_decode_failure_is_visible():

    def boom(*_args, **_kwargs):
        raise ValueError("pickle decoder exploded")

    def literal_safe_decode(text, max_depth=2):
        return payload_decode.safe_decode_payloads(text, max_depth=max_depth, b64decode=boom, urlsafe_b64decode=boom)

    with patch("Virus_Scan.scanners.pickle.payload_literal_records.safe_decode_payloads", literal_safe_decode):
        records = _try_decode_pickle_literal("cG93ZXJzaGVsbCBjbWQuZXhl")

    failures = [r for r in records if isinstance(r, dict) and r.get("failure_evidence")]
    assert failures
    assert "payload_decode_failed" in failures[0]["failure_tags"]
