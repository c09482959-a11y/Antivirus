from Virus_Scan.detection.evidence.indicators.contextual_identity import contextual_identity_reporting_tags


def test_contextual_identity_embedded_type_string_is_single_payload_token():
    tags = contextual_identity_reporting_tags({"sniffed_embedded_types": "pe"})
    assert "polyglot_artifact" in tags
    assert "embedded_pe_payload" in tags
    assert "embedded_p_payload" not in tags
    assert "embedded_e_payload" not in tags


def test_contextual_identity_embedded_types_are_deduplicated_and_sanitized():
    tags = contextual_identity_reporting_tags({"sniffed_embedded_types": ["PE", "pe", "zip local"]})
    assert tags.count("embedded_pe_payload") == 1
    assert "embedded_zip_local_payload" in tags
