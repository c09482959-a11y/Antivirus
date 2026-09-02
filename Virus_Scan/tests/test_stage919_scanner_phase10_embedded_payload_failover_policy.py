"""Stage 919 Phase 10 embedded payload evidence failover policy tests."""
from __future__ import annotations

from Virus_Scan.scanners.binary_failover_policy import renpy_container_without_payload_evidence


def test_malformed_embedded_pe_header_counts_as_payload_evidence() -> None:
    identity = {"ext": ".rpa", "magic_type": "renpy_rpyc"}

    assert renpy_container_without_payload_evidence(identity, {"embedded_pe_header_truncated"}) is False
    assert renpy_container_without_payload_evidence(identity, {"embedded_pe_signature_missing"}) is False


def test_embedded_archive_signatures_count_as_payload_evidence() -> None:
    identity = {"ext": ".rpa", "magic_type": "renpy_rpyc"}

    assert renpy_container_without_payload_evidence(identity, {"embedded_7z_signature"}) is False
    assert renpy_container_without_payload_evidence(identity, {"embedded_rar_signature"}) is False


def test_renpy_container_without_payload_evidence_still_terminal() -> None:
    identity = {"ext": ".rpa", "magic_type": "renpy_rpyc"}

    assert renpy_container_without_payload_evidence(identity, {"file_seen"}) is True
