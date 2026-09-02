import inspect
from pathlib import Path

from Virus_Scan.scanners.archives.evidence import (
    ArchiveMemberFailureRequest,
    append_archive_container_policy_evidence,
    append_archive_member_failure_evidence,
    append_archive_member_policy_evidence,
)
from Virus_Scan.scanners.archives.malformed import append_archive_failure_evidence


def _lower(tags):
    return {str(tag).lower() for tag in tags or []}


def test_archive_failure_evidence_api_uses_explicit_failure_and_evidence_tags():
    member_owner_sig = inspect.signature(append_archive_member_failure_evidence)
    member_request_sig = inspect.signature(ArchiveMemberFailureRequest)
    policy_sig = inspect.signature(append_archive_member_policy_evidence)
    container_sig = inspect.signature(append_archive_container_policy_evidence)
    malformed_sig = inspect.signature(append_archive_failure_evidence)

    assert tuple(member_owner_sig.parameters) == ("request",)
    assert "failure_tag" in member_request_sig.parameters
    assert "evidence_tag" in policy_sig.parameters
    assert "evidence_tag" in container_sig.parameters
    assert "failure_tag" in malformed_sig.parameters

    for sig in (member_owner_sig, member_request_sig, policy_sig, container_sig, malformed_sig):
        assert "fallback_tag" not in sig.parameters


def test_archive_member_policy_evidence_keeps_final_json_failure_publication(tmp_path: Path):
    sample = tmp_path / "archive.zip"
    tags = append_archive_member_policy_evidence(
        ["zip_archive"],
        path=str(sample),
        member_name="../escape.exe",
        evidence_tag="archive_blocked_unsafe_path",
        reason="unsafe archive member path",
    )
    low = _lower(tags)
    assert "archive_blocked_unsafe_path" in low
    assert "archive_member_failure_evidence_recorded" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_blocked_unsafe_path" in low
    assert "failure_domain_extraction" in low
    assert "archive_final_json_must_record" in low


def test_archive_container_policy_evidence_keeps_final_json_failure_publication(tmp_path: Path):
    sample = tmp_path / "broken.zip"
    tags = append_archive_container_policy_evidence(
        ["unknown_archive"],
        path=str(sample),
        evidence_tag="archive_unsupported_container",
        reason="unsupported or malformed archive container extension",
    )
    low = _lower(tags)
    assert "archive_unsupported_container" in low
    assert "archive_container_failure_evidence_recorded" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_unsupported_container" in low
    assert "failure_domain_extraction" in low
    assert "archive_final_json_must_record" in low
