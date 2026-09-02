from Virus_Scan.scanners.archives.ecosystem_evidence import (
    append_archive_ecosystem_boundary_evidence,
)
from Virus_Scan.scanners.archives.evidence import (
    ArchiveMemberFailureRequest,
    append_archive_container_policy_evidence,
    append_archive_member_failure_evidence,
    append_archive_member_finding_publication_evidence,
    append_archive_member_payload_failure_publication_evidence,
    append_archive_member_policy_evidence,
)
from Virus_Scan.scanners.archives.rpa_evidence import (
    append_archive_rpa_failure_publication_evidence,
    append_archive_rpa_finding_publication_evidence,
)


class HostileTags:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("tag truthiness hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("tag iteration hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("tag repr hook executed")


class HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("text truthiness hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("text string hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("text repr hook executed")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("text format hook executed")


class HostileLimited:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("limited truthiness hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("limited repr hook executed")


def _reset_hostile_state():
    HostileTags.touched = 0
    HostileText.touched = 0
    HostileLimited.touched = 0


def _assert_no_hostile_hooks():
    assert HostileTags.touched == 0
    assert HostileText.touched == 0
    assert HostileLimited.touched == 0


def test_archive_member_publication_evidence_rejects_hostile_inputs_without_hooks():
    _reset_hostile_state()

    result = append_archive_member_finding_publication_evidence(
        HostileTags(),
        path=HostileText(),
        member_name=HostileText(),
        finding_tag=HostileText(),
    )

    _assert_no_hostile_hooks()
    assert "tag_normalization_failure_evidence" in result
    assert "detection_stage_degraded" in result
    assert "archive_member_finding_tag_unsafe" in result
    assert "archive_member_finding:archive_member_finding_tag_unsafe" in result
    assert "archive_member_finding_evidence_recorded" in result
    assert "archive_final_json_must_record" in result
    assert "archive_member_finding_member" not in result


def test_archive_member_payload_failure_evidence_rejects_hostile_inputs_without_hooks():
    _reset_hostile_state()

    result = append_archive_member_payload_failure_publication_evidence(
        HostileTags(),
        path=HostileText(),
        member_name=HostileText(),
        failure_tag=HostileText(),
    )

    _assert_no_hostile_hooks()
    assert "tag_normalization_failure_evidence" in result
    assert "archive_member_payload_failure_tag_unsafe" in result
    assert "archive_member_payload_failure:archive_member_payload_failure_tag_unsafe" in result
    assert "archive_member_payload_failure_evidence_recorded" in result
    assert "archive_final_json_must_record" in result
    assert "archive_member_payload_failure_member" not in result


def test_archive_failure_policy_evidence_sanitizes_public_arguments_before_scanner_evidence():
    _reset_hostile_state()

    failure_result = append_archive_member_failure_evidence(ArchiveMemberFailureRequest(
        HostileTags(),
        HostileText(),
        ValueError("owned failure"),
        path=HostileText(),
        member_name=HostileText(),
        failure_tag=HostileText(),
    ))
    policy_result = append_archive_member_policy_evidence(
        HostileTags(),
        path=HostileText(),
        member_name=HostileText(),
        evidence_tag=HostileText(),
        reason=HostileText(),
    )
    container_result = append_archive_container_policy_evidence(
        HostileTags(),
        path=HostileText(),
        evidence_tag=HostileText(),
        reason=HostileText(),
    )

    _assert_no_hostile_hooks()
    for result in (failure_result, policy_result, container_result):
        assert "tag_normalization_failure_evidence" in result
        assert "failure_domain_extraction" in result
        assert "scanner_failure_evidence_recorded" in result
        assert "archive_final_json_must_record" in result
    assert "archive_member_failure_tag_unsafe" in failure_result
    assert "archive_member_policy_reason_unsafe_scan_error" not in policy_result
    assert "archive_container_evidence_tag_unsafe" in container_result
    assert "archive_container_failure_evidence_recorded" in container_result


def test_archive_rpa_evidence_rejects_hostile_path_stage_and_tags_without_hooks():
    _reset_hostile_state()

    finding_result = append_archive_rpa_finding_publication_evidence(
        HostileTags(),
        path=HostileText(),
        finding_tag=HostileText(),
    )
    failure_result = append_archive_rpa_failure_publication_evidence(
        HostileTags(),
        path=HostileText(),
        stage=HostileText(),
        exc=ValueError("owned failure"),
        failure_tag=HostileText(),
    )

    _assert_no_hostile_hooks()
    assert "archive_rpa_finding_tag_unsafe" in finding_result
    assert "archive_rpa_finding:archive_rpa_finding_tag_unsafe" in finding_result
    assert "archive_rpa_finding_path" not in finding_result
    assert "archive_rpa_stage_unsafe_scan_error" in failure_result
    assert "archive_rpa_failure_tag_unsafe" in failure_result
    assert "archive_rpa_failure:archive_rpa_failure_tag_unsafe" in failure_result
    assert "archive_rpa_failure_path" not in failure_result
    assert "archive_final_json_must_record" in finding_result
    assert "archive_final_json_must_record" in failure_result


def test_archive_ecosystem_boundary_evidence_rejects_hostile_limited_without_hooks():
    _reset_hostile_state()

    result = append_archive_ecosystem_boundary_evidence(
        HostileTags(),
        path=HostileText(),
        boundary_tag=HostileText(),
        score=1.0,
        limited=HostileLimited(),
    )

    _assert_no_hostile_hooks()
    assert "tag_normalization_failure_evidence" in result
    assert "archive_ecosystem_boundary_tag_unsafe" in result
    assert "archive_ecosystem_boundary:archive_ecosystem_boundary_tag_unsafe" in result
    assert "archive_ecosystem_limited_flag_unsafe" in result
    assert "archive_ecosystem_boundary_path" not in result
    assert "archive_final_json_must_record" in result


def test_archive_evidence_preserves_exact_primitive_behavior():
    finding = append_archive_member_finding_publication_evidence(
        ["existing"],
        path="sample.zip",
        member_name="member.bin",
        finding_tag="pickle_payload",
    )
    rpa_failure = append_archive_rpa_failure_publication_evidence(
        ["existing"],
        path="game.rpa",
        stage="raw",
        exc=ValueError("owned failure"),
        failure_tag="rpa_scan_error",
    )
    ecosystem = append_archive_ecosystem_boundary_evidence(
        ["existing"],
        path="sample.zip",
        boundary_tag="archive_ecosystem_high_risk",
        score=0.8,
        limited=True,
    )

    assert "existing" in finding
    assert "pickle_payload" in finding
    assert "archive_member_finding_member" in finding
    assert "archive_rpa_failure:rp_scan_error" not in rpa_failure
    assert "archive_rpa_failure:rpa_scan_error" in rpa_failure
    assert "archive_rpa_failure_path" in rpa_failure
    assert "archive_ecosystem_high_risk" in ecosystem
    assert "archive_ecosystem_member_scan_limited" in ecosystem
