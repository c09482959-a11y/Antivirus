"""Stage 1527 Phase 1 profile evidence exact-text boundary tests."""

from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.profiles.baseline import profile_behavior_bucket_validation, profile_tag_behavior_bucket
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest
from Virus_Scan.models.profiles.evidence import (
    _profile_support_unavailable,
    extension_profile_unavailable,
    merge_profile_subsignal_unavailable,
)


class HostileText(str):
    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw strip() was used
        raise AssertionError("caller-owned strip() was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness was probed
        raise AssertionError("caller-owned truthiness was invoked")


class HostileAffectedFields:
    def __bool__(self):  # pragma: no cover - failure proves caller-owned truthiness was probed
        raise AssertionError("affected_fields truthiness was invoked")

    def __iter__(self):
        return iter((HostileText("profile_anomaly"), HostileText("support")))


def test_stage1527_profile_extension_unavailable_detaches_hostile_text() -> None:
    record = extension_profile_unavailable(
        HostileText(".rpy"),
        HostileText("insufficient_extension_history"),
        files_seen=0,
    )

    assert record["extension"] == ".rpy"
    assert record["unavailable_reason"] == "insufficient_extension_history"
    assert record["evidence_type"] == "profile_extension_anomaly"
    assert record["model_failures"][0]["details"]["support_field"] == "files_seen"
    assert record["final_json_must_record"] is True
    assert record["replay_record_required"] is True


def test_stage1527_profile_subsignal_merge_detaches_field_and_reason_text() -> None:
    unavailable_reasons: dict[str, str] = {}
    model_failures: list[dict[str, object]] = []

    merge_profile_subsignal_unavailable(
        HostileText("vector_validation"),
        {
            "degraded": True,
            "unavailable_reason": HostileText("nested_profile_unavailable"),
            "model_failures": ({"model_name": "profiles", "reason": "nested"},),
        },
        unavailable_reasons,
        model_failures,
    )

    assert unavailable_reasons == {"vector_validation": "nested_profile_unavailable"}
    assert model_failures == [{"model_name": "profiles", "reason": "nested"}]


def test_stage1527_profile_support_unavailable_does_not_probe_affected_field_truthiness() -> None:
    record = _profile_support_unavailable(
        HostileText("support_unavailable"),
        evidence_type=HostileText("profile_support_evidence"),
        failure_type=HostileText("profile_support_failure"),
        affected_fields=HostileAffectedFields(),
        support_field=HostileText("samples_seen"),
        support=object(),
    )

    assert record["evidence_type"] == "profile_support_evidence"
    assert record["samples_seen"] == 0
    assert record["samples_seen_unavailable_reason"] == "invalid_samples_seen"
    failure = record["model_failures"][0]
    assert failure["failure_type"] == "profile_support_failure"
    assert failure["affected_fields"] == ("profile_anomaly", "support")
    assert failure["details"]["support_field"] == "samples_seen"


def test_stage1527_profile_bucket_classification_detaches_hostile_tag_text() -> None:
    tag = HostileText("credential_dump")

    assert profile_tag_behavior_bucket(tag) == "credential"

    validation = profile_behavior_bucket_validation(ProfileBucketValidationRequest("renpy", "sample.rpy", physical_tag_evidence(("credential_dump",))))

    assert validation["records"][0]["tag"] == "credential_dump"
    assert validation["records"][0]["bucket"] == "credential"
    assert validation["final_json_must_record"] is not False if "final_json_must_record" in validation else True
