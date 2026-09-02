from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import (
    EvidenceObjectSnapshot,
    ResultEvidenceSnapshot,
    ResultIdentitySnapshot,
    ResultRecordCollectionSnapshot,
)


def test_stage1027_result_identity_snapshot_normalizes_direct_constructor_values() -> None:
    identity = ResultIdentitySnapshot(file=" file.bin ", path=None, input_file_path=123)  # type: ignore[arg-type]

    assert identity.file == "file.bin"
    assert identity.path == ""
    assert identity.input_file_path == "123"
    with pytest.raises(AttributeError):
        identity.file = "mutated"  # type: ignore[misc]


def test_stage1027_result_evidence_snapshot_deep_freezes_tag_and_chain_inputs() -> None:
    tags = [" tag_a ", "tag_b"]
    chains = ["chain_a"]
    snapshot = ResultEvidenceSnapshot(
        verdict=" MALICIOUS ",
        score="70.5",  # type: ignore[arg-type]
        tags=tags,  # type: ignore[arg-type]
        chains=chains,  # type: ignore[arg-type]
        yara_count=True,  # type: ignore[arg-type]
        decoded_count=None,  # type: ignore[arg-type]
        model_evidence_count=2,
        error_present="",  # type: ignore[arg-type]
        explanation_present=1,  # type: ignore[arg-type]
    )

    tags.append("mutated")
    chains.append("mutated")

    assert snapshot.verdict == "malicious"
    assert snapshot.score == 70.5
    assert snapshot.tags == ("tag_a", "tag_b")
    assert snapshot.chains == ("chain_a",)
    assert snapshot.yara_count == 1
    assert snapshot.decoded_count == 0
    assert snapshot.error_present is False
    assert snapshot.explanation_present is True
    with pytest.raises(AttributeError):
        snapshot.tags = ()  # type: ignore[misc]


def test_stage1027_result_collection_snapshot_deep_freezes_identities() -> None:
    identities = ["a.bin"]
    snapshot = ResultRecordCollectionSnapshot(identities)  # type: ignore[arg-type]

    identities.append("b.bin")

    assert snapshot.identities == ("a.bin",)
    with pytest.raises(AttributeError):
        snapshot.identities = ()  # type: ignore[misc]


def test_stage1027_evidence_object_snapshot_normalizes_direct_constructor_values() -> None:
    snapshot = EvidenceObjectSnapshot(key=" evidence ", count=True)  # type: ignore[arg-type]

    assert snapshot.key == "evidence"
    assert snapshot.count == 1
    with pytest.raises(AttributeError):
        snapshot.count = 99  # type: ignore[misc]
