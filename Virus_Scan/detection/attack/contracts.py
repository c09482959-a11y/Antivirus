"""Immutable official Enterprise ATT&CK dataset-version contract."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass

from Virus_Scan.detection.attack.validation import exact_hex
from Virus_Scan.detection.attack.versioning import ATTACK_REPOSITORY_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class AttackDatasetVersion:
    dataset_version: str
    schema_version: str
    source_ref: str
    expected_git_blob_sha1: str
    computed_git_blob_sha1: str
    local_sha256: str

    def __post_init__(self) -> None:
        if type(self) is not AttackDatasetVersion:
            raise TypeError("attack_dataset_version_owner_invalid")
        dataset = exact_hex(self.dataset_version, "attack_dataset_version_invalid", length=40)
        expected = exact_hex(self.expected_git_blob_sha1, "attack_git_blob_sha1_invalid", length=40)
        computed = exact_hex(self.computed_git_blob_sha1, "attack_git_blob_sha1_invalid", length=40)
        if dataset != expected or expected != computed:
            raise ValueError("attack_dataset_identity_mismatch")
        if self.schema_version != ATTACK_REPOSITORY_SCHEMA_VERSION:
            raise ValueError("attack_repository_schema_version_invalid")
        object.__setattr__(self, "dataset_version", dataset)
        object.__setattr__(self, "schema_version", ATTACK_REPOSITORY_SCHEMA_VERSION)
        object.__setattr__(self, "source_ref", exact_bounded_text(self.source_ref, "attack_source_ref_invalid", maximum=256))
        object.__setattr__(self, "expected_git_blob_sha1", expected)
        object.__setattr__(self, "computed_git_blob_sha1", computed)
        object.__setattr__(self, "local_sha256", exact_hex(self.local_sha256, "attack_sha256_invalid", length=64))


__all__ = ("AttackDatasetVersion",)
