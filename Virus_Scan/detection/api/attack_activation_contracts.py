"""Public immutable ATT&CK activation-set contract."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from Virus_Scan.detection.attack.validation import exact_hex, ordered_text_tuple

ATTACK_ACTIVATION_SCHEMA_VERSION = "stage2636_10011_attack_activation_v1"


def _identity_tuple(value: object, reason: str) -> tuple[str, ...]:
    return ordered_text_tuple(value, reason, maximum_items=4096)


@dataclass(frozen=True, slots=True)
class AttackActivationRecord:
    dataset_version: str
    repository_digest: str
    active_alignment_ids: tuple[str, ...]
    quarantined_alignment_ids: tuple[str, ...]
    active_implementation_ids: tuple[str, ...]
    quarantined_implementation_ids: tuple[str, ...]
    active_policy_ids: tuple[str, ...]
    quarantined_policy_ids: tuple[str, ...]
    retired_policy_ids: tuple[str, ...]
    active_calibration_ids: tuple[str, ...]
    quarantined_calibration_ids: tuple[str, ...]
    activation_digest: str = ""
    schema_version: str = ATTACK_ACTIVATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackActivationRecord:
            raise TypeError("attack_activation_owner_invalid")
        object.__setattr__(self, "dataset_version", exact_hex(
            self.dataset_version, "attack_activation_dataset_invalid", length=40,
        ))
        object.__setattr__(self, "repository_digest", exact_hex(
            self.repository_digest, "attack_activation_repository_digest_invalid", length=64,
        ))
        names = (
            "active_alignment_ids", "quarantined_alignment_ids",
            "active_implementation_ids", "quarantined_implementation_ids",
            "active_policy_ids", "quarantined_policy_ids", "retired_policy_ids",
            "active_calibration_ids", "quarantined_calibration_ids",
        )
        for name in names:
            values = _identity_tuple(
                object.__getattribute__(self, name),
                "attack_activation_identity_set_invalid",
            )
            if values != tuple(sorted(set(values))):
                raise ValueError("attack_activation_identity_set_invalid")
            object.__setattr__(self, name, values)
        if set(self.active_alignment_ids) & set(self.quarantined_alignment_ids):
            raise ValueError("attack_activation_alignment_overlap")
        if set(self.active_implementation_ids) & set(self.quarantined_implementation_ids):
            raise ValueError("attack_activation_implementation_overlap")
        policy_sets = (
            set(self.active_policy_ids), set(self.quarantined_policy_ids),
            set(self.retired_policy_ids),
        )
        if any(policy_sets[i] & policy_sets[j] for i in range(3) for j in range(i + 1, 3)):
            raise ValueError("attack_activation_policy_overlap")
        if set(self.active_calibration_ids) & set(self.quarantined_calibration_ids):
            raise ValueError("attack_activation_calibration_overlap")
        if self.schema_version != ATTACK_ACTIVATION_SCHEMA_VERSION:
            raise ValueError("attack_activation_schema_invalid")
        payload = self._record(include_digest=False)
        computed = sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
        supplied = self.activation_digest
        if type(supplied) is not str or (supplied and supplied != computed):
            raise ValueError("attack_activation_digest_invalid")
        object.__setattr__(self, "activation_digest", computed)
        object.__setattr__(self, "schema_version", ATTACK_ACTIVATION_SCHEMA_VERSION)

    def _record(self, *, include_digest: bool) -> dict[str, object]:
        record = {
            "schema_version": self.schema_version,
            "dataset_version": self.dataset_version,
            "repository_digest": self.repository_digest,
            "active_alignment_ids": self.active_alignment_ids,
            "quarantined_alignment_ids": self.quarantined_alignment_ids,
            "active_implementation_ids": self.active_implementation_ids,
            "quarantined_implementation_ids": self.quarantined_implementation_ids,
            "active_policy_ids": self.active_policy_ids,
            "quarantined_policy_ids": self.quarantined_policy_ids,
            "retired_policy_ids": self.retired_policy_ids,
            "active_calibration_ids": self.active_calibration_ids,
            "quarantined_calibration_ids": self.quarantined_calibration_ids,
        }
        if include_digest:
            record["activation_digest"] = self.activation_digest
        return record

    def to_record(self) -> dict[str, object]:
        return self._record(include_digest=True)

    def counts(self) -> dict[str, int]:
        return {
            "active_alignments": len(self.active_alignment_ids),
            "quarantined_alignments": len(self.quarantined_alignment_ids),
            "active_implementations": len(self.active_implementation_ids),
            "quarantined_implementations": len(self.quarantined_implementation_ids),
            "active_policies": len(self.active_policy_ids),
            "quarantined_policies": len(self.quarantined_policy_ids),
            "retired_policies": len(self.retired_policy_ids),
            "active_calibrations": len(self.active_calibration_ids),
            "quarantined_calibrations": len(self.quarantined_calibration_ids),
        }


__all__ = ("ATTACK_ACTIVATION_SCHEMA_VERSION", "AttackActivationRecord")
