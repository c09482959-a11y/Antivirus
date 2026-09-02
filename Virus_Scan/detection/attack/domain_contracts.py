"""Frozen official Enterprise ATT&CK object-family contracts."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass

from Virus_Scan.detection.attack.named_contracts import ATTACK_STIX_ONLY_OBJECT_TYPES
from Virus_Scan.detection.attack.validation import exact_bool, official_attack_id, ordered_text_tuple, stix_id


def _attack_id(value: object, prefix: str, reason: str, *, subtechnique: bool | None = None) -> str:
    attack_id = official_attack_id(value, reason)
    if not attack_id.startswith(prefix):
        raise ValueError(reason)
    if subtechnique is True and "." not in attack_id:
        raise ValueError(reason)
    if subtechnique is False and "." in attack_id:
        raise ValueError(reason)
    return attack_id


def _named_record(value: object) -> dict[str, object]:
    return {
        "attack_id": getattr(value, "attack_id", ""),
        "stix_id": value.stix_id,
        "object_type": value.object_type,
        "name": value.name,
        "description": value.description,
        "revoked": value.revoked,
        "deprecated": value.deprecated,
    }


def _validate_named(value: object, owner: type, expected_type: str) -> None:
    if type(value) is not owner:
        raise TypeError("attack_domain_owner_invalid")
    object.__setattr__(value, "stix_id", stix_id(value.stix_id))
    object_type = exact_bounded_text(value.object_type, "attack_object_type_invalid", maximum=64)
    if object_type != expected_type:
        raise ValueError("attack_object_type_invalid")
    object.__setattr__(value, "object_type", object_type)
    object.__setattr__(value, "name", exact_bounded_text(value.name, "attack_object_name_invalid", maximum=256))
    object.__setattr__(value, "description", exact_bounded_text(value.description, "attack_object_description_invalid", maximum=16384, allow_blank=True))
    object.__setattr__(value, "revoked", exact_bool(value.revoked, "attack_object_revoked_invalid"))
    object.__setattr__(value, "deprecated", exact_bool(value.deprecated, "attack_object_deprecated_invalid"))


@dataclass(frozen=True, slots=True)
class AttackTactic:
    attack_id: str
    stix_id: str
    name: str
    shortname: str
    description: str = ""
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "x-mitre-tactic"

    def __post_init__(self) -> None:
        _validate_named(self, AttackTactic, "x-mitre-tactic")
        object.__setattr__(self, "attack_id", _attack_id(self.attack_id, "TA", "attack_tactic_id_invalid"))
        object.__setattr__(self, "shortname", exact_bounded_text(self.shortname, "attack_tactic_shortname_invalid", maximum=128))

    def to_record(self) -> dict[str, object]:
        return {**_named_record(self), "shortname": self.shortname}


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    attack_id: str
    stix_id: str
    name: str
    tactic_ids: tuple[str, ...]
    description: str = ""
    revoked: bool = False
    deprecated: bool = False
    platforms: tuple[str, ...] = ()
    object_type: str = "attack-pattern"

    def __post_init__(self) -> None:
        _validate_named(self, AttackTechnique, "attack-pattern")
        object.__setattr__(self, "attack_id", _attack_id(self.attack_id, "T", "attack_technique_id_invalid", subtechnique=False))
        _validate_technique_fields(self)

    def to_record(self) -> dict[str, object]:
        return {**_named_record(self), "tactic_ids": self.tactic_ids, "platforms": self.platforms, "parent_attack_id": ""}


@dataclass(frozen=True, slots=True)
class AttackSubTechnique:
    attack_id: str
    parent_attack_id: str
    stix_id: str
    name: str
    tactic_ids: tuple[str, ...]
    description: str = ""
    revoked: bool = False
    deprecated: bool = False
    platforms: tuple[str, ...] = ()
    object_type: str = "attack-pattern"

    def __post_init__(self) -> None:
        _validate_named(self, AttackSubTechnique, "attack-pattern")
        attack_id = _attack_id(self.attack_id, "T", "attack_subtechnique_id_invalid", subtechnique=True)
        parent = _attack_id(self.parent_attack_id, "T", "attack_parent_id_invalid", subtechnique=False)
        if attack_id.split(".", 1)[0] != parent:
            raise ValueError("attack_parent_id_mismatch")
        object.__setattr__(self, "attack_id", attack_id)
        object.__setattr__(self, "parent_attack_id", parent)
        _validate_technique_fields(self)

    def to_record(self) -> dict[str, object]:
        return {**_named_record(self), "tactic_ids": self.tactic_ids, "platforms": self.platforms, "parent_attack_id": self.parent_attack_id}


def _validate_technique_fields(value: object) -> None:
    tactics = ordered_text_tuple(value.tactic_ids, "attack_technique_tactics_invalid", maximum_items=32)
    if any(not _attack_id(item, "TA", "attack_technique_tactic_id_invalid") for item in tactics):
        raise ValueError("attack_technique_tactic_id_invalid")
    object.__setattr__(value, "tactic_ids", tactics)
    object.__setattr__(value, "platforms", ordered_text_tuple(value.platforms, "attack_object_platforms_invalid", maximum_items=64))


@dataclass(frozen=True, slots=True)
class AttackMitigation:
    attack_id: str
    stix_id: str
    name: str
    description: str = ""
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "course-of-action"

    def __post_init__(self) -> None:
        _validate_named(self, AttackMitigation, "course-of-action")
        attack_id = official_attack_id(
            self.attack_id,
            "attack_mitigation_id_invalid",
        )
        active_identity = attack_id.startswith("M")
        legacy_deprecated_identity = self.deprecated and attack_id.startswith("T")
        if not active_identity and not legacy_deprecated_identity:
            raise ValueError("attack_mitigation_id_invalid")
        object.__setattr__(self, "attack_id", attack_id)

    def to_record(self) -> dict[str, object]:
        return _named_record(self)


@dataclass(frozen=True, slots=True)
class AttackGroup:
    attack_id: str
    stix_id: str
    name: str
    description: str = ""
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "intrusion-set"

    def __post_init__(self) -> None:
        _validate_named(self, AttackGroup, "intrusion-set")
        object.__setattr__(self, "attack_id", _attack_id(self.attack_id, "G", "attack_group_id_invalid"))

    def to_record(self) -> dict[str, object]:
        return _named_record(self)


@dataclass(frozen=True, slots=True)
class AttackSoftware:
    attack_id: str
    stix_id: str
    object_type: str
    name: str
    description: str = ""
    revoked: bool = False
    deprecated: bool = False
    platforms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object_type = exact_bounded_text(self.object_type, "attack_software_type_invalid", maximum=64)
        if object_type not in ("malware", "tool"):
            raise ValueError("attack_software_type_invalid")
        _validate_named(self, AttackSoftware, object_type)
        object.__setattr__(self, "attack_id", _attack_id(self.attack_id, "S", "attack_software_id_invalid"))
        object.__setattr__(self, "platforms", ordered_text_tuple(self.platforms, "attack_object_platforms_invalid", maximum_items=64))

    def to_record(self) -> dict[str, object]:
        return {**_named_record(self), "platforms": self.platforms}


@dataclass(frozen=True, slots=True)
class AttackCampaign:
    attack_id: str
    stix_id: str
    name: str
    description: str = ""
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "campaign"

    def __post_init__(self) -> None:
        _validate_named(self, AttackCampaign, "campaign")
        object.__setattr__(self, "attack_id", _attack_id(self.attack_id, "C", "attack_campaign_id_invalid"))

    def to_record(self) -> dict[str, object]:
        return _named_record(self)


@dataclass(frozen=True, slots=True)
class AttackRelationship:
    stix_id: str
    relationship_type: str
    source_stix_id: str
    target_stix_id: str
    description: str = ""
    revoked: bool = False

    def __post_init__(self) -> None:
        if type(self) is not AttackRelationship:
            raise TypeError("attack_relationship_owner_invalid")
        object.__setattr__(self, "stix_id", stix_id(self.stix_id))
        object.__setattr__(self, "relationship_type", exact_bounded_text(self.relationship_type, "attack_relationship_type_invalid", maximum=64))
        object.__setattr__(self, "source_stix_id", stix_id(self.source_stix_id, "attack_relationship_source_invalid"))
        object.__setattr__(self, "target_stix_id", stix_id(self.target_stix_id, "attack_relationship_target_invalid"))
        object.__setattr__(self, "description", exact_bounded_text(self.description, "attack_relationship_description_invalid", maximum=16384, allow_blank=True))
        object.__setattr__(self, "revoked", exact_bool(self.revoked, "attack_relationship_revoked_invalid"))

    def to_record(self) -> dict[str, object]:
        return {
            "stix_id": self.stix_id, "relationship_type": self.relationship_type,
            "source_stix_id": self.source_stix_id, "target_stix_id": self.target_stix_id,
            "description": self.description, "revoked": self.revoked,
        }


ATTACK_DOMAIN_OBJECT_TYPES = (
    AttackTactic, AttackTechnique, AttackSubTechnique, AttackMitigation,
    AttackGroup, AttackSoftware, AttackCampaign,
) + ATTACK_STIX_ONLY_OBJECT_TYPES
ATTACK_TECHNIQUE_TYPES = (AttackTechnique, AttackSubTechnique)

__all__ = (
    "ATTACK_DOMAIN_OBJECT_TYPES", "ATTACK_TECHNIQUE_TYPES", "AttackCampaign",
    "AttackGroup", "AttackMitigation", "AttackRelationship", "AttackSoftware",
    "AttackSubTechnique", "AttackTactic", "AttackTechnique",
)
