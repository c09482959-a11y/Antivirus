"""Strict STIX 2.x importer for official Enterprise ATT&CK bundles."""
from __future__ import annotations

import json

from Virus_Scan.detection.attack.contracts import AttackDatasetVersion
from Virus_Scan.detection.attack.domain_contracts import (
    AttackCampaign, AttackGroup, AttackMitigation, AttackRelationship,
    AttackSoftware, AttackSubTechnique, AttackTactic, AttackTechnique,
)
from Virus_Scan.detection.attack.named_contracts import (
    AttackAnalytic,
    AttackDataComponent,
    AttackDataSource,
    AttackDetectionStrategy,
    AttackLogSource,
    AttackLogSourceReference,
    AttackMutableElement,
)
from Virus_Scan.detection.attack.repository import build_repository_snapshot
from Virus_Scan.detection.attack.validation import stix_id
from Virus_Scan.detection.attack.versioning import ATTACK_REPOSITORY_SCHEMA_VERSION

_SUPPORTED_NAMED_TYPES = frozenset({
    "attack-pattern", "x-mitre-tactic", "course-of-action", "intrusion-set",
    "malware", "tool", "campaign", "x-mitre-data-source",
    "x-mitre-data-component", "x-mitre-analytic", "x-mitre-detection-strategy",
})


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in out:
            raise ValueError("attack_stix_duplicate_json_key")
        out[str.__str__(key)] = value
    return out


def _reject_constant(_value: str) -> object:
    raise ValueError("attack_stix_nonfinite_json_value")


def _dict(value: object, reason: str) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError(reason)
    return value


def _text(data: dict[str, object], key: str, *, blank: bool = False) -> str:
    value = dict.get(data, key, "")
    if type(value) is not str or (not blank and value == ""):
        raise ValueError("attack_stix_" + key + "_invalid")
    return str.__str__(value)


def _bool(data: dict[str, object], key: str) -> bool:
    value = dict.get(data, key, False)
    if type(value) is not bool:
        raise TypeError("attack_stix_" + key + "_invalid")
    return value


def _string_tuple(value: object, reason: str, *, limit: int = 64) -> tuple[str, ...]:
    if type(value) is not list or len(value) > limit or any(type(item) is not str for item in value):
        raise TypeError(reason)
    out = tuple(str.__str__(item) for item in value)
    if len(out) != len(set(out)):
        raise ValueError(reason)
    return tuple(sorted(out))


def _external_id(data: dict[str, object]) -> str:
    refs = dict.get(data, "external_references", [])
    if type(refs) is not list or len(refs) > 64:
        raise TypeError("attack_stix_external_references_invalid")
    found: list[str] = []
    for raw in refs:
        ref = _dict(raw, "attack_stix_external_reference_invalid")
        source = dict.get(ref, "source_name", "")
        value = dict.get(ref, "external_id", "")
        if source == "mitre-attack" and type(value) is str and value:
            found.append(str.__str__(value))
    if len(found) != len(set(found)) or len(found) > 1:
        raise ValueError("attack_stix_conflicting_external_ids")
    return found[0] if found else ""


def _tactic_ids(data: dict[str, object], tactic_by_shortname: dict[str, str]) -> tuple[str, ...]:
    phases = dict.get(data, "kill_chain_phases", [])
    if type(phases) is not list or len(phases) > 64:
        raise TypeError("attack_stix_kill_chain_phases_invalid")
    ids: list[str] = []
    for raw in phases:
        phase = _dict(raw, "attack_stix_kill_chain_phase_invalid")
        chain_name = dict.get(phase, "kill_chain_name", "mitre-attack")
        short = dict.get(phase, "phase_name", "")
        if chain_name == "mitre-attack" and type(short) is str and short in tactic_by_shortname:
            ids.append(tactic_by_shortname[short])
    return tuple(sorted(set(ids)))


def _common(item: dict[str, object]) -> dict[str, object]:
    return {
        "stix_id": _text(item, "id"),
        "name": _text(item, "name"),
        "description": _text(item, "description", blank=True),
        "revoked": _bool(item, "revoked"),
        "deprecated": _bool(item, "x_mitre_deprecated"),
    }


def _exact_nested_keys(
    value: dict[str, object],
    expected: frozenset[str],
    reason: str,
) -> None:
    if frozenset(dict.keys(value)) != expected:
        raise ValueError(reason)


def _defensive_common(
    item: dict[str, object],
    external_id: str,
    prefix: str,
) -> dict[str, object]:
    common = _common(item)
    if not external_id or not external_id.startswith(prefix):
        raise ValueError("attack_stix_defensive_external_id_invalid")
    domains = _string_tuple(
        dict.get(item, "x_mitre_domains", []),
        "attack_stix_domains_invalid",
        limit=8,
    )
    if (
        not common["revoked"]
        and not common["deprecated"]
        and "enterprise-attack" not in domains
    ):
        raise ValueError("attack_stix_enterprise_domain_required")
    return {
        "attack_id": external_id,
        "domains": domains,
        "object_version": _text(item, "x_mitre_version"),
        "attack_spec_version": _text(item, "x_mitre_attack_spec_version"),
        "modified": _text(item, "modified"),
        **common,
    }


def _log_sources(item: dict[str, object]) -> tuple[AttackLogSource, ...]:
    raw = dict.get(item, "x_mitre_log_sources", [])
    if type(raw) is not list or len(raw) > 512:
        raise TypeError("attack_stix_log_sources_invalid")
    values: list[AttackLogSource] = []
    for entry in raw:
        record = _dict(entry, "attack_stix_log_source_invalid")
        _exact_nested_keys(
            record,
            frozenset({"name", "channel"}),
            "attack_stix_log_source_keys_invalid",
        )
        values.append(AttackLogSource(
            name=_text(record, "name"),
            channel=_text(record, "channel"),
        ))
    if len(values) != len(set(values)):
        raise ValueError("attack_stix_log_sources_duplicate")
    return tuple(sorted(values))


def _log_source_references(
    item: dict[str, object],
) -> tuple[AttackLogSourceReference, ...]:
    raw = dict.get(item, "x_mitre_log_source_references", [])
    if type(raw) is not list or len(raw) > 256:
        raise TypeError("attack_stix_log_source_references_invalid")
    values: list[AttackLogSourceReference] = []
    for entry in raw:
        record = _dict(entry, "attack_stix_log_source_reference_invalid")
        _exact_nested_keys(
            record,
            frozenset({"x_mitre_data_component_ref", "name", "channel"}),
            "attack_stix_log_source_reference_keys_invalid",
        )
        values.append(AttackLogSourceReference(
            data_component_stix_id=_text(
                record,
                "x_mitre_data_component_ref",
            ),
            name=_text(record, "name"),
            channel=_text(record, "channel"),
        ))
    if len(values) != len(set(values)):
        raise ValueError("attack_stix_log_source_references_duplicate")
    return tuple(sorted(values))


def _mutable_elements(item: dict[str, object]) -> tuple[AttackMutableElement, ...]:
    raw = dict.get(item, "x_mitre_mutable_elements", [])
    if type(raw) is not list or len(raw) > 128:
        raise TypeError("attack_stix_mutable_elements_invalid")
    values: list[AttackMutableElement] = []
    for entry in raw:
        record = _dict(entry, "attack_stix_mutable_element_invalid")
        _exact_nested_keys(
            record,
            frozenset({"field", "description"}),
            "attack_stix_mutable_element_keys_invalid",
        )
        values.append(AttackMutableElement(
            field=_text(record, "field"),
            description=_text(record, "description"),
        ))
    if len(values) != len(set(values)):
        raise ValueError("attack_stix_mutable_elements_duplicate")
    return tuple(sorted(values))


def _analytic_refs(item: dict[str, object]) -> tuple[str, ...]:
    refs = _string_tuple(
        dict.get(item, "x_mitre_analytic_refs", []),
        "attack_stix_analytic_refs_invalid",
        limit=128,
    )
    if any(not value.startswith("x-mitre-analytic--") for value in refs):
        raise ValueError("attack_stix_analytic_ref_invalid")
    return refs


def _parse_named(item: dict[str, object], tactic_by_shortname: dict[str, str]) -> object:
    object_type = _text(item, "type")
    common = _common(item)
    external_id = _external_id(item)
    if object_type == "x-mitre-tactic":
        shortname = _text(item, "x_mitre_shortname")
        if not external_id:
            raise ValueError("attack_tactic_external_id_required")
        return AttackTactic(attack_id=external_id, shortname=shortname, **common)
    if object_type == "attack-pattern":
        if not external_id:
            raise ValueError("attack_technique_external_id_required")
        fields = {
            "attack_id": external_id,
            "tactic_ids": _tactic_ids(item, tactic_by_shortname),
            "platforms": _string_tuple(dict.get(item, "x_mitre_platforms", []), "attack_stix_platforms_invalid"),
            **common,
        }
        if "." in external_id:
            return AttackSubTechnique(parent_attack_id=external_id.split(".", 1)[0], **fields)
        return AttackTechnique(**fields)
    if object_type == "course-of-action":
        if not external_id:
            raise ValueError("attack_mitigation_external_id_required")
        return AttackMitigation(attack_id=external_id, **common)
    if object_type == "intrusion-set":
        if not external_id:
            raise ValueError("attack_group_external_id_required")
        return AttackGroup(attack_id=external_id, **common)
    if object_type in ("malware", "tool"):
        if not external_id:
            raise ValueError("attack_software_external_id_required")
        return AttackSoftware(
            attack_id=external_id, object_type=object_type,
            platforms=_string_tuple(dict.get(item, "x_mitre_platforms", []), "attack_stix_platforms_invalid"),
            **common,
        )
    if object_type == "campaign":
        if not external_id:
            raise ValueError("attack_campaign_external_id_required")
        return AttackCampaign(attack_id=external_id, **common)
    if object_type == "x-mitre-data-source":
        fields = _defensive_common(item, external_id, "DS")
        return AttackDataSource(
            platforms=_string_tuple(
                dict.get(item, "x_mitre_platforms", []),
                "attack_stix_platforms_invalid",
            ),
            **fields,
        )
    if object_type == "x-mitre-data-component":
        return AttackDataComponent(
            log_sources=_log_sources(item),
            **_defensive_common(item, external_id, "DC"),
        )
    if object_type == "x-mitre-analytic":
        return AttackAnalytic(
            platforms=_string_tuple(
                dict.get(item, "x_mitre_platforms", []),
                "attack_stix_platforms_invalid",
            ),
            log_source_references=_log_source_references(item),
            mutable_elements=_mutable_elements(item),
            **_defensive_common(item, external_id, "AN"),
        )
    if object_type == "x-mitre-detection-strategy":
        return AttackDetectionStrategy(
            analytic_stix_ids=_analytic_refs(item),
            **_defensive_common(item, external_id, "DET"),
        )
    raise ValueError("attack_stix_named_type_unsupported")


def import_stix_bundle(
    data: bytes,
    *,
    dataset_version: str,
    source_ref: str,
    expected_git_blob_sha1: str,
    computed_git_blob_sha1: str,
    local_sha256: str,
):
    if type(data) is not bytes or len(data) > 256 * 1024 * 1024:
        raise TypeError("attack_stix_bundle_bytes_invalid")
    root = _dict(json.loads(
        data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_constant,
    ), "attack_stix_bundle_mapping_required")
    if dict.get(root, "type") != "bundle":
        raise ValueError("attack_stix_bundle_type_invalid")
    stix_id(_text(root, "id"), "attack_stix_bundle_id_invalid")
    raw_objects = dict.get(root, "objects")
    if type(raw_objects) is not list or not raw_objects or len(raw_objects) > 200_000:
        raise ValueError("attack_stix_bundle_objects_invalid")
    parsed = tuple(_dict(item, "attack_stix_object_mapping_required") for item in raw_objects)
    seen_stix_ids: set[str] = set()
    for item in parsed:
        object_type = _text(item, "type")
        object_id = stix_id(_text(item, "id"))
        if not object_id.startswith(object_type + "--"):
            raise ValueError("attack_stix_object_identity_type_mismatch")
        if object_id in seen_stix_ids:
            raise ValueError("attack_stix_duplicate_object_identity")
        seen_stix_ids.add(object_id)
    tactic_by_shortname: dict[str, str] = {}
    for item in parsed:
        if dict.get(item, "type") != "x-mitre-tactic":
            continue
        external_id = _external_id(item)
        short = dict.get(item, "x_mitre_shortname", "")
        if type(short) is not str or not external_id:
            raise ValueError("attack_tactic_identity_invalid")
        if short in tactic_by_shortname or external_id in tactic_by_shortname.values():
            raise ValueError("attack_tactic_identity_duplicate")
        tactic_by_shortname[str.__str__(short)] = external_id
    objects: list[object] = []
    relationships: list[AttackRelationship] = []
    for item in parsed:
        object_type = _text(item, "type")
        if object_type == "relationship":
            relationships.append(AttackRelationship(
                stix_id=_text(item, "id"), relationship_type=_text(item, "relationship_type"),
                source_stix_id=_text(item, "source_ref"), target_stix_id=_text(item, "target_ref"),
                description=_text(item, "description", blank=True), revoked=_bool(item, "revoked"),
            ))
        elif object_type in _SUPPORTED_NAMED_TYPES:
            objects.append(_parse_named(item, tactic_by_shortname))
    version = AttackDatasetVersion(
        dataset_version=dataset_version, schema_version=ATTACK_REPOSITORY_SCHEMA_VERSION,
        source_ref=source_ref, expected_git_blob_sha1=expected_git_blob_sha1,
        computed_git_blob_sha1=computed_git_blob_sha1, local_sha256=local_sha256,
    )
    return build_repository_snapshot(version=version, objects=tuple(objects), relationships=tuple(relationships))


__all__ = ("import_stix_bundle",)
