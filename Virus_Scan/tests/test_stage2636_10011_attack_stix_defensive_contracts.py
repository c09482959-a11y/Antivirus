from __future__ import annotations

from copy import deepcopy
import json

import pytest

from Virus_Scan.detection.attack.integrity import git_blob_sha1_bytes, sha256_bytes
from Virus_Scan.detection.attack.named_contracts import (
    AttackAnalytic,
    AttackDataComponent,
    AttackDetectionStrategy,
    AttackLogSource,
    AttackLogSourceReference,
    AttackMutableElement,
)
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.detection.attack.validation import official_attack_id, stix_timestamp


class _TrapString(str):
    called = False

    def __str__(self) -> str:
        type(self).called = True
        raise AssertionError("hook executed")

    def __bool__(self) -> bool:
        type(self).called = True
        raise AssertionError("hook executed")


class _TrapTuple(tuple):
    called = False

    def __iter__(self):
        type(self).called = True
        raise AssertionError("hook executed")


_TIMESTAMP = "2025-10-21T14:00:00.000Z"
_DATA_COMPONENT_ID = "x-mitre-data-component--00000001-0000-4000-8000-000000000001"
_ANALYTIC_ID = "x-mitre-analytic--00000002-0000-4000-8000-000000000002"
_STRATEGY_ID = "x-mitre-detection-strategy--00000003-0000-4000-8000-000000000003"
_TECHNIQUE_ID = "attack-pattern--00000005-0000-4000-8000-000000000005"
_RELATIONSHIP_ID = "relationship--00000006-0000-4000-8000-000000000006"


def _bundle_objects() -> list[dict[str, object]]:
    return [
        {
            "type": "x-mitre-data-component",
            "id": _DATA_COMPONENT_ID,
            "name": "Process Access",
            "description": "Process access telemetry.",
            "modified": _TIMESTAMP,
            "x_mitre_domains": ["enterprise-attack"],
            "x_mitre_version": "1.0",
            "x_mitre_attack_spec_version": "3.3.0",
            "x_mitre_log_sources": [
                {"name": "WinEventLog:Security", "channel": "EventCode=4656"},
                {"name": "Sysmon", "channel": "EventCode=10"},
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "DC0001"},
            ],
        },
        {
            "type": "x-mitre-analytic",
            "id": _ANALYTIC_ID,
            "name": "Suspicious Process Access",
            "description": "Correlate target process access events.",
            "modified": _TIMESTAMP,
            "x_mitre_platforms": ["Windows"],
            "x_mitre_domains": ["enterprise-attack"],
            "x_mitre_version": "1.1",
            "x_mitre_attack_spec_version": "3.3.0",
            "x_mitre_log_source_references": [
                {
                    "x_mitre_data_component_ref": _DATA_COMPONENT_ID,
                    "name": "Sysmon",
                    "channel": "EventCode=10",
                },
            ],
            "x_mitre_mutable_elements": [
                {
                    "field": "TargetImage",
                    "description": "Tune the protected target process set.",
                },
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "AN0001"},
            ],
        },
        {
            "type": "x-mitre-detection-strategy",
            "id": _STRATEGY_ID,
            "name": "Detect Suspicious Process Access",
            "description": "Detect process access associated with credential access.",
            "modified": _TIMESTAMP,
            "x_mitre_domains": ["enterprise-attack"],
            "x_mitre_version": "1.2",
            "x_mitre_attack_spec_version": "3.3.0",
            "x_mitre_analytic_refs": [_ANALYTIC_ID],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "DET0001"},
            ],
        },
        {
            "type": "attack-pattern",
            "id": _TECHNIQUE_ID,
            "name": "OS Credential Dumping",
            "description": "Credential dumping technique.",
            "x_mitre_platforms": ["Windows"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1003"},
            ],
        },
        {
            "type": "relationship",
            "id": _RELATIONSHIP_ID,
            "relationship_type": "detects",
            "source_ref": _STRATEGY_ID,
            "target_ref": _TECHNIQUE_ID,
            "description": "The strategy detects the technique.",
        },
    ]


def _bundle(objects: list[dict[str, object]] | None = None) -> bytes:
    payload = {
        "type": "bundle",
        "id": "bundle--00000004-0000-4000-8000-000000000004",
        "objects": _bundle_objects() if objects is None else objects,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _snapshot(payload: bytes | None = None):
    data = _bundle() if payload is None else payload
    identity = git_blob_sha1_bytes(data)
    return import_stix_bundle(
        data,
        dataset_version=identity,
        source_ref="stage2636.10011-test",
        expected_git_blob_sha1=identity,
        computed_git_blob_sha1=identity,
        local_sha256=sha256_bytes(data),
    )


def test_defensive_external_id_and_timestamp_validation() -> None:
    assert official_attack_id("DC0001") == "DC0001"
    assert official_attack_id("AN0001") == "AN0001"
    assert official_attack_id("DET0001") == "DET0001"
    assert stix_timestamp(_TIMESTAMP) == _TIMESTAMP
    for value in ("DC1", "AN0001.001", "DET-0001"):
        with pytest.raises(ValueError):
            official_attack_id(value)
    for value in ("2025-13-21T14:00:00Z", "2025-10-21 14:00:00Z", object()):
        with pytest.raises((TypeError, ValueError)):
            stix_timestamp(value)


def test_complete_defensive_objects_survive_import_and_round_trip() -> None:
    snapshot = _snapshot()
    component = snapshot.by_attack_id["DC0001"]
    analytic = snapshot.by_attack_id["AN0001"]
    strategy = snapshot.by_attack_id["DET0001"]
    assert type(component) is AttackDataComponent
    assert type(analytic) is AttackAnalytic
    assert type(strategy) is AttackDetectionStrategy
    assert component.to_record() == {
        "attack_id": "DC0001",
        "stix_id": _DATA_COMPONENT_ID,
        "object_type": "x-mitre-data-component",
        "name": "Process Access",
        "description": "Process access telemetry.",
        "domains": ("enterprise-attack",),
        "object_version": "1.0",
        "attack_spec_version": "3.3.0",
        "modified": _TIMESTAMP,
        "revoked": False,
        "deprecated": False,
        "log_sources": (
            {"name": "Sysmon", "channel": "EventCode=10"},
            {"name": "WinEventLog:Security", "channel": "EventCode=4656"},
        ),
    }
    assert analytic.platforms == ("Windows",)
    assert analytic.log_source_references == (
        AttackLogSourceReference(_DATA_COMPONENT_ID, "Sysmon", "EventCode=10"),
    )
    assert analytic.mutable_elements == (
        AttackMutableElement("TargetImage", "Tune the protected target process set."),
    )
    assert strategy.analytic_stix_ids == (_ANALYTIC_ID,)
    assert all(snapshot.by_attack_id[key].to_record()["attack_id"] == key for key in (
        "DC0001", "AN0001", "DET0001",
    ))


def test_defensive_import_digest_is_deterministic_under_json_reordering() -> None:
    first_objects = _bundle_objects()
    second_objects = list(reversed(deepcopy(first_objects)))
    component = next(value for value in second_objects if value["type"] == "x-mitre-data-component")
    component["x_mitre_log_sources"] = list(reversed(component["x_mitre_log_sources"]))
    assert _snapshot(_bundle(first_objects)).digest == _snapshot(_bundle(second_objects)).digest


def test_data_component_log_source_bound_covers_current_live_bundle_shape() -> None:
    objects = _bundle_objects()
    component = next(value for value in objects if value["type"] == "x-mitre-data-component")
    component["x_mitre_log_sources"] = [
        {"name": f"source-{index:03d}", "channel": f"channel-{index:03d}"}
        for index in range(333)
    ]
    snapshot = _snapshot(_bundle(objects))
    assert len(snapshot.by_attack_id["DC0001"].log_sources) == 333

    component["x_mitre_log_sources"] = [
        {"name": f"source-{index:03d}", "channel": f"channel-{index:03d}"}
        for index in range(513)
    ]
    with pytest.raises(TypeError, match="log_sources_invalid"):
        _snapshot(_bundle(objects))


def test_defensive_import_rejects_invalid_prefix_domain_and_nested_shape() -> None:
    prefix = _bundle_objects()
    prefix[0]["external_references"][0]["external_id"] = "AN0001"
    with pytest.raises(ValueError, match="defensive_external_id_invalid"):
        _snapshot(_bundle(prefix))

    domain = _bundle_objects()
    domain[1]["x_mitre_domains"] = ["mobile-attack"]
    with pytest.raises(ValueError, match="enterprise_domain_required"):
        _snapshot(_bundle(domain))

    nested = _bundle_objects()
    nested[0]["x_mitre_log_sources"][0]["unexpected"] = "not allowed"
    with pytest.raises(ValueError, match="log_source_keys_invalid"):
        _snapshot(_bundle(nested))

    reference = _bundle_objects()
    reference[1]["x_mitre_log_source_references"][0]["x_mitre_data_component_ref"] = _ANALYTIC_ID
    with pytest.raises(ValueError, match="log_source_component_invalid"):
        _snapshot(_bundle(reference))

    strategy = _bundle_objects()
    strategy[2]["x_mitre_analytic_refs"] = [_DATA_COMPONENT_ID]
    with pytest.raises(ValueError, match="analytic_ref_invalid"):
        _snapshot(_bundle(strategy))


def test_defensive_import_rejects_duplicate_external_identity() -> None:
    objects = _bundle_objects()
    duplicate = deepcopy(objects[0])
    duplicate["id"] = "x-mitre-data-component--00000005-0000-4000-8000-000000000005"
    objects.append(duplicate)
    with pytest.raises(ValueError, match="duplicate_attack_identity"):
        _snapshot(_bundle(objects))


def test_defensive_contracts_reject_foreign_owners_without_hooks() -> None:
    _TrapString.called = False
    with pytest.raises(TypeError, match="log_source_name_invalid"):
        AttackLogSource(_TrapString("Sysmon"), "EventCode=10")
    assert _TrapString.called is False

    _TrapTuple.called = False
    with pytest.raises(TypeError, match="log_sources_invalid"):
        AttackDataComponent(
            attack_id="DC0001",
            stix_id=_DATA_COMPONENT_ID,
            name="Process Access",
            description="",
            domains=("enterprise-attack",),
            log_sources=_TrapTuple((AttackLogSource("Sysmon", "EventCode=10"),)),
            object_version="1.0",
            attack_spec_version="3.3.0",
            modified=_TIMESTAMP,
        )
    assert _TrapTuple.called is False
