from __future__ import annotations

from dataclasses import replace

import pytest

from Virus_Scan.contracts.detection_observation import (
    DETECTION_OBSERVATION_SCHEMA_VERSION,
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.contracts.yara_hits import (
    YARA_HIT_SCHEMA_VERSION,
    YARA_RULE_IDENTITY_SCHEMA_VERSION,
    YARA_SCAN_RESULT_SCHEMA_VERSION,
    YaraHit,
    YaraRuleIdentity,
    YaraScanResult,
)
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_result


def _observation() -> DetectionObservation:
    return DetectionObservation.create(
        tag="process_exec",
        producer_id="stage2744",
        stage_id="phase3",
        modality="static_structure",
        artifact_identity="content_sha256:" + "1" * 64,
        source_location=ObservationSourceLocation(
            "file_offset", locator="sample.bin", byte_offset=7,
        ),
        evidence={"kind": "phase3_exact_schema"},
    )


def test_rev15_detection_observation_accepts_only_typed_or_exact_current_record() -> None:
    observation = _observation()
    record = observation.to_record()
    assert record["schema_version"] == DETECTION_OBSERVATION_SCHEMA_VERSION
    assert DetectionObservation.from_value(observation) is observation
    hydrated = DetectionObservation.from_value(record)
    assert hydrated.to_record() == record


@pytest.mark.parametrize("schema", [
    "stage2636_10014_detection_observation_v2",
    "stage2636_10014_detection_observation_v999",
    3,
    None,
])
def test_rev15_detection_observation_rejects_stale_future_or_malformed_schema(schema: object) -> None:
    record = _observation().to_record()
    record["schema_version"] = schema
    with pytest.raises((TypeError, ValueError)):
        DetectionObservation.from_value(record)


def test_rev15_detection_observation_rejects_missing_schema_partial_unknown_and_scalar() -> None:
    record = _observation().to_record()
    missing = dict(record)
    missing.pop("schema_version")
    partial = {"schema_version": DETECTION_OBSERVATION_SCHEMA_VERSION, "tag": "process_exec"}
    unknown = dict(record)
    unknown["legacy_field"] = "legacy"
    for value in (missing, partial, unknown):
        with pytest.raises(ValueError):
            DetectionObservation.from_value(value)
    with pytest.raises(TypeError):
        DetectionObservation.from_value("process_exec")


def _mutated_yara_record(level: str, *, schema: object, remove: bool = False) -> dict[str, object]:
    record = canonical_test_yara_result().to_record()
    if level == "scan":
        target = record
    else:
        hit = dict(record["hits"][0])
        record["hits"] = (hit,)
        if level == "hit":
            target = hit
        else:
            rule = dict(hit["rule_identity"])
            hit["rule_identity"] = rule
            target = rule
    if remove:
        target.pop("schema_version")
    else:
        target["schema_version"] = schema
    return record


@pytest.mark.parametrize("level", ["scan", "hit", "rule"])
@pytest.mark.parametrize("schema", ["stale_schema_v0", "future_schema_v999", 1, None])
def test_rev15_yara_nested_schema_is_exact_current_transitively(level: str, schema: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        YaraScanResult.from_record(_mutated_yara_record(level, schema=schema))


@pytest.mark.parametrize("level", ["scan", "hit", "rule"])
def test_rev15_yara_nested_missing_schema_is_rejected(level: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        YaraScanResult.from_record(_mutated_yara_record(level, schema="", remove=True))


def test_rev15_yara_current_tree_hydrates_and_stale_typed_objects_cannot_exist() -> None:
    result = canonical_test_yara_result()
    assert result.schema_version == YARA_SCAN_RESULT_SCHEMA_VERSION
    assert result.hits[0].schema_version == YARA_HIT_SCHEMA_VERSION
    assert result.hits[0].rule_identity.schema_version == YARA_RULE_IDENTITY_SCHEMA_VERSION
    hydrated = YaraScanResult.from_record(result.to_record())
    assert hydrated == result
    assert hydrated.verified is True
    assert hydrated.hits[0].rule_identity.mapping_eligible is True

    with pytest.raises(ValueError, match="schema_version_unsupported"):
        replace(result.hits[0].rule_identity, schema_version="stale_rule_schema")
    with pytest.raises(ValueError, match="schema_version_unsupported"):
        replace(result.hits[0], schema_version="stale_hit_schema")
    with pytest.raises(ValueError, match="schema_version_unsupported"):
        replace(result, schema_version="stale_scan_schema")
