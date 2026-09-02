from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.detection_observation import DetectionObservation, ObservationSourceLocation



class HostileDict(dict):
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned mapping iteration hook was invoked")

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned mapping get hook was invoked")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items hook was invoked")


class HostileText:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


def test_stage2023_detection_observation_rejects_hostile_dict_subclass_hooks() -> None:
    HostileDict.touched = 0

    try:
        DetectionObservation.from_value(HostileDict({"tag": "api_loadurl"}))
    except TypeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("dict subclass crossed exact-current observation boundary")
    assert HostileDict.touched == 0


def test_stage2023_detection_observation_rejects_hostile_producer_fields_without_hooks() -> None:
    HostileText.touched = 0
    try:
        DetectionObservation.create(
            tag="api_loadurl",
            producer_id=HostileText(),
            stage_id="unit",
            modality="static_structure",
            artifact_identity="sha256:unit",
            source_location=ObservationSourceLocation("event", event_id="api_loadurl"),
        )
    except TypeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("caller-owned producer field was accepted")
    assert HostileText.touched == 0


def test_stage2023_detection_observation_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/detection_observation.py"))

    forbidden = (
        "fallback, fallback_reason = no_hook_text(default,",
        "return \"\" if fallback_reason else str.strip(fallback)",
        "value = {key: item for key, item in dict.items(value)}",
        "items = tuple(dict.items(value)) if isinstance(value, dict) else tuple(value.items())",
        "default=f\"unreadable_evidence_key_{index}\"",
        "key_text = f\"{key_text}#{index}\"",
        "dict(dict.items(raw_evidence))",
        "raw_evidence.items()",
        "_MAPPING_PROXY_TYPE",
        "role or \"unknown\"",
        "source or \"detection\"",
    )
    for snippet in forbidden:
        assert snippet not in source
