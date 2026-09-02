from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models.replay.payload import (
    result_learning_payload,
    safe_parent_replay_result_for_normalization,
)
from Virus_Scan.models.replay.payload_boundaries import (
    first_safe_text,
    mapping_flag,
    safe_truthy_replay_flag,
)



class HostileDict(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __contains__(self, _key):  # pragma: no cover - must not execute
        return self._touch()

    def __iter__(self):  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()

    def items(self):  # pragma: no cover - must not execute
        return self._touch()

    def values(self):  # pragma: no cover - must not execute
        return self._touch()


class HostileText:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


def test_stage2023_replay_payload_boundary_helpers_reject_hostile_hooks() -> None:
    HostileDict.touched = 0
    HostileText.touched = 0
    mapping = HostileDict({"file": "sample.py", "queue_failure": True})

    assert first_safe_text(mapping, "file") == ""
    assert mapping_flag(mapping, "queue_failure") is False
    assert safe_truthy_replay_flag(HostileText()) is False
    assert HostileDict.touched == 0
    assert HostileText.touched == 0


def test_stage2023_safe_parent_replay_rejects_hostile_mapping_without_hooks() -> None:
    HostileDict.touched = 0

    result = HostileDict({"file": "sample.py", "classification": "benign"})
    normalized, resolved = safe_parent_replay_result_for_normalization(result)

    assert normalized is result
    assert resolved == ""
    assert HostileDict.touched == 0


def test_stage2023_result_learning_payload_rejects_hostile_mapping_without_hooks() -> None:
    HostileDict.touched = 0

    payload = result_learning_payload(HostileDict({"file": "sample.py", "classification": "benign"}))

    assert payload is None
    assert HostileDict.touched == 0


def test_stage2023_result_learning_payload_bounds_hostile_queue_flag_text() -> None:
    HostileText.touched = 0

    payload = result_learning_payload(
        {
            "file": "sample.py",
            "classification": "benign",
            "score": 0.0,
            "tags": ["normal_tag"],
            "queue_failure": HostileText(),
            "scan_integrity": {"allow_learning": True},
        }
    )

    assert payload is None
    assert HostileText.touched == 0


def test_stage2023_replay_payload_sources_removed_backlog_hook_snippets() -> None:
    payload_source = read_python_file(Path("Virus_Scan/models/replay/payload.py"))
    boundary_source = read_python_file(Path("Virus_Scan/models/replay/payload_boundaries.py"))

    forbidden_payload = (
        "out.get(",
        "result.get(",
        "api_obj.get(",
        "profile_selection.get(",
        "dict(res)",
        "isinstance(res, dict)",
        'safe_truthy_replay_flag(result.get("queue_failure"))',
    )
    for snippet in forbidden_payload:
        assert snippet not in payload_source
    assert "mapping.get(" not in boundary_source
    assert "return str.strip(safe_replay_text(value)).lower()" not in boundary_source
