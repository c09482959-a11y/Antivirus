from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.profiles import learning_gate
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest



class HostileDict(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __iter__(self):  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()

    def items(self):  # pragma: no cover - must not execute
        return self._touch()

    def values(self):  # pragma: no cover - must not execute
        return self._touch()


def test_stage2023_scan_integrity_rejects_hostile_meta_without_hooks() -> None:
    HostileDict.touched = 0

    allowed, reason, payload = learning_gate._scan_integrity_allows_learning(HostileDict({"scan_incomplete": True}))

    assert allowed is False
    assert reason == "scan_integrity_metadata_unavailable_blocks_learning"
    assert payload == {"scan_integrity_unavailable": True}
    assert HostileDict.touched == 0


def test_stage2023_learning_gate_validation_records_do_not_invoke_mapping_hooks(tmp_path: Path) -> None:
    HostileDict.touched = 0
    sample = tmp_path / "game" / "script.rpy"
    validation = {"records": (HostileDict({"bucket": "credential", "confidence": 0.1}),)}

    with patch.object(learning_gate, "profile_behavior_bucket_validation", return_value=validation):
        allowed, reason, result = learning_gate.should_learn_scan_result(
            ProfileLearningGateRequest(
                "renpy", sample, ("benign_asset",), risk=0.0, verdict="clean",
            )
        )

    assert allowed is True
    assert reason == "trusted_benign_learning_allowed"
    assert result["contextual_engine_identity"]
    assert HostileDict.touched == 0


def test_stage2023_learning_rejection_rejects_hostile_validation_meta_without_hooks(tmp_path: Path) -> None:
    HostileDict.touched = 0
    profile = default_engine_profile("renpy")
    sample = tmp_path / "game" / "script.rpy"

    with (
        patch.object(learning_gate, "load_engine_profile", return_value=profile),
        patch.object(learning_gate, "save_engine_profile") as save_profile,
    ):
        result = learning_gate.record_learning_rejection(
            "renpy",
            sample,
            "unit_test_rejection",
            validation_meta=HostileDict({"contextual_engine_identity": {"baseline_key": ".rpy"}}),
        )

    assert result["recorded"] is True
    assert save_profile.called
    assert HostileDict.touched == 0


def test_stage2023_learning_gate_source_has_no_meta_materialization_backlog_snippet() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/learning_gate.py"))

    assert "m = dict(meta or {})" not in source
    assert "dict(validation_meta)" not in source
    assert "validation.get(" not in source
