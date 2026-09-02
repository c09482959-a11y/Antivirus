from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from Virus_Scan.detection.api.attack_activation_contracts import AttackActivationRecord


class _HostileTuple(tuple):
    def __iter__(self):
        raise AssertionError("caller iterator executed")

    def __bool__(self):
        raise AssertionError("caller truth hook executed")


class _HostileText(str):
    def __str__(self):
        raise AssertionError("caller string hook executed")

    def __bool__(self):
        raise AssertionError("caller truth hook executed")


class _HostileDict(dict):
    def items(self):
        raise AssertionError("caller mapping hook executed")

    def __iter__(self):
        raise AssertionError("caller iterator executed")


def _activation(**overrides: object) -> AttackActivationRecord:
    values: dict[str, object] = {
        "dataset_version": "a" * 40,
        "repository_digest": "b" * 64,
        "active_alignment_ids": (),
        "quarantined_alignment_ids": (),
        "active_implementation_ids": (),
        "quarantined_implementation_ids": (),
        "active_policy_ids": (),
        "quarantined_policy_ids": (),
        "retired_policy_ids": (),
        "active_calibration_ids": (),
        "quarantined_calibration_ids": (),
    }
    values.update(overrides)
    return AttackActivationRecord(**values)


def test_activation_contract_rejects_hostile_sequence_and_text_without_hooks() -> None:
    with pytest.raises(TypeError, match="identity_set_invalid"):
        _activation(active_policy_ids=_HostileTuple(("T1003",)))
    with pytest.raises(TypeError, match="dataset_invalid"):
        _activation(dataset_version=_HostileText("a" * 40))


def test_activation_contract_enforces_bounded_identity_sets() -> None:
    values = tuple(f"tag-{index:04d}" for index in range(4097))
    with pytest.raises((TypeError, ValueError), match="identity_set_invalid"):
        _activation(active_alignment_ids=values)


def test_activation_digest_is_deterministic_and_overlap_is_rejected() -> None:
    first = _activation(active_policy_ids=("T1003",), retired_policy_ids=("T1562.001",))
    second = _activation(active_policy_ids=("T1003",), retired_policy_ids=("T1562.001",))
    assert first.activation_digest == second.activation_digest
    assert first.to_record() == second.to_record()
    with pytest.raises(ValueError, match="policy_overlap"):
        _activation(active_policy_ids=("T1003",), quarantined_policy_ids=("T1003",))


def test_current_semantic_manifests_are_hashseed_deterministic() -> None:
    code = """
import json
from Virus_Scan.detection.attack.admission import attack_technique_admission_manifest
from Virus_Scan.detection.attack.alignment import tag_stix_alignment_manifest
from Virus_Scan.detection.attack.capabilities import scanner_capability_manifest
from Virus_Scan.detection.attack.implementations import attack_analytic_implementation_manifest
from Virus_Scan.tests.test_stage2636_10011_attack_stix_defensive_contracts import _snapshot
from Virus_Scan.detection.registries.chain_registry import chain_registry_manifest
record = {
    'admission': attack_technique_admission_manifest(_snapshot())['digest'],
    'alignment': tag_stix_alignment_manifest()['digest'],
    'capability': scanner_capability_manifest()['digest'],
    'chain': chain_registry_manifest()['digest'],
    'implementation': attack_analytic_implementation_manifest()['digest'],
}
print(json.dumps(record, sort_keys=True, separators=(',', ':')))
"""
    outputs: list[str] = []
    root = Path(__file__).resolve().parents[2]
    for seed in ("1", "7", "101"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=root, env=env,
            check=False, capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, result.stderr
        outputs.append(result.stdout.strip())
    assert len(set(outputs)) == 1
    assert len(json.loads(outputs[0])) == 5


def test_hostile_mapping_carrier_is_not_a_valid_activation_record() -> None:
    carrier = _HostileDict({"dataset_version": "a" * 40})
    with pytest.raises(TypeError, match="owner_invalid"):
        AttackActivationRecord.__post_init__(carrier)  # type: ignore[arg-type]
