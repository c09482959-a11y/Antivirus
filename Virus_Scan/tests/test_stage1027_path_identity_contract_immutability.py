from __future__ import annotations

import pytest

from Virus_Scan.contracts.path_identity import PathIdentity, ScanPathPolicySnapshot


def test_stage1027_path_identity_deep_freezes_parts_from_caller_list() -> None:
    caller_parts = ["Game", "Temp", "asset.png"]
    identity = PathIdentity(raw=123, name="Asset.PNG", suffix=".PNG", parts=caller_parts, exists=1)

    caller_parts.append("mutated")

    assert identity.raw == "123"
    assert identity.name == "Asset.PNG"
    assert identity.suffix == ".png"
    assert identity.parts == ("Game", "Temp", "asset.png")
    assert identity.exists is True
    with pytest.raises(AttributeError):
        identity.parts = ()  # type: ignore[misc]


def test_stage1027_scan_path_policy_snapshot_deep_freezes_direct_constructor_inputs() -> None:
    excluded_dirs = ["Temp"]
    excluded_files = ["ScanLog"]
    excluded_suffixes = [".LOG"]
    policy = ScanPathPolicySnapshot(excluded_dirs, excluded_files, excluded_suffixes)  # type: ignore[arg-type]

    excluded_dirs.append("mutated")
    excluded_files.append("mutated")
    excluded_suffixes.append(".mutated")

    assert policy.excluded_dirs == frozenset({"Temp"})
    assert policy.excluded_files == frozenset({"ScanLog"})
    assert policy.excluded_suffixes == frozenset({".log"})
    assert policy.normalized_dirs == frozenset({"temp"})
    assert policy.normalized_files == frozenset({"scanlog"})
    with pytest.raises(AttributeError):
        policy.excluded_dirs = frozenset()  # type: ignore[misc]
