from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.profiles import context as profile_context


def test_stage2023_profile_context_records_container_root_probe_failure() -> None:
    target_parent = Path("stage2023_unavailable_root")
    original_exists = Path.exists

    def fail_target_parent(path: Path) -> bool:
        if path == target_parent:
            raise OSError("injected profile context root probe failure")
        return original_exists(path)

    with patch.object(Path, "exists", fail_target_parent):
        root = profile_context.profile_context_container_root(target_parent / "sample.rpy")
        identity = profile_context.contextual_profile_learning_policy(target_parent / "sample.rpy")

    assert root == target_parent
    assert "profile_context_container_root_unavailable" in identity.fingerprint_evidence
    assert identity.baseline_key


def test_stage2023_profile_context_source_has_no_exception_sentinel_root_return() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/context.py"))

    assert "except OSError:\n        return None" not in source
    assert "profile_context_container_root_unavailable" in source
