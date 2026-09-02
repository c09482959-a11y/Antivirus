"""Stage 1737: partial result recovery snapshots mappings without caller hooks."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from Virus_Scan.publication.json_finalization.partial_results import (
    PARTIAL_RECOVERY_EVIDENCE_KEY,
    recover_results_from_partial,
)


class HostileResultMap(dict):
    touched = 0

    def get(self, *args, **kwargs):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned get hook must not execute")

    def keys(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned keys hook must not execute")

    def items(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned items hook must not execute")

    def __iter__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned iter hook must not execute")

    def __getitem__(self, key):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned getitem hook must not execute")


class HostileKey:
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned key str hook must not execute")

    def __repr__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned key repr hook must not execute")


class HostileExternalMapping:
    touched = 0

    def __iter__(self) -> Iterator[str]:  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned external mapping iter hook must not execute")

    def items(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned external mapping items hook must not execute")

    def keys(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned external mapping keys hook must not execute")

    def __getitem__(self, key):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned external mapping getitem hook must not execute")



def reset_hooks() -> None:
    HostileResultMap.touched = 0
    HostileKey.touched = 0
    HostileExternalMapping.touched = 0



def test_stage1737_partial_recovery_snapshots_dict_subclass_without_mapping_hooks(tmp_path: Path) -> None:
    reset_hooks()
    current = HostileResultMap({"current": {"classification": "clean"}})

    recovered = recover_results_from_partial(str(tmp_path / "missing.json"), current)

    assert recovered == {"current": {"classification": "clean"}}
    assert HostileResultMap.touched == 0



def test_stage1737_partial_recovery_preserves_malformed_key_as_explicit_evidence(tmp_path: Path) -> None:
    reset_hooks()
    key = HostileKey()
    current = HostileResultMap({key: {"classification": "clean"}})

    recovered = recover_results_from_partial(str(tmp_path / "missing.json"), current)

    assert HostileResultMap.touched == 0
    assert HostileKey.touched == 0
    assert list(recovered) == ["_unavailable_key_0"]
    malformed = recovered["_unavailable_key_0"]
    evidence = malformed[PARTIAL_RECOVERY_EVIDENCE_KEY]
    assert evidence["partial_result_recovery_failed"] is True
    assert evidence["reason"] == "partial_result_key_rejected"
    assert evidence["value_type"] == "HostileKey"
    assert malformed["value"] == {"classification": "clean"}



def test_stage1737_partial_recovery_rejects_external_mapping_without_hooks(tmp_path: Path) -> None:
    reset_hooks()
    current = HostileExternalMapping()

    recovered = recover_results_from_partial(str(tmp_path / "missing.json"), current)

    assert HostileExternalMapping.touched == 0
    evidence = recovered[PARTIAL_RECOVERY_EVIDENCE_KEY]
    assert evidence["partial_result_recovery_failed"] is True
    assert evidence["reason"] == "partial_result_current_results_rejected"
    assert evidence["value_type"] == "HostileExternalMapping"
