"""Stage 2069 detection no-hook boundary centralization regressions."""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_internal_frozen_dataclass_status,
    no_hook_module_dict_status,
)
from Virus_Scan.detection.contracts import filetype_context
from Virus_Scan.detection.contracts.filetype_context import FiletypePolicyUnavailable
from Virus_Scan.detection.registries.publication import freeze_registry_publication
from Virus_Scan.detection.scoring.stress.scoring_framework import IterationScoreProfile
from Virus_Scan.detection.registries.snapshot import _module_registry_items


class HostilePlainInstance:
    touched = 0

    def __getattribute__(self, name: str):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        return object.__getattribute__(self, name)


def test_stage2069_filetype_plain_instance_backing_uses_canonical_no_hook_status() -> None:
    HostilePlainInstance.touched = 0

    items = filetype_context._policy_mapping_items(HostilePlainInstance())

    assert type(items) is filetype_context.FiletypePolicyUnavailable
    assert items.reason == "custom_getattribute"
    assert HostilePlainInstance.touched == 0


def test_stage2069_registry_publication_uses_canonical_internal_frozen_dataclass_status() -> None:
    frozen_record = FiletypePolicyUnavailable("reason", "field", "value")
    frozen_ok, frozen_reason = no_hook_internal_frozen_dataclass_status(frozen_record)
    mutable_ok, mutable_reason = no_hook_internal_frozen_dataclass_status(IterationScoreProfile())

    assert frozen_ok is True
    assert frozen_reason == ""
    assert mutable_ok is False
    assert mutable_reason == "dataclass_not_frozen"
    assert freeze_registry_publication(frozen_record) is frozen_record


def test_stage2069_registry_snapshot_module_dict_uses_canonical_owner() -> None:
    module = ModuleType("Virus_Scan.tests.stage2069_fake_registry")
    module.PUBLIC_VALUE = "published"

    module_dict, reason = no_hook_module_dict_status(module)
    items = _module_registry_items(module)

    assert reason == ""
    assert module_dict is not None
    assert ("PUBLIC_VALUE", "published") in items
    assert _module_registry_items(object()) == ()


def test_stage2069_detection_sources_have_no_local_direct_object_getattribute_reads() -> None:
    touched = (
        Path("Virus_Scan/detection/contracts/filetype_context.py"),
        Path("Virus_Scan/detection/registries/publication.py"),
        Path("Virus_Scan/detection/registries/snapshot.py"),
    )

    offenders = [path for path in touched if "object.__getattribute__" in path.read_text(encoding="utf-8")]

    assert offenders == []
