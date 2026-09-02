from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.queue.workload_identity import workload_from_identity_outcome


class HostileIdentityMapping(dict):
    get_touched = 0
    items_touched = 0

    def get(self, key, default=None):  # pragma: no cover - must not be called
        type(self).get_touched += 1
        raise RuntimeError("do not call hostile get")

    def items(self):  # pragma: no cover - must not be called
        type(self).items_touched += 1
        raise RuntimeError("do not call hostile items")


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must not be called
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):  # pragma: no cover - must not be called
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileNumber:
    touched = 0

    def __float__(self):  # pragma: no cover - must not be called
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __str__(self):  # pragma: no cover - must not be called
        type(self).touched += 1
        raise RuntimeError("do not stringify")


class HostileTags:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not be called
        type(self).touched += 1
        raise RuntimeError("do not iterate")


class HostileTag:
    touched = 0

    def __str__(self):  # pragma: no cover - must not be called
        type(self).touched += 1
        raise RuntimeError("do not stringify tag")

    def __repr__(self):  # pragma: no cover - must not be called
        type(self).touched += 1
        raise RuntimeError("do not repr tag")


def test_stage1584_workload_identity_rejects_hostile_mapping_without_get_or_items_hooks() -> None:
    hostile = HostileIdentityMapping(magic_stage="archive", confidence=1.0, tags=("archive_file",))

    assert workload_from_identity_outcome(hostile).accepted is False
    assert HostileIdentityMapping.get_touched == 0
    assert HostileIdentityMapping.items_touched == 0


def test_stage1584_workload_identity_does_not_stringify_or_float_hostile_values() -> None:
    identity = {
        "magic_stage": HostileText(),
        "magic_type": HostileText(),
        "confidence": HostileNumber(),
        "tags": (HostileTag(),),
    }

    assert workload_from_identity_outcome(identity).accepted is False
    assert HostileText.touched == 0
    assert HostileNumber.touched == 0
    assert HostileTag.touched == 0


def test_stage1584_workload_identity_does_not_iterate_hostile_tags() -> None:
    identity = {"magic_stage": "archive", "confidence": 1.0, "tags": HostileTags()}

    assert workload_from_identity_outcome(identity).workload == "archive"
    assert HostileTags.touched == 0


def test_stage1584_workload_identity_preserves_owned_dict_and_frozen_scheduler_mapping() -> None:
    assert workload_from_identity_outcome({"magic_stage": "archive", "confidence": "1.0", "tags": ("archive_file",)}).workload == "archive"
    assert workload_from_identity_outcome({"magic_stage": "binary", "magic_type": "pe_mz", "confidence": 1.0}).workload == "dotnet"
    assert workload_from_identity_outcome(immutable_mapping({"magic_stage": "asset", "confidence": 0.95, "tags": ("media_file",)})).workload == "image"
