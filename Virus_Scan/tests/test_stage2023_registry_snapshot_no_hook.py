from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.registries import snapshot



class HostileModuleLike:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __getattribute__(self, name):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("hostile module hook")


class HostileMapping(dict):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def items(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("hostile items hook")


class HostileRegistryName:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("hostile name string")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("hostile name repr")


def test_stage2023_public_registry_items_rejects_hostile_module_like_without_hooks() -> None:
    HostileModuleLike.reset()

    values = snapshot._public_registry_items(HostileModuleLike())

    assert dict(values) == {}
    assert HostileModuleLike.touched == 0


def test_stage2023_merge_registry_values_rejects_hostile_mapping_and_names_without_hooks() -> None:
    HostileMapping.reset()
    HostileRegistryName.reset()

    merged = snapshot._merge_registry_values(
        HostileMapping({"UNSAFE": "value"}),
        {HostileRegistryName(): "value", "TAG_RISK_SCORES": {}},
    )

    assert "UNSAFE" not in merged
    assert "TAG_RISK_SCORES" in merged
    assert HostileMapping.touched == 0
    assert HostileRegistryName.touched == 0


def test_stage2023_registry_snapshot_source_removed_raw_item_hooks() -> None:
    source = read_python_file(Path("Virus_Scan/detection/registries/snapshot.py"))

    assert "for name, value in vars(module).items():" not in source
    assert "for name, value in tuple(group.items()):" not in source
