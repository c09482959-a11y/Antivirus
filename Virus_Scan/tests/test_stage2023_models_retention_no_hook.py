from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models.retention import prune_counter_map



class HostileIterDict(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned dict hook was invoked")

    def __iter__(self):  # pragma: no cover - must not execute
        return self._touch()

    def __len__(self):  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()

    def items(self):  # pragma: no cover - must not execute
        return self._touch()

    def values(self):  # pragma: no cover - must not execute
        return self._touch()


def test_stage2023_retention_rejects_hostile_iteration_dict_without_hooks() -> None:
    HostileIterDict.touched = 0
    counter = HostileIterDict({"high": 9, "low": 1})

    returned = prune_counter_map(counter, 1)

    assert returned is counter
    assert dict.items(counter)
    assert HostileIterDict.touched == 0


def test_stage2023_retention_source_removed_backlog_hook_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/models/retention.py"))

    forbidden = (
        "except RETENTION_TEXT_ERRORS:\n        return None",
        "except RETENTION_TEXT_ERRORS:\n            return False",
        "except RETENTION_TEXT_ERRORS:\n            return 0",
        "tuple(dict.values(value))",
        "tuple(dict.items(value))",
        "return f'retention_text_unavailable:{_retention_type_label(value)}'",
    )
    for snippet in forbidden:
        assert snippet not in source
