from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.api_behavior import API_NAME_TEXT_UNAVAILABLE, api_call_values, map_api_to_group



class HostileApiName:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


class PlainSequence:
    def __init__(self, values):
        self.values = values


def test_stage2023_api_behavior_group_lookup_uses_owned_group_items() -> None:
    HostileApiName.touched = 0

    assert map_api_to_group("CreateProcessA") == "process_execution"
    assert map_api_to_group(HostileApiName()) == "unknown"
    assert HostileApiName.touched == 0


def test_stage2023_api_behavior_plain_sequence_uses_instance_dict_no_hook() -> None:
    assert api_call_values(PlainSequence(["CreateFile", b"ReadFile"])) == ["CreateFile", b"ReadFile"]


def test_stage2023_api_behavior_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/api_behavior.py"))

    forbidden = (
        "for group, apis in API_GROUPS.items():",
        "values = data.get(\"values\")",
        "_MAPPING_PROXY_TYPE",
    )
    for snippet in forbidden:
        assert snippet not in source
