from Virus_Scan.tests.support.static_inventory import read_python_file

import os
from pathlib import Path

from Virus_Scan.contracts import env_config



class HostileEnvironment:
    touched = 0

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned environment items hook was invoked")


class HostileDefault:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned default text hook was invoked")


def test_stage2023_env_contains_text_rejects_replaced_environment_without_hooks() -> None:
    HostileEnvironment.touched = 0

    matched, reason = env_config.env_contains_text_status("umige", environment=HostileEnvironment())

    assert matched is False
    assert reason == "unsupported_process_environment_mapping"
    assert HostileEnvironment.touched == 0


def test_stage2023_env_contains_text_preserves_normal_process_environment() -> None:
    key = "UMIGE_STAGE2023_ENV_NEEDLE"
    previous = os.environ.get(key)
    os.environ[key] = "needle-value"
    try:
        matched, reason = env_config.env_contains_text_status("needle-value")

        assert matched is True
        assert reason == "matched_env_text"
        assert env_config.env_contains_text("needle-value") is True
    finally:
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def test_stage2023_str_env_rejects_hostile_default_without_hooks() -> None:
    HostileDefault.touched = 0

    assert env_config.str_env("UMIGE_STAGE2023_MISSING_ENV", HostileDefault()) == ""
    assert HostileDefault.touched == 0


def test_stage2023_env_config_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/env_config.py"))

    forbidden = (
        "env_items = tuple(os.environ.items())",
        "return False",
        "fallback, fallback_reason = no_hook_text(default, unsupported_reason=\"unsafe_env_default_rejected\")",
        "return \"\" if fallback_reason else fallback",
    )
    for snippet in forbidden:
        assert snippet not in source
