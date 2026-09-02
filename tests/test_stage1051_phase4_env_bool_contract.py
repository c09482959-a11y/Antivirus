
"""Phase 4 regression tests for canonical boolean environment policy parsing."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.contracts.env_config import bool_env
from Virus_Scan.models.replay_economics import ReplayEconomicsConfig
from tests.support.env_override import temporary_environ


def test_env_config_bool_contract_preserves_false_spellings():
    for value in ("0", "false", "no", "off"):
        with temporary_environ({"UMIGE_STAGE1051_BOOL": value}):
            assert bool_env("UMIGE_STAGE1051_BOOL", True) is False


def test_env_config_bool_contract_defaults_true_for_unknown_enabled_spellings():
    with temporary_environ({"UMIGE_STAGE1051_BOOL": "unexpected-enabled"}):
        assert bool_env("UMIGE_STAGE1051_BOOL", False) is True


def test_replay_economics_uses_public_bool_env_contract():
    with temporary_environ({"UMIGE_REPLAY_KEEP_DIVERGENCE": "off"}):
        assert ReplayEconomicsConfig.from_env().divergence_always_keep is False


def test_replay_economics_no_longer_reads_os_environ_directly():
    tree = parse_python_file(Path("Virus_Scan/models/replay_economics.py"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            assert "os" not in {alias.name for alias in getattr(node, "names", ())}
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert not (node.value.id == "os" and node.attr == "environ")
