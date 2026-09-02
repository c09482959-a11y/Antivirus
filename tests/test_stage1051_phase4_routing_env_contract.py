
"""Phase 4 regression tests for routing env parsing through canonical contracts."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.routing import intrastage_execution_plan
from tests.support.env_override import temporary_environ


def test_routing_parallel_policy_uses_public_env_contracts():
    source = read_python_file(Path("Virus_Scan/routing/intrastage_execution_plan.py"))
    assert "from Virus_Scan.contracts.env_config import bool_env, int_env, str_env" in source
    assert "os.environ.get('UMIGE_STAGE_PARALLEL'" not in source
    assert "os.environ.get('UMIGE_INTRASTAGE_PARALLEL'" not in source
    assert "os.environ.get('UMIGE_STAGE_PARALLEL_WORKERS'" not in source


def test_routing_parallel_policy_preserves_false_and_min_worker_semantics():
    with temporary_environ({"UMIGE_STAGE_PARALLEL": "off", "UMIGE_INTRASTAGE_PARALLEL": "0", "UMIGE_STAGE_PARALLEL_WORKERS": "0"}):
        assert intrastage_execution_plan.stage_parallel_enabled() is False
        assert intrastage_execution_plan.intrastage_enabled() is False
        assert intrastage_execution_plan.stage_parallel_workers() == 1
