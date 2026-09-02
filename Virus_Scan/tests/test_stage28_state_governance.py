from dataclasses import FrozenInstanceError
import pytest

from Virus_Scan.runtime.config import RuntimeConfig
from Virus_Scan.runtime.events import RuntimeEvent
from Virus_Scan.runtime.ownership import RuntimeStateOwner
from Virus_Scan.runtime.readonly import ReadonlyRuntimeView
from Virus_Scan.runtime.state_domains import RuntimeDomainRegistry


def test_runtime_config_is_immutable_snapshot():
    cfg = RuntimeConfig.from_args(None)
    with pytest.raises(FrozenInstanceError):
        cfg.archive_limits = None


def test_runtime_event_is_immutable():
    ev = RuntimeEvent(event_type="scheduler_pressure", domain="scheduler", message="pressure")
    with pytest.raises(FrozenInstanceError):
        ev.message = "changed"


def test_readonly_runtime_view_rejects_mutation():
    view = ReadonlyRuntimeView.from_mapping({"a": 1})
    with pytest.raises(TypeError):
        view.state["a"] = 2


def test_state_owner_records_domain_mutations():
    owner = RuntimeStateOwner(state={})
    owner.set("pressure", 0.5, domain="scheduler")
    owner.set("seen", 1, domain="telemetry")
    counts = owner.mutation_counts()
    assert counts["scheduler"] >= 1
    assert counts["telemetry"] >= 1
    assert owner.readonly_view().get("pressure") == 0.5


def test_domain_registry_isolated_snapshots():
    registry = RuntimeDomainRegistry()
    registry.set("scheduler", "debt", 10)
    registry.set("replay", "depth", 2)
    snap = registry.snapshot()
    assert snap["scheduler"]["debt"] == 10
    assert snap["replay"]["depth"] == 2
    assert "depth" not in snap["scheduler"]
