"""Stage2192 strict typing closure for in-memory parent maintenance."""
from __future__ import annotations

import inspect

from Virus_Scan.scheduler.orchestration import inmemory_parent_maintenance as maintenance
from Virus_Scan.scheduler.orchestration import inmemory_parent_iteration as iteration
from Virus_Scan.scheduler.orchestration import inmemory_parent_runtime_contracts as runtime_contracts


def _annotation_text(value: object) -> str:
    return repr(value)


def test_stage2192_inmemory_maintenance_request_annotations_remove_any() -> None:
    """The maintenance request boundary uses protocols/callables, not Any."""

    request_annotations = tuple(maintenance.InMemoryMaintenanceRequest.__annotations__.values())
    result_annotations = tuple(maintenance.InMemoryMaintenanceResult.__annotations__.values())
    annotation_text = "\n".join(_annotation_text(value) for value in (*request_annotations, *result_annotations))

    assert "typing.Any" not in annotation_text
    assert "Any" not in annotation_text
    assert maintenance.InMemoryMaintenanceRequest.__annotations__["recovery"] == "InMemoryRecoveryMaintenanceProtocol"
    assert maintenance.InMemoryMaintenanceRequest.__annotations__["memory_policy"] == "InMemoryMemoryPolicyProtocol"


def test_stage2192_inmemory_runtime_setup_contracts_have_no_any_annotations() -> None:
    """The runtime setup/result handoff records unknowns as object, not Any."""

    source = inspect.getsource(runtime_contracts)
    annotations = (
        *runtime_contracts.InMemoryParentRuntimeSetupRequest.__annotations__.values(),
        *runtime_contracts.InMemoryParentRuntimeSetupResult.__annotations__.values(),
    )
    annotation_text = "\n".join(repr(value) for value in annotations)

    assert "from typing import Any" not in source
    assert "Any" not in source
    assert "tuple[object, ...]" in annotation_text
    assert runtime_contracts.InMemoryParentRuntimeSetupResult.__annotations__["recovery"] == "object"


def test_stage2192_inmemory_iteration_source_has_no_any_setup_boundary_annotations() -> None:
    """The parent iteration boundary consumes the typed runtime setup result."""

    source = inspect.getsource(iteration)

    assert "from typing import Any" not in source
    assert "setup: Any" not in source
    assert "root: Any" not in source
    assert "partial_output_path: Any" not in source
    assert "InMemoryParentRuntimeSetupResult" in source
    assert "-> InMemoryMaintenanceResult" in source


def test_stage2192_inmemory_maintenance_source_has_no_any_import_or_boundary_annotations() -> None:
    """Current source does not keep the stale Any-based request/result boundary."""

    source = inspect.getsource(maintenance)

    assert "from typing import Any" not in source
    assert ": Any" not in source
    assert "Mapping[str, Any]" not in source
    assert "Callable[..., object]" in source
    assert "Protocol" in source
