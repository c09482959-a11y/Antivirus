from __future__ import annotations

from unittest.mock import patch

import pytest

from Virus_Scan.scheduler.queue import workload_classification_rules
from Virus_Scan.scheduler.queue.admission import (
    WorkloadClassificationPlan,
    build_workload_classification_plan,
    workload_plan_summary,
)
from Virus_Scan.scheduler.queue.admission_fairness import (
    interleave_workloads,
    weighted_fair_interleave,
)


def test_phase9_scheduler_planning_classifies_each_target_once(tmp_path) -> None:
    sample = tmp_path / "extensionless_payload.bin"
    sample.write_bytes(b"MZ" + (b"\x00" * 128))
    actual_sniff = workload_classification_rules._queue_sniff_workload_identity

    with patch.object(
        workload_classification_rules,
        "_queue_sniff_workload_identity",
        wraps=actual_sniff,
    ) as sniff:
        plan = build_workload_classification_plan((sample,))
        summary = workload_plan_summary(plan)
        interleaved = interleave_workloads(plan)
        weighted = weighted_fair_interleave(interleaved)

    assert type(plan) is WorkloadClassificationPlan
    assert sniff.call_count == 1
    assert summary["counts"]["dotnet"] == 1
    assert [target.path for target in weighted] == [sample]


def test_phase9_planning_consumers_require_the_canonical_plan() -> None:
    with pytest.raises(TypeError, match="workload_classification_plan_required"):
        workload_plan_summary(())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="workload_classification_plan_required"):
        interleave_workloads(())  # type: ignore[arg-type]
