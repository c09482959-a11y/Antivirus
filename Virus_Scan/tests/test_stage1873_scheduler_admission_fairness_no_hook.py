from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scheduler.queue.admission import build_workload_classification_plan
from Virus_Scan.scheduler.queue.admission_fairness import QueueDebtLedger, interleave_workloads, weighted_fair_interleave



class HostileScalar:
    def __bool__(self):  # pragma: no cover - must never execute
        raise AssertionError("truthiness hook executed")

    def __str__(self):  # pragma: no cover - must never execute
        raise AssertionError("text hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        raise AssertionError("repr hook executed")

    def __float__(self):  # pragma: no cover - must never execute
        raise AssertionError("numeric hook executed")

    def __format__(self, spec):  # pragma: no cover - must never execute
        raise AssertionError("format hook executed")



def test_stage1873_queue_debt_ledger_rejects_hostile_workload_and_amount_without_hooks():
    ledger = QueueDebtLedger()
    hostile = HostileScalar()

    ledger.charge(hostile, hostile)
    ledger.age(hostile)
    priority = ledger.priority(hostile, hostile)

    assert 0.0 < priority <= 1.0



def test_stage1873_queue_debt_ledger_preserves_exact_primitive_default_semantics():
    ledger = QueueDebtLedger()
    ledger.charge("archive", 5.0)

    assert ledger.priority("archive", 0.0) == 1.5
    assert ledger.priority(None, None) == 1.0



def test_stage1873_admission_fairness_source_avoids_mapping_values_and_scalar_hooks():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/admission_fairness.py"))

    assert "buckets.values()" not in source
    assert "str(workload or" not in source
    assert "float(amount or" not in source
    assert "float(base_cost or" not in source



def test_stage1873_interleavers_still_preserve_items_after_no_hook_loop_rewrite():
    files = ["large.zip", "lib.dll", "image.png", "script.ps1", "plain.txt"]

    plan = build_workload_classification_plan(files)
    interleaved = interleave_workloads(plan)
    weighted = weighted_fair_interleave(plan.targets)

    assert sorted(target.path for target in interleaved) == sorted(files)
    assert sorted(target.path for target in weighted) == sorted(files)
