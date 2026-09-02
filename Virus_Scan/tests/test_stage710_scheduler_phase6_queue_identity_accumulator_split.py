from pathlib import Path

from Virus_Scan.scheduler.queue import identity_lock, raw_queue_identity
from Virus_Scan.scheduler.queue import raw_queue_accumulator, raw_accumulator_lock, raw_accumulator_store
from Virus_Scan.scheduler.queue import integrity, integrity_contracts, raw_integrity


def test_stage710_raw_queue_identity_and_accumulator_are_queue_owned():
    for module in (
        raw_queue_identity,
        identity_lock,
        raw_queue_accumulator,
        raw_accumulator_lock,
        raw_accumulator_store,
        integrity,
        integrity_contracts,
        raw_integrity,
    ):
        parts = Path(module.__file__).parts
        assert parts[-3] == "scheduler"
        assert parts[-2] == "queue"


def test_stage710_dead_ownership_reconciliation_surfaces_deleted():
    assert not Path("Virus_Scan/scheduler/ownership/raw_queue_identity.py").exists()
    assert not Path("Virus_Scan/scheduler/reconciliation/raw_queue_accumulator.py").exists()
    assert not Path("Virus_Scan/scheduler/reconciliation/raw_accumulator_store.py").exists()


def test_stage710_queue_integrity_and_accumulator_are_bounded():
    for rel in (
        "Virus_Scan/scheduler/queue/raw_queue_identity.py",
        "Virus_Scan/scheduler/queue/identity_lock.py",
        "Virus_Scan/scheduler/queue/raw_queue_accumulator.py",
        "Virus_Scan/scheduler/queue/raw_accumulator_lock.py",
        "Virus_Scan/scheduler/queue/raw_accumulator_store.py",
        "Virus_Scan/scheduler/queue/integrity.py",
        "Virus_Scan/scheduler/queue/integrity_contracts.py",
        "Virus_Scan/scheduler/queue/raw_integrity.py",
    ):
        assert sum(1 for _ in Path(rel).open(encoding="utf-8")) < 225
