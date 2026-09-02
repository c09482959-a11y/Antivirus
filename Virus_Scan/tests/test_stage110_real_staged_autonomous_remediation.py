import concurrent.futures

import pytest

from Virus_Scan.runtime.provenance_graph import ProvenanceGraphEvent, ProvenanceGraphStore
from Virus_Scan.runtime.transactional_state import RuntimeTransaction, TransactionalRuntimeJournal
from Virus_Scan.runtime.immutable_core import RuntimeTransition
from Virus_Scan.contracts.runtime_contracts import QueueOwnershipContract, RuntimeContractRegistry, RuntimeContractViolation
from Virus_Scan.runtime.entropy_governance import audit_entropy


def test_provenance_graph_is_append_only_for_repeated_identical_events():
    store = ProvenanceGraphStore()
    event = ProvenanceGraphEvent.build(event_type="retry", subsystem="scheduler", payload={"attempt": 1})
    store.append(event)
    store.append(event)
    snap = store.canonical_snapshot()
    assert len(snap["events"]) == 2
    assert snap["events"][0]["event_id"] == snap["events"][1]["event_id"]
    assert snap["events"][0]["append_record_id"] != snap["events"][1]["append_record_id"]
    assert [e["append_index"] for e in snap["events"]] == [0, 1]


def test_provenance_graph_set_payload_is_deterministic():
    a = ProvenanceGraphEvent.build(event_type="mutation", subsystem="runtime", payload={"tags": {"b", "a", "c"}})
    b = ProvenanceGraphEvent.build(event_type="mutation", subsystem="runtime", payload={"tags": {"c", "b", "a"}})
    assert a.event_id == b.event_id
    assert a.canonical() == b.canonical()


def test_runtime_journal_set_values_hash_deterministically():
    transition = RuntimeTransition(owner="scheduler", action="set", key="tags", value={"z", "a", "m"}, reason="set-test")
    tx = RuntimeTransaction.build(owner="scheduler", transitions=[transition])
    j1 = TransactionalRuntimeJournal(owner="scheduler")
    j2 = TransactionalRuntimeJournal(owner="scheduler")
    j1.apply(tx)
    j2.apply(tx)
    assert j1.replay_hash() == j2.replay_hash()
    assert TransactionalRuntimeJournal.replay("scheduler", j1.journal_snapshot()).digest == j1.checkpoint().digest


def test_runtime_contract_registry_thread_safe_conflict_detection():
    registry = RuntimeContractRegistry()
    base = QueueOwnershipContract(queue_id="q", owner_domain="scheduler", generation=1)
    conflict = QueueOwnershipContract(queue_id="q", owner_domain="other", generation=1)
    registry.register_queue(base)

    def attempt_conflict():
        with pytest.raises(RuntimeContractViolation):
            registry.register_queue(conflict)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda _: attempt_conflict(), range(32)))
    assert registry.require_owner("q", "scheduler").contract_id == base.contract_id


def test_entropy_audit_counts_annotation_mutation(tmp_path):
    module = tmp_path / "m.py"
    module.write_text("class X:\n    pass\nx = X()\nx.value: int = 3\n", encoding="utf-8")
    report = audit_entropy(tmp_path)
    assert report["totals"]["mutation_writes"] >= 1
