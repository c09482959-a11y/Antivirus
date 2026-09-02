import threading
from Virus_Scan.runtime.structured_failures import clear_failure_records, record_suppressed_failure, failure_snapshot, canonical_failure_snapshot
from Virus_Scan.runtime.provenance import ProvenanceLedger
from Virus_Scan.contracts.schema_registry import register_schema, get_schema, schema_snapshot


def test_failure_record_store_concurrent_updates_are_owned_and_bounded():
    clear_failure_records()
    def worker(i):
        for j in range(25):
            record_suppressed_failure('phase4_shared_state', RuntimeError(f'x-{i}-{j}'), domain='runtime')
    threads=[threading.Thread(target=worker,args=(i,)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    records=failure_snapshot()['records']
    assert len(records)==1
    assert records[0]['count']==200
    assert canonical_failure_snapshot()['records'][0]['provenance'].get('runtime_epoch') is None


def test_provenance_ledger_snapshots_are_caller_mutation_safe():
    ledger = ProvenanceLedger(max_events=3)
    source={'event_type':'x','nested':{'value':1}}
    saved=ledger.append(source)
    source['nested']['value']=99
    snap=ledger.snapshot()
    assert snap[0]['nested']['value']==1
    snap[0]['nested']['value']=100
    assert ledger.snapshot()[0]['nested']['value']==1
    assert saved['nested']['value']==1


def test_schema_registry_uses_static_owned_snapshots():
    register_schema('result_record', owner='contracts.result_record', version=1)
    assert get_schema('result_record').version == 1
    snap = schema_snapshot()
    snap['result_record']['owner'] = 'mutated'
    assert schema_snapshot()['result_record']['owner'] == 'contracts.result_record'
    try:
        register_schema('phase4_global_schema', owner='test.global', version=2)
    except KeyError as exc:
        assert 'unregistered static schema contract' in str(exc)
    else:
        raise AssertionError('unknown schema contract mutated static schema table')
