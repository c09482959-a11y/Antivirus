import os
import pickle

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.scanners.pickle_scan import pickle_embedded_payload_tags
from Virus_Scan.scheduler.queue.file_job_predicate import process_queue_is_file_job as _process_queue_is_file_job


class _DangerousPickle:
    def __reduce__(self):
        return (os.system, ("calc",))


def _renpy_rpc_blob(payload: bytes) -> bytes:
    header = b"RENPY RPC2\n0 0 0\n\n"
    for _ in range(4):
        header = b"RENPY RPC2\n0 %d %d\n\n" % (len(header), len(payload))
    return header + payload


def test_renpy_rpyc_magic_is_scanned_when_extension_is_renamed():
    payload = pickle.dumps(_DangerousPickle(), protocol=2)
    tags = set(pickle_embedded_payload_tags(_renpy_rpc_blob(payload), path="renamed.txt"))
    assert "pickle_opcode_graph_analyzed" in tags
    assert "pickle_reduce_opcode" in tags
    assert "pickle_callable_reference" in tags
    assert "confirmed_pickle_exec_chain" not in tags
    assert "renpy_pickle_exec" not in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(tags))))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:pickle_execution_chain"
    )
    assert decision.status == "blocked"
    assert decision.candidate.blocked_reason == "forbidden_evidence:failure"
    assert decision.scoreable is False


def test_rpa_magic_is_scanned_when_extension_is_renamed():
    tags = set(pickle_embedded_payload_tags(b"RPA-3.0\n", path="archive.bin"))
    assert "pickle_byte_view_scan_error" not in tags


def test_process_queue_file_job_predicate_is_canonical_module_function():
    assert _process_queue_is_file_job({"job_type": "file"}) is True
    assert _process_queue_is_file_job({"job_type": "raw_stage"}) is False
    assert _process_queue_is_file_job({"collector": True}) is False
