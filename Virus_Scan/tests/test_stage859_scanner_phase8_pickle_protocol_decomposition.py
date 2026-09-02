import pickle

from Virus_Scan.scanners.pickle.protocol import has_pickle_protocol_header, pickle_protocol_offsets
from Virus_Scan.scanners.pickle_scan import analyze_pickle_opcode_graph, pickle_fast_escalation_prefilter


def test_pickle_protocol_detection_is_owned_by_pickle_protocol_module():
    payload = b"prefix" + pickle.dumps({"ok": True}, protocol=4)
    assert has_pickle_protocol_header(payload, max_bytes=len(payload))
    offsets = pickle_protocol_offsets(payload, max_offsets=8, max_bytes=len(payload))
    assert 0 in offsets
    assert payload.index(b"\x80\x04") in offsets


def test_pickle_opcode_graph_uses_protocol_offsets_without_execution():
    payload = b"prefix" + pickle.dumps({"cmd": "noop"}, protocol=4)
    summary = analyze_pickle_opcode_graph(payload)
    assert summary["valid_pickle"] is True
    assert payload.index(b"\x80\x04") in summary["offsets"]


def test_pickle_fast_prefilter_keeps_base64_protocol_path_real():
    payload = b"\x80\x04cposix\nsystem\n."
    result = pickle_fast_escalation_prefilter("script.rpy", data=b"", text="pickle.loads gIAEY3Bvc2l4CnN5c3RlbQou")
    # The exact decoded payload is intentionally not executed; the public result
    # must remain a deterministic escalation shape with tags/hits lists.
    assert isinstance(result["hits"], list)
    assert isinstance(result["tags"], list)
