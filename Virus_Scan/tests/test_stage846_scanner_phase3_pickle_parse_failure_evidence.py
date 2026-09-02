from Virus_Scan.scanners import pickle_scan
from Virus_Scan.scanners.pickle.literals import _iter_pickle_fragment_decode_records_from_analysis
from Virus_Scan.scanners.pickle.payload_records import _iter_pickle_payload_records


def _tags(items):
    return {str(item).lower() for item in items or []}


def test_pickle_payload_opcode_parse_failure_emits_evidence_record():
    records = list(_iter_pickle_payload_records(b"\x80\x05broken truncated pickle"))
    failures = [record for record in records if isinstance(record, dict) and record.get("failure_evidence")]

    assert failures
    failure = failures[0]
    assert failure["failure_evidence"][0]["scanner_name"] == "pickle"
    assert failure["failure_evidence"][0]["scanner_stage"] == "pickle_payload_opcode_decode"
    assert failure["failure_evidence"][0]["state"] == "malformed"
    assert "scanner_failure_evidence_recorded" in _tags(failure.get("failure_tags"))
    assert "pickle_parse_failed" in _tags(failure.get("failure_tags"))


def test_pickle_embedded_payload_tags_propagates_parse_failure_evidence_tags(tmp_path):
    sample = tmp_path / "broken.pkl"
    sample.write_bytes(b"\x80\x05broken truncated pickle")

    tags = pickle_scan.pickle_embedded_payload_tags(sample.read_bytes(), path=str(sample))
    low = _tags(tags)

    assert "scanner_failure_evidence_recorded" in low
    assert "pickle_parse_failed" in low
    assert "pickle_payload_opcode_decode_error" in low


def test_pickle_fragment_decode_failure_records_immutable_evidence():
    class BrokenAnalysis(dict):
        def __bool__(self):
            return True

        def get(self, *_args, **_kwargs):
            raise ValueError("fragment decode exploded")

    records = _iter_pickle_fragment_decode_records_from_analysis(BrokenAnalysis())
    failures = [record for record in records if record.get("failure_evidence")]

    assert failures
    failure = failures[0]
    assert failure["failure_evidence"][0]["scanner_stage"] == "pickle_fragment_decode_records"
    assert "scanner_failure_evidence_recorded" in _tags(failure.get("failure_tags"))
