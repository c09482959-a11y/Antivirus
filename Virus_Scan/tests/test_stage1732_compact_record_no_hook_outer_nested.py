from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.publication.json_writer import compact_result_record


class NoisyDict(dict):
    touched = 0

    def get(self, *args, **kwargs):  # pragma: no cover - failure proves caller hook executed
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass get invoked")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass items invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned dict subclass iter invoked")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping getitem invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping iter invoked")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping len invoked")

    def get(self, *args, **kwargs):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping get invoked")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items invoked")


def _reset() -> None:
    NoisyDict.touched = 0
    HostileMapping.touched = 0


def test_stage1732_compact_outer_record_uses_descriptor_mapping_reads_before_normalization() -> None:
    _reset()
    record = NoisyDict({
        "file": "sample.exe",
        "classification": "error",
        "error": "outer boom",
        "score": 0,
    })

    compact = compact_result_record(record)

    assert NoisyDict.touched == 0
    assert "outer boom" in compact["errors_warnings"]
    assert compact["input_file_path"] == "sample.exe"
    assert "non-dict scan result" not in compact["errors_warnings"]


def test_stage1732_compact_nested_dict_subclass_timing_explanation_timeout_do_not_call_hooks() -> None:
    _reset()
    record = {
        "file": "sample.exe",
        "classification": "malicious",
        "score": 80.0,
        "error": "nested evidence",
        "timing": NoisyDict({"duration": 2.5}),
        "explanation": NoisyDict({"classification": "malicious", "score": 80.0, "reasons": ["r"]}),
        "timeout_evidence": NoisyDict({"worker_state": "running", "timeout_budget": 30.0}),
    }

    compact = compact_result_record(record)

    assert NoisyDict.touched == 0
    assert compact["scan_duration_seconds"] == 2.5
    assert compact["timing"]["duration"] == 2.5
    assert compact["explanation"]["classification"] == "malicious"
    assert compact["timeout_evidence"]["worker_state"] == "running"


def test_stage1732_compact_malformed_nested_mappings_become_projection_evidence_without_hooks() -> None:
    _reset()
    hostile_timing = HostileMapping()
    hostile_explanation = HostileMapping()
    hostile_timeout = HostileMapping()
    record = {
        "file": "sample.exe",
        "classification": "error",
        "error": "malformed nested evidence",
        "timing": hostile_timing,
        "explanation": hostile_explanation,
        "timeout_evidence": hostile_timeout,
    }

    compact = compact_result_record(record)

    assert HostileMapping.touched == 0
    assert compact["timing"]["_unavailable_mapping"]["reason"] == "final_json_mapping_projection_failure"
    assert compact["duration"]["reason"] == "unsafe_numeric_value_rejected"
    assert compact["explanation"]["_unavailable_mapping"]["reason"] == "final_json_mapping_projection_failure"
    assert compact["timeout_evidence"]["reason"] == "unsupported_timeout_evidence"
