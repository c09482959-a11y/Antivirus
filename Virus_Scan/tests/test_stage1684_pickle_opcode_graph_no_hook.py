from typing import Any, cast

from Virus_Scan.detection.chains.execution import pickle_opcode_graph
from Virus_Scan.detection.contracts.pickle_graph_analysis import analyze_pickle_opcode_graph, path_is_renpy_pickle, pickle_dangerous_global, unify_pickle_detection_tags
from Virus_Scan.detection.contracts.pickle_opcode import detect_python_pickle_opcode_exec


class HostilePath:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


class HostileBlob:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __bytes__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bytes")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call iter")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")


class HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not call format")


def _reset():
    HostilePath.touched = 0
    HostileBlob.touched = 0
    HostileText.touched = 0


def test_pickle_opcode_graph_rejects_hostile_data_and_path_without_hooks():
    _reset()
    assert pickle_opcode_graph.pickle_opcode_graph_tags(HostileBlob(), path=HostilePath()) == []
    assert HostileBlob.touched == 0
    assert HostilePath.touched == 0


def test_pickle_opcode_graph_malformed_pickle_records_degraded_failure_tags():
    invalid_tags = set(pickle_opcode_graph.pickle_opcode_graph_tags(b"not pickle", path="bad.rpyc"))
    partial_tags = set(pickle_opcode_graph.pickle_opcode_graph_tags(b"\x80\x04", path="bad.rpyc"))

    assert {
        "detection_stage_degraded",
        "detection_failure_evidence",
        "failure_evidence_recorded",
        "pickle_opcode_graph_parse_degraded",
        "pickle_opcode_graph_parse_pickle_opcode_parse_failure",
    }.issubset(invalid_tags)
    assert "pickle_opcode_graph_analyzed" in partial_tags
    assert "pickle_opcode_graph_parse_degraded" in partial_tags


def test_pickle_opcode_graph_analysis_fields_are_no_hook():
    _reset()
    tags = []
    analysis = {
        "valid_pickle": True,
        "globals": [HostileText()],
        "has_stack_global": True,
        "has_reduce": True,
        "dangerous_globals": [HostileText()],
        "reduce_chains": [
            {
                "callable": HostileText(),
                "opcode": HostileText(),
                "stream_offset": HostileText(),
                "op_position": HostileText(),
            }
        ],
        "trigger_windows": [
            {
                "ops": [
                    {"opcode": HostileText(), "arg": HostileText(), "op_position": HostileText()}
                ]
            }
        ],
        "has_exec_chain": True,
    }
    pickle_opcode_graph._append_trigger_context_failure_tags(tags, analysis, HostilePath())
    assert tags == []
    assert HostileText.touched == 0
    assert HostilePath.touched == 0


def test_pickle_tag_unification_rejects_hostile_tags_and_path_without_hooks():
    _reset()
    tags = unify_pickle_detection_tags([
        "pickle_opcode_graph_analyzed",
        "pickle_dangerous_global",
        HostileText(),
    ], path=HostilePath())
    assert {"pickle_opcode_graph_analyzed", "pickle_dangerous_global"} <= set(tags)
    assert "pickle_opcode_execution" not in tags
    assert HostileText.touched == 0
    assert HostilePath.touched == 0


def test_pickle_path_and_text_detection_do_not_execute_hostile_objects():
    _reset()
    assert path_is_renpy_pickle(HostilePath()) is False
    assert detect_python_pickle_opcode_exec(HostileText(), ext=cast(Any, HostileText())) == []
    assert HostilePath.touched == 0
    assert HostileText.touched == 0


def test_pickle_opcode_analyzer_rejects_hostile_input_without_hooks():
    _reset()
    result = analyze_pickle_opcode_graph(cast(Any, HostileBlob()))
    assert result["valid_pickle"] is False
    assert result["degraded"] is True
    assert result["failure_evidence"]
    assert pickle_dangerous_global(HostileText()) is False
    assert HostileBlob.touched == 0
    assert HostileText.touched == 0
