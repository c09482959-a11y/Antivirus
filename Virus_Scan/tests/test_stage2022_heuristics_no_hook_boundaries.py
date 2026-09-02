import ast
from pathlib import Path

from Virus_Scan.heuristics.downloader_patterns import evaluate_downloader_behavior
from Virus_Scan.heuristics.game_engine_threats import evaluate_game_engine_threats
from Virus_Scan.heuristics.obfuscation import evaluate_obfuscation
from Virus_Scan.heuristics.pickle_exec import evaluate_pickle_execution
from Virus_Scan.heuristics.script_exec import evaluate_script_execution


class HostileHeuristicValue:
    touched = []

    @classmethod
    def reset(cls):
        cls.touched.clear()

    def __str__(self):
        type(self).touched.append("__str__")
        return "powershell"

    def __repr__(self):
        type(self).touched.append("__repr__")
        return "powershell"

    def __format__(self, spec):
        type(self).touched.append("__format__")
        return "powershell"

    def __bool__(self):
        type(self).touched.append("__bool__")
        return True

    def __iter__(self):
        type(self).touched.append("__iter__")
        return iter(())

    def __hash__(self):
        type(self).touched.append("__hash__")
        return 1

    def __eq__(self, other):
        type(self).touched.append("__eq__")
        return False


def test_stage2022_heuristic_evaluators_reject_hostile_text_without_hooks():
    hostile = HostileHeuristicValue()
    HostileHeuristicValue.reset()

    assert evaluate_downloader_behavior(hostile, source=hostile)["tags"] == []
    assert evaluate_game_engine_threats(hostile, path=hostile, engine=hostile)["tags"] == []
    assert evaluate_obfuscation(hostile, source=hostile)["tags"] == []
    assert evaluate_pickle_execution(hostile, source=hostile)["tags"] == []
    assert evaluate_script_execution(hostile, source=hostile, engine=hostile)["tags"] == []

    assert HostileHeuristicValue.touched == []


def test_stage2022_heuristic_byte_inputs_still_decode_latin1_and_detect():
    assert "network_download" in evaluate_downloader_behavior(b"Invoke-WebRequest http://example.test")["tags"]
    assert "encoded_data_context" in evaluate_obfuscation(b"FromBase64String")["tags"]
    assert "pickle_reduce_opcode" in evaluate_pickle_execution(b"GLOBAL\nREDUCE")["tags"]
    assert "powershell_exec" in evaluate_script_execution(b"powershell.exe -enc AAAA")["tags"]


def test_stage2022_heuristics_sources_have_no_repaired_string_coercions():
    checked = [
        Path("Virus_Scan/heuristics/downloader_patterns.py"),
        Path("Virus_Scan/heuristics/game_engine_threat_rules.py"),
        Path("Virus_Scan/heuristics/game_engine_threats.py"),
        Path("Virus_Scan/heuristics/obfuscation.py"),
        Path("Virus_Scan/heuristics/pickle_exec.py"),
        Path("Virus_Scan/heuristics/script_exec.py"),
    ]
    offenders = {}
    for path in checked:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        bad_lines = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
        for token in ("str(text or", "str(path or", "str(blob or", "str(engine or", "str(source or"):
            if token in source:
                bad_lines.append(0)
        if bad_lines:
            offenders[str(path)] = sorted(bad_lines)

    assert offenders == {}
