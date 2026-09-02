from Virus_Scan.detection.enrichment.strings.boundaries import enrichment_sequence
from Virus_Scan.detection.enrichment.strings.contextual.scan import ContextualTagScanRequest, contextual_tag_scan
from Virus_Scan.detection.enrichment.strings.micro_stage import micro_stage_collect


class TruthHostileText:
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return self._text

    def __bool__(self):  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned text truthiness was probed")


class TruthHostileSequence:
    def __init__(self, values):
        self._values = tuple(values)

    def __iter__(self):
        return iter(self._values)

    def __bool__(self):  # pragma: no cover - must never be reached
        raise AssertionError("helper-returned sequence truthiness was probed")


def test_contextual_tag_scan_does_not_truth_test_text_or_source():
    tags = contextual_tag_scan(ContextualTagScanRequest(
        TruthHostileText("os.system('powershell -enc AAA http://example.test')"),
        path="game/script.rpy",
        source=TruthHostileText("strings"),
        finalize=False,
    ))

    assert "process_exec" in tags
    assert "script_execution" in tags


def test_micro_stage_runtime_context_does_not_truth_test_payload():
    tags = micro_stage_collect(
        "runtime_context",
        TruthHostileText("subprocess.run(['cmd.exe', '/c', 'curl http://example.test'])"),
        path="game/script.rpy",
    )

    assert "process_exec" in tags
    assert "script_execution" in tags


def test_enrichment_sequence_freezes_without_truthiness_fallback():
    assert enrichment_sequence(TruthHostileSequence(["tag_a", "tag_b"])) == ("tag_a", "tag_b")
    assert enrichment_sequence(None) == ()
