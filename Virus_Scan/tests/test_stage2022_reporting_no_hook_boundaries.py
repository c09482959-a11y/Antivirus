import ast
from pathlib import Path

from Virus_Scan.reporting import compact, result_schema
from Virus_Scan.virustotal import reporting as virustotal
from Virus_Scan.core.logging import emit_parent_scan_log_event
from Virus_Scan.reporting.evidence_line_text import safe_report_text
from Virus_Scan.reporting.risk_label import risk_label_from_score


class HostileReportValue:
    touched = []

    @classmethod
    def reset(cls):
        cls.touched.clear()

    def _hit(self, name):
        type(self).touched.append(name)
        return "hostile"

    def __str__(self):
        return self._hit("__str__")

    def __repr__(self):
        return self._hit("__repr__")

    def __format__(self, spec):
        return self._hit("__format__")

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

    def __lt__(self, other):
        type(self).touched.append("__lt__")
        return False

    def __float__(self):
        type(self).touched.append("__float__")
        return 99.0

    def __int__(self):
        type(self).touched.append("__int__")
        return 99

    def __fspath__(self):
        return self._hit("__fspath__")


class HostileReportMapping:
    def get(self, key, default=None):
        HostileReportValue.touched.append("mapping.get")
        return default

    def items(self):
        HostileReportValue.touched.append("mapping.items")
        return ()

    def __bool__(self):
        HostileReportValue.touched.append("mapping.__bool__")
        return True


def test_stage2022_reporting_text_limit_rejects_hostile_limit_without_hooks():
    HostileReportValue.reset()

    assert safe_report_text("abcdef", limit=HostileReportValue()) == "abcdef"

    assert HostileReportValue.touched == []


def test_stage2022_reporting_display_boundaries_reject_hostile_values_without_hooks(capsys):
    hostile = HostileReportValue()
    result = {
        "score": 55.0,
        "tags": ["cmd_exec", hostile],
        "yara_hits": [hostile, "hit_rule"],
        "strings_blob": "",
    }
    results = {hostile: result}
    HostileReportValue.reset()

    assert risk_label_from_score(hostile) == "LOW"
    assert compact.display_tags_for_result(result, hostile) == []
    compact.print_compact_scan_report(results, hostile, output_path=hostile, yara_rule_count=hostile)

    assert "FINAL RESULT" in capsys.readouterr().out
    assert HostileReportValue.touched == []


def test_stage2022_virustotal_runtime_event_boundary_rejects_hostile_values_without_hooks():
    hostile = HostileReportValue()
    HostileReportValue.reset()

    try:
        emit_parent_scan_log_event("VT", {"hostile": hostile}, mirror_console=False)
    except (TypeError, ValueError):
        pass
    else:
        raise AssertionError("hostile VirusTotal scanlog payload accepted")
    vt_row = virustotal._new_row("", 0.0, "unknown", "a" * 64, "unknown")

    assert vt_row["path"] == ""
    assert vt_row["content_sha256"] == "a" * 64
    assert HostileReportValue.touched == []


def test_stage2022_reporting_result_schema_rejects_hostile_evidence_without_hooks():
    hostile = HostileReportValue()
    HostileReportValue.reset()

    terminal = result_schema.make_terminal_asset_result(hostile, [hostile], cache_sha256=hostile)
    rec = result_schema._umige_record_decoded_result([], set(), b"powershell -enc aaa", hostile, hostile, 1, hostile, chain=[hostile])

    assert terminal["path"] == ""
    assert rec is not None
    assert rec["raw_sample"] == "HostileReportValue"
    assert HostileReportValue.touched == []


def test_stage2022_reporting_sources_have_no_fstring_formatting():
    paths = sorted(Path("Virus_Scan/reporting").glob("*.py")) + sorted(Path("Virus_Scan/virustotal").glob("*.py"))
    offenders = {}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        lines = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
        if lines:
            offenders[str(path)] = lines

    assert offenders == {}
