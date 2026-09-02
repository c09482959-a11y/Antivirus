from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.reporting.compact import display_tags_for_result, print_compact_scan_report
from Virus_Scan.reporting.evidence_line_text import clip_evidence_text, safe_report_mapping_get
from Virus_Scan.reporting.evidence_lines import cli_human_evidence_lines


class HostileDisplayValue:
    def __str__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __str__ invoked")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __repr__ invoked")

    def __format__(self, spec):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __format__ invoked")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __bool__ invoked")


class HostileIterable(list):
    def __iter__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __iter__ invoked")


class HostileMapping(Mapping):
    def __getitem__(self, key):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __getitem__ invoked")

    def __iter__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __iter__ invoked")

    def __len__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile __len__ invoked")

    def keys(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile keys invoked")

    def items(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile items invoked")

    def values(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile values invoked")

    def get(self, key, default=None):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile get invoked")


class HostileDict(dict):
    def __getitem__(self, key):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile dict __getitem__ invoked")

    def items(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile dict items invoked")

    def get(self, key, default=None):  # pragma: no cover - test fails if invoked
        raise AssertionError("hostile dict get invoked")


class HostileTypeNameMeta(type):
    def __getattribute__(cls, name):  # pragma: no cover - test fails if invoked
        if name in {"__name__", "__qualname__"}:
            raise AssertionError("hostile type name hook invoked")
        return super().__getattribute__(name)


class HostileTypeName(metaclass=HostileTypeNameMeta):
    pass


def test_stage1572_clip_evidence_text_rejects_hostile_display_hooks():
    assert clip_evidence_text(HostileDisplayValue()) == ""
    assert clip_evidence_text(HostileTypeName()) == ""


def test_stage1572_reporting_mapping_get_rejects_unknown_mapping_without_hooks():
    assert safe_report_mapping_get(HostileMapping(), "tags", "fallback") == "fallback"
    proxy = MappingProxyType(HostileDict({"tags": ["cmd_exec"]}))
    assert safe_report_mapping_get(proxy, "tags", "fallback") == "fallback"


def test_stage1572_display_tags_omits_hostile_values_without_stringifying():
    result = {
        "tags": [
            "file_seen",
            "cmd_exec",
            HostileDisplayValue(),
            HostileTypeName(),
            "encoded_powershell",
        ]
    }
    assert display_tags_for_result(result, 25.0) == ["cmd_exec", "encoded_powershell"]
    assert display_tags_for_result({"tags": HostileIterable(["cmd_exec"])}, 25.0) == []


def test_stage1572_cli_evidence_lines_omit_hostile_report_values(tmp_path):
    sample = tmp_path / "payload.ps1"
    sample.write_text("powershell.exe -enc AAAA https://example.test/payload", encoding="utf-8")
    result = {
        "tags": ["powershell_exec", "network_download", HostileDisplayValue()],
        "strings_blob": HostileDisplayValue(),
        "ordered_events": HostileIterable([{"tag": "powershell_exec", "raw": "powershell.exe -enc AAAA"}]),
        "yara_hits": [HostileDisplayValue(), "SuspiciousRule"],
    }
    lines = cli_human_evidence_lines(sample, result, max_lines=8)
    assert any(line.startswith("Url: https://example.test/payload") for line in lines)
    assert all("Hostile" not in line for line in lines)


def test_stage1572_compact_report_rejects_hostile_results_mapping(capsys):
    print_compact_scan_report(HostileMapping(), HostileDisplayValue(), elapsed_sec=HostileDisplayValue())
    captured = capsys.readouterr().out
    assert "Files: 0" in captured
    assert "Scan Time: unknown" in captured
    assert "Hostile" not in captured
