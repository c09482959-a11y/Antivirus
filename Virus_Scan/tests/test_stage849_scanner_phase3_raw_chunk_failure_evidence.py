from Virus_Scan.scanners.raw_chunk_engine_collectors import unity_dotnet_chunk
from Virus_Scan.scanners.raw_chunk_headers import il2cpp_header


def _read_range_text(_path, *, start=0, size=None):
    return "Assembly-CSharp UnityEngine MonoBehaviour"


def _context_off(_text):
    return False


def _contextual_scan(*_args, **_kwargs):
    return []


def _context_failure(tags, collector, exc, *, path=None, start=0):
    tags.append(f"{collector}_context_failure")
    return tags


def test_unity_dotnet_il_extract_failure_emits_scanner_evidence(tmp_path):
    sample = tmp_path / "game.dll"
    sample.write_bytes(b"Assembly-CSharp UnityEngine MonoBehaviour")
    reports = []

    def extract_il_patterns(_text):
        raise ValueError("bad il pattern stream")

    result = unity_dotnet_chunk(
        str(sample),
        read_range_text_func=_read_range_text,
        extract_il_patterns=extract_il_patterns,
        analyze_il_pipeline=None,
        should_context_scan_func=_context_off,
        contextual_scan=_contextual_scan,
        context_failure=_context_failure,
        report_issue=lambda *args, **kwargs: reports.append((args, kwargs)),
    )
    tags = {str(tag).lower() for tag in result["tags"]}

    assert reports
    assert "raw_unity_dotnet_il_extract_failed" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "unity_dotnet_il_extract_scan_error" in tags
    assert "scanner_failure_evidence:binary:unity_dotnet_il_extract" in tags


def test_unity_dotnet_il_pipeline_failure_emits_scanner_evidence(tmp_path):
    sample = tmp_path / "game.dll"
    sample.write_bytes(b"Assembly-CSharp UnityEngine MonoBehaviour")
    reports = []

    def analyze_il_pipeline(*_args, **_kwargs):
        raise RuntimeError("il pipeline failed")

    result = unity_dotnet_chunk(
        str(sample),
        read_range_text_func=_read_range_text,
        extract_il_patterns=lambda _text: ["Call"],
        analyze_il_pipeline=analyze_il_pipeline,
        should_context_scan_func=_context_off,
        contextual_scan=_contextual_scan,
        context_failure=_context_failure,
        report_issue=lambda *args, **kwargs: reports.append((args, kwargs)),
    )
    tags = {str(tag).lower() for tag in result["tags"]}

    assert reports
    assert "raw_unity_dotnet_il_pipeline_failed" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "unity_dotnet_il_pipeline_scan_error" in tags
    assert "scanner_failure_evidence:binary:unity_dotnet_il_pipeline" in tags


def test_il2cpp_header_read_failure_emits_scanner_evidence(tmp_path):
    sample = tmp_path / "global-metadata.dat"

    def read_file_bytes(_path, *, max_size=None):
        raise OSError("cannot read il2cpp header")

    result = il2cpp_header(str(sample), read_file_bytes=read_file_bytes)
    tags = {str(tag).lower() for tag in result["tags"]}

    assert "raw_il2cpp_header_read_failed" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "il2cpp_header_read_scan_error" in tags
    assert "scanner_failure_evidence:binary:il2cpp_header_read" in tags
