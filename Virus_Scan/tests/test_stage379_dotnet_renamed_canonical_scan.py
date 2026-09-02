from pathlib import Path

from Virus_Scan.scanners.dotnet import scan_unity_dotnet_layered_file, unity_ilspy_should_run
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage379_renamed_bytes_dotnet_uses_canonical_dotnet_scanner(tmp_path: Path):
    sample = tmp_path / "Assembly-CSharp.bytes"
    sample.write_bytes(
        b"BSJB #~ #Strings #US mscoree.dll UnityEngine Assembly-CSharp "
        b"System.Reflection Assembly.Load Type.GetType MethodInfo.Invoke "
        b"PowerShell WebClient DownloadString Process.Start call callvirt ldstr newobj"
    )

    tags, meta = scan_unity_dotnet_layered_file(sample, finalize=False)

    assert meta["is_dotnet"] is True
    assert meta["dncil_used"] is True
    assert "extension_mismatch" in tags
    assert "binary_failover_dotnet_metadata" in tags
    assert "unity_managed" in tags
    assert "pseudo_dncil_il_scan" in tags
    assert "powershell_exec" in tags
    assert "network_download" in tags
    assert "process_exec" in tags


def test_stage379_ilspy_gate_reports_disabled_not_clean_for_renamed_dotnet(tmp_path: Path):
    sample = tmp_path / "payload.dat"
    sample.write_bytes(b"BSJB #~ #Strings #US mscoree.dll System.Reflection Assembly.Load")

    should_run, ctx = unity_ilspy_should_run(sample, tags=["extension_mismatch"], strings_blob=sample.read_bytes().decode("latin1"))

    assert should_run is False
    assert ctx["is_dotnet"] is True
    assert ctx["reason"] == "ilspy_disabled"


def test_stage379_compact_json_preserves_dncil_ops_from_scanner_meta():
    record = {
        "file": "Assembly-CSharp.bytes",
        "path": "Assembly-CSharp.bytes",
        "input_file_path": "Assembly-CSharp.bytes",
        "score": 87.0,
        "classification": "high_confidence",
        "declared_extension": ".bytes",
        "sniffed_type": "mono_dotnet_assembly",
        "effective_analysis_engine": "unity_dotnet",
        "tags": [
            "extension_mismatch",
            "binary_failover_dotnet_metadata",
            "unity_managed",
            "pseudo_dncil_il_scan",
            "il_op_call",
            "il_op_ldstr",
            "assembly_load",
            "powershell_exec",
        ],
        "decoded_evidence_snippets": ["PowerShell Assembly.Load Process.Start"],
        "explanation": {"classification": "high_confidence", "score": 87.0, "reasons": []},
    }

    compact = compact_result_record(record)

    assert "binary_failover_dotnet_metadata" in compact["binary_failover_tags"]
    assert compact["dotnet_findings"]
    assert "pseudo_dncil_il_scan" in compact["dncil_findings"]
