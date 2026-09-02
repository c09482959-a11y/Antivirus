from pathlib import Path

from Virus_Scan.routing.file_identity import sniff_file_identity
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage378_dotnet_metadata_without_mz_is_sniffed_as_dotnet(tmp_path: Path):
    sample = tmp_path / "managed.bytes"
    sample.write_bytes(
        b"BSJB #~ #Strings #US mscoree.dll System.Reflection "
        b"Assembly.Load Type.GetType MethodInfo.Invoke PowerShell WebClient DownloadString Process.Start"
    )

    identity = sniff_file_identity(sample)

    assert identity.sniffed_type == "mono_dotnet_assembly"
    assert "structure:dotnet_metadata_without_pe_magic" in identity.evidence


def test_stage378_compact_record_emits_functional_evidence_fields_for_dotnet_and_stego():
    record = {
        "file": "payload.dat",
        "path": "payload.dat",
        "input_file_path": "payload.dat",
        "score": 92.0,
        "classification": "malicious",
        "declared_extension": ".dat",
        "sniffed_type": "mono_dotnet_assembly",
        "tags": [
            "binary_failover_scan",
            "extension_mismatch",
            "assembly_load",
            "reflection",
            "dynamic_loader",
            "powershell_exec",
            "network_download_execute",
            "process_exec",
        ],
        "decoded_evidence_snippets": ["PowerShell WebClient DownloadString Process.Start"],
        "explanation": {
            "classification": "malicious",
            "score": 92.0,
            "reasons": ["PowerShell WebClient DownloadString Process.Start"],
        },
    }

    compact = compact_result_record(record)

    assert compact["binary_failover_tags"]
    assert compact["dotnet_findings"]
    assert compact["ilspy_findings"] == ["ilspy_not_available_static_metadata_used"]
    assert compact["dncil_findings"]
    assert compact["decoded_evidence_snippets"]


def test_stage378_compact_record_emits_stego_polyglot_findings():
    record = {
        "file": "image.png",
        "path": "image.png",
        "input_file_path": "image.png",
        "score": 25.0,
        "classification": "low_confidence",
        "declared_extension": ".png",
        "sniffed_type": "png",
        "sniffed_embedded_types": ["pe"],
        "tags": [
            "image_stego_checked",
            "polyglot_artifact",
            "embedded_pe_payload",
            "png_invalid_chunk_length",
            "stego_statistical_anomaly",
        ],
        "decoded_evidence_snippets": ["EmbeddedPayload: PE payload marker observed inside declared media/container artifact"],
        "explanation": {
            "classification": "low_confidence",
            "score": 25.0,
            "reasons": ["EmbeddedPayload: PE payload marker observed inside declared media/container artifact"],
        },
    }

    compact = compact_result_record(record)

    assert compact["stego_findings"]
    assert "embedded_pe_payload" in compact["stego_findings"]
