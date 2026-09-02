import Virus_Scan.scanners.image as image
import Virus_Scan.scanners.ilspy as ilspy
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scanners.dotnet import scan_unity_dotnet_layered_file, unity_ilspy_should_run

from pathlib import Path


def test_stage380_clean_imports_use_canonical_image_and_ilspy_modules():

    assert callable(image.scan_image_file)
    assert callable(ilspy.scan_unity_ilspy_file)
    assert callable(scan_unity_dotnet_layered_file)
    assert callable(unity_ilspy_should_run)


def test_stage380_renamed_managed_asset_uses_ilspy_and_dncil_metadata(tmp_path):

    sample = tmp_path / "Assembly-CSharp.asset"
    sample.write_bytes(
        b"MZ\0\0BSJB #~ #Strings #US mscoree.dll "
        b"System.Reflection Assembly.Load Type.GetType MethodInfo.Invoke "
        b"PowerShell WebClient DownloadString Process.Start "
        b"call ldstr callvirt newobj stsfld UnityEngine Assembly-CSharp"
    )

    tags, meta = scan_unity_dotnet_layered_file(sample)

    assert "extension_mismatch" in tags
    assert "binary_failover_dotnet_metadata" in tags
    assert "pseudo_dncil_il_scan" in tags
    assert "il_behavior_signal" in tags
    assert meta["is_dotnet"] is True
    assert meta["dncil_used"] is True
    assert meta["ilspy_gate"] == "enabled"
    assert meta.get("diagnostic_reason") == "ilspy_disabled"


def test_stage380_media_module_was_replaced_by_canonical_image_module():
    assert Path("Virus_Scan/scanners/image.py").exists()
    assert not Path("Virus_Scan/scanners/media.py").exists()


def test_stage380_malformed_pe_like_record_gets_explicit_json_warning():

    compact = compact_result_record({
        "path": "malformed.dll",
        "file": "malformed.dll",
        "classification": "benign_clean",
        "score": 2.0,
        "declared_extension": ".dll",
        "extension": "dll",
        "sniffed_type": "pe",
        "tags": ["magic_type_pe_mz"],
        "warnings": [],
    })

    assert "malformed_or_non_dotnet_pe_static_metadata_only" in compact["warnings"]
    assert compact["binary_failover_tags"] == ["magic_type_pe_mz"]
