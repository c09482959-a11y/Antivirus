from pathlib import Path

from Virus_Scan.routing.file_identity import (
    ACCEPTED_EQUIVALENT_SNIFFED_TYPES,
    sniff_file_identity,
)


def test_stage389_equivalent_sniff_types_are_module_owned_immutable():
    assert ACCEPTED_EQUIVALENT_SNIFFED_TYPES["pe"] == frozenset({"mono_dotnet_assembly"})
    try:
        ACCEPTED_EQUIVALENT_SNIFFED_TYPES["pe"] = frozenset()
    except TypeError:
        pass
    else:  # pragma: no cover - MappingProxyType must reject mutation.
        raise AssertionError("equivalent sniff type policy must be immutable")


def test_stage389_dotnet_dll_equivalence_does_not_mark_extension_mismatch(tmp_path):
    sample = tmp_path / "Assembly-CSharp.dll"
    sample.write_bytes(b"MZ" + b"\0" * 128 + b"BSJB" + b"mscorlib" + b"UnityEngine")
    identity = sniff_file_identity(sample)
    assert identity.sniffed_type == "mono_dotnet_assembly"
    assert identity.extension_mismatch is False
    assert "structure:unity_dotnet_or_runtime" in identity.evidence
