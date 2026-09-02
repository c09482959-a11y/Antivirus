from pathlib import Path
from types import SimpleNamespace

import pytest

from Virus_Scan.orchestration.lifecycle import attach_direct_audit_fields, report_results
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record


class _Runtime:
    scan_started_at = 0.0
    parent_cli = False

    def __init__(self):
        self._values = {}

    def set(self, key, value):
        self._values[key] = value

    def get(self, key, default=None):
        return self._values.get(key, default)


def test_reporting_rejects_stale_identity_without_canonical_context(tmp_path: Path) -> None:
    renpy = tmp_path / "renpy_game"
    (renpy / "game").mkdir(parents=True)
    (renpy / "game" / "script.rpy").write_text("label start:\n    pass\n", encoding="utf-8")
    dll = renpy / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZ" + b"assembly-csharp" + b"\0" * 64)

    args = SimpleNamespace(scheduler="serial", engine="auto", dir=str(renpy), output=str(tmp_path / "out.json"))
    stale = {
        str(dll): {
            "file": str(dll),
            "path": str(dll),
            "tags": [],
            "score": 0,
            "container_engine": "other",
            "artifact_engine": "other",
            "sniffed_type": "data",
            "baseline_key": "other::other::.dll::data",
            "learning_allowed": True,
        }
    }

    with pytest.raises(ValueError, match="canonical routing evidence"):
        attach_direct_audit_fields(args, stale, yara_ok=False)


def test_reporting_consumes_canonical_context_without_reclassifying(tmp_path: Path) -> None:
    renpy = tmp_path / "renpy_game"
    (renpy / "game").mkdir(parents=True)
    (renpy / "game" / "script.rpy").write_text("label start:\n    pass\n", encoding="utf-8")
    dll = renpy / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZ" + b"assembly-csharp" + b"\0" * 64)

    args = SimpleNamespace(scheduler="serial", engine="auto", dir=str(renpy), output=str(tmp_path / "out.json"))
    base = {"file": str(dll), "path": str(dll), "tags": [], "score": 0, "class": "benign_clean", "classification": "benign_clean"}
    canonical = attach_routing_evidence_to_record(base, dll, container_root=renpy, tags=[])

    annotated = attach_direct_audit_fields(args, {str(dll): canonical}, yara_ok=False)
    record = annotated[str(dll)]

    assert record["container_engine"] == "renpy"
    assert record["artifact_engine"] == "unity"
    assert record["sniffed_type"] in {"pe", "mono_dotnet_assembly"}
    assert record["cross_engine_artifact"] is True
    assert record["engine_mismatch"] is True
    assert record["learning_allowed"] is False
    assert record["baseline_key"].startswith("renpy::unity::.dll")


def test_reporting_rejects_malformed_static_analysis_summary(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    record = attach_routing_evidence_to_record(
        {"tags": []},
        sample,
        router_identity={
            "ext": ".bin",
            "magic_type": "unknown",
            "static_program_analysis": {"semantic_digest": "not-a-digest"},
        },
    )

    assert "static_program_analysis" not in record
