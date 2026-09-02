from pathlib import Path

import pytest

from Virus_Scan.detection.chains.composite.attack_authority import high_gate_attack_chain_details
from Virus_Scan.detection.chains.composite.strong_partial import high_gate_calls
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.chains.composite.text_boundaries import composite_colon_join, composite_type_diagnostic
from Virus_Scan.detection.chains.composite.threat_intel import compute_threat_intel_layer


class HostileValue:
    def __str__(self):  # pragma: no cover - must never execute
        raise AssertionError("__str__ executed")

    def __repr__(self):  # pragma: no cover - must never execute
        raise AssertionError("__repr__ executed")

    def __format__(self, spec):  # pragma: no cover - must never execute
        raise AssertionError("__format__ executed")

    def __iter__(self):  # pragma: no cover - must never execute
        raise AssertionError("__iter__ executed")

    def __bool__(self):  # pragma: no cover - must never execute
        raise AssertionError("__bool__ executed")

    def keys(self):  # pragma: no cover - must never execute
        raise AssertionError("keys executed")

    def get(self, key, default=None):  # pragma: no cover - must never execute
        raise AssertionError("get executed")


def test_composite_text_boundaries_do_not_call_hostile_hooks():
    hostile = HostileValue()

    allowed, details = high_gate_attack_chain_details(
        evaluate_chain_evidence(api_calls=hostile)
    )
    assert allowed is False
    assert details == []
    assert composite_type_diagnostic("type:", hostile) == "type:HostileValue"
    assert composite_colon_join("chain_failure", hostile, "blocked") == "chain_failure::blocked"
    assert high_gate_calls((hostile, "CreateProcessA")) == frozenset({"createprocessa"})


def test_threat_intel_and_yara_sources_preserve_primitive_behavior():
    tags = ["process_exec", "network_download"]
    layer = compute_threat_intel_layer(
        tags, evaluate_chain_evidence(tags=tags), yara_hits=[]
    )
    assert layer["name"] == "Layer 4 Threat Intelligence"
    assert isinstance(layer["score"], float)
    assert isinstance(layer["hits"], list)

    assert not Path("Virus_Scan/detection/chains/composite/yara_candidates.py").exists()


def test_stage1987_composite_sources_remove_verified_hook_hazards():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "detection/chains/composite/behavior_detection.py").exists()
    assert not (root / "detection/chains/composite/profile_chains.py").exists()
    checked = {
        "detection/chains/composite/attack_authority.py": [
            'f"unsupported_api_calls_type:',
        ],
        "detection/chains/composite/audit_report.py": [
            ".keys()",
            "BUCKET_TAGS.values()",
            "isinstance(obj, dict)",
        ],
        "detection/chains/composite/strong_partial.py": [
            "str(call).strip()",
            "f'{source}_partial",
        ],
        "detection/chains/composite/text_behavior.py": [
            "return bool(fetch_tool and",
        ],
        "detection/chains/composite/threat_intel.py": [
            "attack.get(",
            "float(chain_score)",
            "f'ttp:",
            "f'high_fidelity:",
            "f\"family:",
            "f\"failure_evidence_recorded:",
        ],
    }
    assert not (root / "detection/chains/composite/policy.py").exists()
    assert not (root / "detection/chains/composite/signal_matching.py").exists()
    assert not (root / "contracts/chain_signal_matching.py").exists()
    for relative, forbidden in checked.items():
        source = (root / relative).read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in source, (relative, needle)
