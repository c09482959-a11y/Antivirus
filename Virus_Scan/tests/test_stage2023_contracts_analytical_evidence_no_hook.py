from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.analytical_evidence import (
    analytical_correlation_ceiling,
    analytical_family_counts,
    analytical_format_oddity_snapshot,
    analytical_text_sequence,
)



class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned format hook was invoked")


class HostileFloat:
    touched = 0

    def __float__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned float hook was invoked")


def test_stage2023_analytical_text_sequence_rejection_is_no_hook() -> None:
    HostileText.touched = 0

    texts = analytical_text_sequence((HostileText(),))

    assert texts == ("unsafe_analytical_sequence_text_rejected:HostileText",)
    assert HostileText.touched == 0


def test_stage2023_analytical_family_aggregation_uses_owned_items() -> None:
    counts = analytical_family_counts(("exec", "network_url", "packed_payload"))
    ceiling = analytical_correlation_ceiling({"execution": 5, "network": 2, "obfuscation": 1})

    assert counts["execution"] > 0
    assert counts["network"] > 0
    assert ceiling["active_families"] == {"execution": 5, "network": 2, "obfuscation": 1}
    assert ceiling["capped_family_counts"] == {"execution": 3, "network": 2, "obfuscation": 1}
    assert 0.35 <= ceiling["correlation_multiplier"] <= 1.0


def test_stage2023_analytical_entropy_rejection_source_is_no_hook() -> None:
    HostileFloat.touched = 0

    oddity = analytical_format_oddity_snapshot(
        path="payload.exe",
        entropy=HostileFloat(),
        tags=("packed_payload",),
    )

    assert oddity["ready"] is False
    assert oddity["confidence_source"] == "unsafe_entropy_numeric_value_rejected_unavailable"
    assert HostileFloat.touched == 0


def test_stage2023_analytical_evidence_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/analytical_evidence.py"))

    forbidden = (
        'texts.append(f"{reason}:{no_hook_type_name(item)}")',
        "for family, needles in ANALYTICAL_TAG_FAMILIES.items()",
        "capped = {key: min(value, 3) for key, value in active.items()}",
        "total_active = sum(active.values())",
        "amplification = sum(capped.values()) / max(1, total_active)",
        '"confidence_source": f"{entropy_reason}_unavailable"',
        "data.get(\"values\")",
    )
    for snippet in forbidden:
        assert snippet not in source
