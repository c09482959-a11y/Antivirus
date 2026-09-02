from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_bool,
    contract_field_issue,
    contract_float,
    contract_int,
    contract_mapping_items,
    contract_mapping_rejected,
    contract_mapping_value,
    contract_sequence,
    contract_text,
    first_contract_mapping_value,
    merge_contract_issues,
)


class HostileContractValue:
    def __getattribute__(self, name: str):  # pragma: no cover - must not be invoked
        raise AssertionError(f"hostile __getattribute__ invoked for {name}")

    def __bool__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __bool__ invoked")

    def __iter__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __iter__ invoked")

    def __len__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __len__ invoked")

    def __str__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __str__ invoked")


class HookedMapping(dict[str, object]):
    def __iter__(self):  # pragma: no cover - exact dict required
        raise AssertionError("mapping __iter__ hook invoked")

    def items(self):  # pragma: no cover - no-hook materializer must bypass this
        raise AssertionError("mapping items hook invoked")


class HookedSequence(list[object]):
    def __iter__(self):  # pragma: no cover - exact list/tuple required
        raise AssertionError("sequence __iter__ hook invoked")


def test_stage2135_contract_scalar_rejections_are_typed_no_hook_evidence() -> None:
    hostile = HostileContractValue()

    assert contract_field_issue(hostile, field_name="payload", reason="rejected") == {
        "scheduler_contract_field_rejected": True,
        "field_name": "payload",
        "reason": "rejected",
        "value_type": "HostileContractValue",
    }

    text, text_issues = contract_text(hostile, field_name="text", default="fallback")
    assert text == "fallback"
    assert text_issues[0]["reason"] == "scheduler_contract_text_rejected"

    integer, integer_issues = contract_int(hostile, field_name="count", default=7, minimum=2)
    assert integer == 7
    assert integer_issues[0]["reason"] == "scheduler_contract_int_rejected"

    real, real_issues = contract_float(hostile, field_name="elapsed", default=1.5, minimum=0.0)
    assert real == 1.5
    assert real_issues[0]["reason"] == "scheduler_contract_float_rejected"

    flag, flag_issues = contract_bool(hostile, field_name="failed", default=False)
    assert flag is False
    assert flag_issues[0]["reason"] == "scheduler_contract_bool_rejected"


def test_stage2135_contract_mapping_helpers_distinguish_absence_from_rejection() -> None:
    hostile = HostileContractValue()
    exact_mapping = {"missing": None, "primary": "value", 7: "ignored"}
    proxy = MappingProxyType({"proxy": 3})

    assert contract_mapping_items(hostile) is None
    assert contract_mapping_rejected(None, field_name="payload") == ()
    rejected = contract_mapping_rejected(hostile, field_name="payload")
    assert rejected[0]["reason"] == "scheduler_contract_mapping_rejected"

    assert contract_mapping_value(hostile, "primary", default="fallback") == "fallback"
    assert contract_mapping_value(exact_mapping, "primary", default="fallback") == "value"
    assert contract_mapping_value(exact_mapping, "missing", default="fallback") is None
    assert first_contract_mapping_value(exact_mapping, "missing", "primary", default="fallback") == "value"
    assert contract_mapping_value(proxy, "proxy", default=0) == 3
    assert contract_mapping_items(HookedMapping({"hooked": "rejected"})) is None


def test_stage2135_contract_sequence_and_issue_merge_are_explicit_boundaries() -> None:
    hostile = HostileContractValue()

    values, value_issues = contract_sequence(("alpha", 2), field_name="items")
    assert values == ("alpha", 2)
    assert value_issues == ()

    rejected_values, rejected_issues = contract_sequence(hostile, field_name="items")
    assert rejected_values == ()
    assert rejected_issues[0]["reason"] == "scheduler_contract_sequence_rejected"
    assert contract_sequence(HookedSequence(["unsafe"]), field_name="items")[0] == ()

    merged = merge_contract_issues((), ["a"], ("b",), "c", None)
    assert merged == ("a", "b", "c")
