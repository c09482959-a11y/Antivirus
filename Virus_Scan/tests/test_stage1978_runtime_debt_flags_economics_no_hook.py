from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.runtime.runtime_debt import RuntimeDebtLedger
from Virus_Scan.runtime.runtime_economics_ledger import RuntimeEconomicsLedger
from Virus_Scan.runtime.runtime_flags import RuntimeFlagOwner


class HostileNumber:
    touched = 0

    def __float__(self) -> float:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile float hook executed")

    def __int__(self) -> int:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile int hook executed")

    def __repr__(self) -> str:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile repr hook executed")


class HostileChannels:
    touched = 0

    def items(self) -> object:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile channel items hook executed")

    def __iter__(self) -> object:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile channel iter hook executed")


class HostileFlagStore(dict):
    touched = 0

    def items(self) -> object:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile flag items hook executed")


def test_stage1978_runtime_debt_normalizes_hostile_cost_without_hooks() -> None:
    HostileNumber.touched = 0
    ledger = RuntimeDebtLedger()

    record = ledger.record("job", event=HostileNumber())

    assert record.workload_id == "job"
    assert record.event_cost == 0.0
    assert HostileNumber.touched == 0


def test_stage1978_runtime_economics_rejects_hostile_channels_without_items_hook() -> None:
    HostileChannels.touched = 0

    ledger = RuntimeEconomicsLedger(channels=HostileChannels())
    snapshot = ledger.snapshot()

    assert snapshot["admission_cost"] == 0.0
    assert ledger.input_evidence == ({"field": "channels", "reason": "runtime_economics_channels_rejected"},)
    assert HostileChannels.touched == 0


def test_stage1978_runtime_flag_snapshot_uses_exact_dict_owner() -> None:
    owner = RuntimeFlagOwner()
    owner._flags = HostileFlagStore({"runtime_model_state_dirty": True})

    snapshot = owner.snapshot()

    assert snapshot["runtime_model_state_dirty"] is True
    assert HostileFlagStore.touched == 0


def test_stage1978_runtime_source_closes_debt_economics_flag_rows() -> None:
    sources = {
        "runtime_debt.py": read_python_file(Path("Virus_Scan/runtime/runtime_debt.py")),
        "runtime_economics_ledger.py": read_python_file(Path("Virus_Scan/runtime/runtime_economics_ledger.py")),
        "runtime_flags.py": read_python_file(Path("Virus_Scan/runtime/runtime_flags.py")),
    }

    for filename, source in sources.items():
        tree = ast.parse(source, filename=filename)
        assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []

    debt_source = sources["runtime_debt.py"]
    assert "field_name=f\"runtime_debt_" not in debt_source
    assert "field_name=f\"runtime_debt_record_" not in debt_source
    assert "self._items.items()" not in debt_source
    assert "sorted(self._items.items" not in debt_source

    economics_source = sources["runtime_economics_ledger.py"]
    assert "key: value for key, value in sorted(dict.items(self.channels))" not in economics_source

    flags_source = sources["runtime_flags.py"]
    assert "{key: value for key, value in dict.items(self._flags)}" not in flags_source
