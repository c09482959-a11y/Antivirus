from __future__ import annotations

import logging
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.cli.args import normalize_runtime_args
from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.core.logging import configure_single_parent_log
from Virus_Scan.orchestration import lifecycle
from Virus_Scan.stress.corpus_builder import _contract_field
from Virus_Scan.stress.corpus_types import EngineFileTypeContract
from Virus_Scan.utils.text_validation import text_boundary_value


_STAGE2084_DIRECT_GETATTRIBUTE_FREE_MODULES = (
    Path("Virus_Scan/core/logging.py"),
    Path("Virus_Scan/core/paths.py"),
    Path("Virus_Scan/orchestration/lifecycle.py"),
    Path("Virus_Scan/utils/text_validation.py"),
    Path("Virus_Scan/stress/corpus_builder.py"),
    Path("Virus_Scan/cli/args.py"),
)


def test_stage2084_local_no_hook_call_sites_are_centralized() -> None:
    for module_path in _STAGE2084_DIRECT_GETATTRIBUTE_FREE_MODULES:
        assert "object.__getattribute__" not in module_path.read_text(encoding="utf-8")


def test_stage2084_simplenamespace_instance_dict_is_canonical_no_hook_boundary() -> None:
    args = SimpleNamespace(partial_output_every="0")
    assert no_hook_plain_instance_dict(args) == {"partial_output_every": "0"}
    normalized = normalize_runtime_args(args)
    assert normalized is args
    assert args.partial_output_every == 0


def test_stage2084_argparse_namespace_still_mutates_without_local_getattribute() -> None:
    args = Namespace(partial_output_every="4")
    normalized = normalize_runtime_args(args)
    assert normalized is args
    assert args.partial_output_every == 4


def test_stage2084_orchestration_owned_attr_rejects_hostile_getattribute() -> None:
    class Hostile:
        def __init__(self) -> None:
            object.__setattr__(self, "calls", [])
            object.__setattr__(self, "value", "unsafe")

        def __getattribute__(self, name: str):  # noqa: ANN001
            object.__getattribute__(self, "calls").append(name)
            raise AssertionError("hostile getter executed")

    hostile = Hostile()
    assert lifecycle._owned_attr(hostile, "value", "fallback") == "fallback"
    assert lifecycle._set_owned_attr(hostile, "value", "changed") is False
    assert object.__getattribute__(hostile, "calls") == []


def test_stage2084_orchestration_bound_method_uses_canonical_owner_field() -> None:
    class Owned:
        def is_process_shard(self) -> bool:
            return False

    method = lifecycle._owned_bound_method(Owned(), "is_process_shard")
    assert method is not None
    assert method() is False



def test_stage2084_text_boundary_rejects_hostile_instance_dict_without_hook_execution() -> None:
    class HostileText:
        def __init__(self) -> None:
            object.__setattr__(self, "calls", [])
            object.__setattr__(self, "text", "unsafe")

        def __getattribute__(self, name: str):  # noqa: ANN001
            object.__getattribute__(self, "calls").append(name)
            raise AssertionError("hostile getter executed")

    hostile = HostileText()
    assert text_boundary_value(hostile, unsupported="rejected") == "rejected"
    assert object.__getattribute__(hostile, "calls") == []


def test_stage2084_stress_contract_field_uses_canonical_owner_field() -> None:
    contract = EngineFileTypeContract("engine", "bucket", ".ext", "native")
    assert _contract_field(contract, "engine") == "engine"
    assert _contract_field(contract, "extension") == ".ext"
    assert _contract_field(object(), "engine") == ""


def test_stage2084_configure_single_parent_log_reuses_existing_filehandler(tmp_path: Path) -> None:
    log_path = tmp_path / "scan.log"
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    try:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        first = configure_single_parent_log(str(log_path))
        second = configure_single_parent_log(str(log_path))
        file_handlers = [handler for handler in root.handlers if type(handler) is logging.FileHandler]
        assert first == second == str(log_path.resolve())
        assert len(file_handlers) == 1
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        for handler in original_handlers:
            root.addHandler(handler)
