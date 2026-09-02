from pathlib import Path

from Virus_Scan.detection.chains.composite import behavior_taxonomy
from Virus_Scan.detection.registries.chain_registry import chain_rule
from Virus_Scan.detection.chains.execution import anchors, syscall_sequence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_runtime_chain_event
from Virus_Scan.detection.chains.execution.text_boundaries import (
    execution_anchor_hit,
    execution_chain_id,
    pickle_global_trigger_text,
    pickle_opcode_window_part,
    pickle_reduce_trigger_text,
)


class HostileValue:
    def __str__(self):
        raise AssertionError("caller-owned __str__ executed")
    def __format__(self, spec):
        raise AssertionError("caller-owned __format__ executed")
    def __bool__(self):
        raise AssertionError("caller-owned __bool__ executed")


def test_stage1991_chain_identity_has_no_alias_or_parallel_family_owner():
    assert chain_rule("network_download_execute") is None
    assert not Path("Virus_Scan/detection/chains/composite/policy.py").exists()
    assert "CHAIN_FAMILY_ALIASES" not in behavior_taxonomy.__all__
    assert not hasattr(behavior_taxonomy, "CHAIN_FAMILY_ALIASES")
    assert not Path("Virus_Scan/detection/registries/chain_family_defaults.py").exists()
    assert not Path("Virus_Scan/detection/chains/composite/family_policy.py").exists()


def test_stage1991_execution_chain_identifiers_preserve_exact_strings_without_format_hooks():
    assert execution_chain_id("api_calls", "download_execute") == "api_calls_chain:download_execute"
    assert execution_anchor_hit("api_calls_chain:download_execute") == "anchor:ordered_api_calls_chain:download_execute"
    assert pickle_reduce_trigger_text("os.system", "reduce", 7, 9) == "os.system via REDUCE stream_offset=7 op_pos=9"
    assert pickle_global_trigger_text("builtins.eval") == "builtins.eval referenced by pickle GLOBAL/STACK_GLOBAL"
    assert pickle_opcode_window_part(12, "GLOBAL", "os system") == "12:GLOBAL os system"
    assert execution_chain_id(HostileValue(), "download_execute") == "none_chain:download_execute"


def test_stage1991_canonical_execution_boundary_classifies_observed_api_order():
    evidence = anchors.evaluate_chain_evidence(
        ordered_events=(
            physical_runtime_chain_event(
                "network_download", 1.0, 0, source_detector="stage1991_runtime_fixture",
            ),
            physical_runtime_chain_event(
                "process_exec", 2.0, 1, source_detector="stage1991_runtime_fixture",
            ),
        ),
        match_modes=("ordered",),
    )
    decision = next(item for item in evidence.confirmed if item.candidate.chain_id == "execution.download_execute")
    assert decision.candidate.order_class == "observed_order"
    syscall_result = syscall_sequence.detect_syscall_sequence_model(HostileValue(), tags=(HostileValue(),))
    assert syscall_result["score"] == 0.0
    assert "syscall_sequence_input_unavailable" in syscall_result["tags"]
