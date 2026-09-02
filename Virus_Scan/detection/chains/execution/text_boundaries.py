"""No-hook text and identifier boundaries for execution-chain detection."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text


def execution_text(value: object, *, default_text: str = "") -> str:
    if type(value) is str:
        return str.lower(str.strip(value))
    text, reason = no_hook_text(
        value,
        missing_reason="missing_execution_chain_text",
        unsupported_reason="unsafe_execution_chain_text_rejected",
    )
    if reason:
        return str.__str__(default_text) if type(default_text) is str else ""
    return str.lower(str.strip(text))


def execution_raw_text(value: object, *, default_text: str = "") -> str:
    if type(value) is str:
        return str.strip(value)
    text, reason = no_hook_text(
        value,
        missing_reason="missing_execution_chain_text",
        unsupported_reason="unsafe_execution_chain_text_rejected",
    )
    if reason:
        return str.__str__(default_text) if type(default_text) is str else ""
    return str.strip(text)


def execution_chain_id(source: object, chain_name: str) -> str:
    source_text = execution_text(source, default_text="none")
    chain_text = str.__str__(chain_name) if type(chain_name) is str else execution_text(chain_name, default_text="unavailable_chain")
    return str.__add__(str.__add__(source_text, "_chain:"), chain_text)


def execution_anchor_hit(value: object) -> str:
    return str.__add__("anchor:ordered_", execution_text(value, default_text="unavailable_ordered_chain"))


def execution_reason_hit(prefix: str, reason: object) -> str:
    prefix_text = str.__str__(prefix) if type(prefix) is str else "execution_reason:"
    return str.__add__(prefix_text, execution_text(reason, default_text="unavailable"))


def execution_unit_score(value: object) -> float:
    metric, reason = no_hook_finite_float(
        value,
        default=0.0,
        reason="unsafe_execution_chain_metric_rejected",
        non_finite_reason="unsafe_execution_chain_metric_rejected",
    )
    if reason:
        return 0.0
    if metric < 0.0:
        return 0.0
    if metric > 1.0:
        return 1.0
    return metric


def pickle_reduce_trigger_text(callable_name: object, opcode_name: object, stream_offset: int, op_position: int) -> str:
    left = str.__add__(execution_raw_text(callable_name), " via ")
    left = str.__add__(left, str.upper(execution_raw_text(opcode_name, default_text="REDUCE")))
    left = str.__add__(left, " stream_offset=")
    left = str.__add__(left, int.__str__(stream_offset))
    left = str.__add__(left, " op_pos=")
    return str.__add__(left, int.__str__(op_position))


def pickle_global_trigger_text(global_name: object) -> str:
    return str.__add__(execution_raw_text(global_name), " referenced by pickle GLOBAL/STACK_GLOBAL")


def pickle_opcode_window_part(position: int, opcode_name: object, argument_text: object = "") -> str:
    head = str.__add__(int.__str__(position), ":")
    head = str.__add__(head, execution_raw_text(opcode_name))
    arg = execution_raw_text(argument_text)
    if arg:
        return str.__add__(str.__add__(head, " "), arg)
    return head


__all__ = (
    "execution_anchor_hit",
    "execution_chain_id",
    "execution_raw_text",
    "execution_reason_hit",
    "execution_text",
    "execution_unit_score",
    "pickle_global_trigger_text",
    "pickle_opcode_window_part",
    "pickle_reduce_trigger_text",
)
