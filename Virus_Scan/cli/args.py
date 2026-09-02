"""Canonical public CLI argument parser for UMIGE startup."""
from __future__ import annotations

from collections.abc import Sequence
from Virus_Scan.cli.arg_parser_builders import build_parser
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_mapping_items, no_hook_plain_instance_dict
from argparse import Namespace
from types import SimpleNamespace

RECOVERABLE_RUNTIME_ERRORS = (ValueError, TypeError, AttributeError, OSError)
_OWNED_NAMESPACE_TYPES = (Namespace, SimpleNamespace)

def parse_args(argv: Sequence[str] | None = None) -> Namespace:
    """Parse UMIGE command-line arguments through the canonical parser."""
    return build_parser().parse_args(argv)


def _owned_arg_value(args: object, name: str, default: object | None = None) -> object | None:
    if type(name) is not str:
        return default
    data = no_hook_plain_instance_dict(args)
    if data is not None and name in data:
        return dict.get(data, name)
    try:
        mro = type.__getattribute__(type(args), "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return default
    if type(mro) is not tuple:
        return default
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError, RuntimeError):
            return default
        class_items = no_hook_mapping_items(class_dict)
        if class_items is None:
            return default
        for candidate_key, value in class_items:
            if type(candidate_key) is str and str.__eq__(candidate_key, name):
                if type(value) in (str, bool, int, float, tuple, list, dict, set, frozenset, type(None)):
                    return value
                return default
    return default


def normalize_runtime_args(args: object) -> object:
    """Normalize expensive runtime knobs after argparse.

    Stage 20 treats --partial-output-every 0 as disabled instead of forcing a
    write every file. Negative values are also disabled.
    """
    data = no_hook_plain_instance_dict(args)
    if data is None:
        return args
    n, reason = no_hook_exact_nonnegative_int(_owned_arg_value(args, "partial_output_every", 10), default=10, allow_exact_text=True)
    if reason:
        n = 10
    dict.__setitem__(data, "partial_output_every", 0 if n <= 0 else max(1, n))
    return args
