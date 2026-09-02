"""Scanner-owned AST string extraction helpers."""

import ast

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_text
from Virus_Scan.contracts.string_eval import const_eval_string_node
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
STRINGS_AST_MAX_LITERAL_CHARS = _SCANNER_LIMITS_POLICY.strings_ast_max_literal_chars
STRINGS_AST_MAX_TEXT_CHARS = _SCANNER_LIMITS_POLICY.strings_ast_max_text_chars
STRINGS_AST_MAX_ITEMS = _SCANNER_LIMITS_POLICY.strings_ast_max_items


def _record_string_ast_failure(exc: object) -> object:
    try:
        record_suppressed_failure('suppressed_exception', exc, domain='runtime')
    except SCAN_CONTENT_ERRORS as reporting_exc:
        _ = reporting_exc


def _strings_ast_item_limit(max_items: object) -> int:
    item_limit, limit_reason = no_hook_exact_nonnegative_int(
        max_items,
        default=STRINGS_AST_MAX_ITEMS,
        reason='unsafe_strings_ast_max_items_rejected',
    )
    if limit_reason or item_limit == 0:
        return STRINGS_AST_MAX_ITEMS
    return item_limit


def _strings_ast_tree(code: object) -> tuple[ast.AST | None, str]:
    code_text, code_reason = no_hook_text(
        code,
        missing_reason='missing_strings_ast_code',
        unsupported_reason='unsafe_strings_ast_code_rejected',
    )
    if code_reason:
        return None, code_reason
    try:
        tree = ast.parse(code_text)
    except SCAN_CONTENT_ERRORS:
        return None, 'strings_ast_parse_failed'
    return tree, ''


def _strings_ast_environment(tree: ast.AST) -> dict[str, str]:
    environment: dict[str, str] = {}
    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value = const_eval_string_node(node.value, environment)
                if isinstance(value, str) and len(value) <= STRINGS_AST_MAX_LITERAL_CHARS:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            environment[target.id] = value
            elif isinstance(node, ast.AnnAssign):
                value = const_eval_string_node(node.value, environment) if node.value is not None else None
                if (
                    isinstance(value, str)
                    and isinstance(node.target, ast.Name)
                    and len(value) <= STRINGS_AST_MAX_LITERAL_CHARS
                ):
                    environment[node.target.id] = value
    except SCAN_CONTENT_ERRORS as exc:
        _record_string_ast_failure(exc)
    return environment


def _strings_ast_node_values(
    tree: ast.AST,
    environment: dict[str, str],
    item_limit: int,
) -> list[str]:
    values: list[str] = []
    try:
        for node in ast.walk(tree):
            value = const_eval_string_node(node, environment)
            if (
                isinstance(value, str)
                and value
                and len(value) <= STRINGS_AST_MAX_TEXT_CHARS
                and value not in values
            ):
                values.append(value)
                if len(values) >= item_limit:
                    break
    except SCAN_CONTENT_ERRORS as exc:
        _record_string_ast_failure(exc)
    return values


def _append_strings_ast_environment_values(
    values: list[str],
    environment: dict[str, str],
    item_limit: int,
) -> None:
    try:
        for value in tuple(dict.values(environment)):
            if value and value not in values:
                values.append(value)
                if len(values) >= item_limit:
                    break
    except SCAN_CONTENT_ERRORS as exc:
        _record_string_ast_failure(exc)


def _umige_ast_enriched_strings(code: object, max_items: object = None) -> object:
    """Extract literal and trivially-folded strings from Python/Ren'Py source."""
    item_limit = _strings_ast_item_limit(max_items)
    tree, tree_status = _strings_ast_tree(code)
    if tree_status or tree is None:
        return []
    environment = _strings_ast_environment(tree)
    values = _strings_ast_node_values(tree, environment, item_limit)
    _append_strings_ast_environment_values(values, environment, item_limit)
    return values


__all__ = ('_umige_ast_enriched_strings',)
