"""Canonical safe static string expression evaluator."""
from __future__ import annotations
import ast

_STRING_EVAL_UNAVAILABLE = None


def const_eval_string_node(node: object, env: dict[str, str] | None = None, depth: int = 0) -> str | None:
    if depth > 4:
        return _STRING_EVAL_UNAVAILABLE
    env = env if type(env) is dict else {}
    try:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            val = dict.get(env, node.id)
            return val if isinstance(val, str) else _STRING_EVAL_UNAVAILABLE
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = const_eval_string_node(node.left, env, depth + 1)
            right = const_eval_string_node(node.right, env, depth + 1)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    return _STRING_EVAL_UNAVAILABLE
            return ''.join(parts)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = const_eval_string_node(node.func.value, env, depth + 1)
            if isinstance(base, str) and node.func.attr == 'replace' and len(node.args) == 2:
                a = const_eval_string_node(node.args[0], env, depth + 1)
                b = const_eval_string_node(node.args[1], env, depth + 1)
                if isinstance(a, str) and isinstance(b, str):
                    return base.replace(a, b)
    except (ValueError, TypeError, UnicodeError):
        return _STRING_EVAL_UNAVAILABLE
    return _STRING_EVAL_UNAVAILABLE
