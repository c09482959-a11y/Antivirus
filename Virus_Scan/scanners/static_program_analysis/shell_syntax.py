"""Bounded structural parser for POSIX-style shell source.

The parser recognizes commands, pipelines, functions, simple control-flow
blocks, redirections, and here-document boundaries without invoking a shell.
Unsupported dynamic grammar is explicit and fail-closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

SHELL_MAX_PHYSICAL_LINES = 20_000
SHELL_MAX_LOGICAL_LINES = 20_000
SHELL_MAX_LINE_LENGTH = 16_384
SHELL_MAX_COMMANDS = 24_000
SHELL_MAX_FUNCTIONS = 4_096
SHELL_MAX_CONTINUATIONS = 64
SHELL_MAX_WORDS = 512
SHELL_MAX_BLOCK_DEPTH = 128

_FUNCTION = re.compile(
    r"^\s*(?:function\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:\(\s*\))?\s*\{(?P<body>.*)$"
)
_HEREDOC = re.compile(r"<<-?\s*(?P<quote>['\"]?)(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)\1")


class ShellSyntaxError(ValueError):
    """Raised when bounded shell parsing cannot safely continue."""


@dataclass(frozen=True, slots=True)
class ShellRedirection:
    operator: str
    target: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class ShellCommand:
    raw: str
    command: str
    words: tuple[str, ...]
    redirections: tuple[ShellRedirection, ...]
    line: int
    column: int
    end_line: int
    end_column: int
    condition_state: str
    separator: str
    scope: str


@dataclass(frozen=True, slots=True)
class ShellScript:
    commands: tuple[ShellCommand, ...]
    functions: tuple[str, ...]
    unresolved_constructs: tuple[str, ...]
    limitations: tuple[str, ...]


def _logical_lines(source: str) -> tuple[tuple[str, int, int], ...]:
    physical = source.splitlines()
    if len(physical) > SHELL_MAX_PHYSICAL_LINES:
        raise ShellSyntaxError("shell_physical_line_limit_exceeded")
    output: list[tuple[str, int, int]] = []
    current = ""
    start = 1
    continuations = 0
    for index, line in enumerate(physical, start=1):
        if len(line) > SHELL_MAX_LINE_LENGTH:
            raise ShellSyntaxError("shell_line_length_limit_exceeded")
        if not current:
            start = index
        stripped = line.rstrip()
        slash_count = len(stripped) - len(stripped.rstrip("\\"))
        if slash_count % 2:
            continuations += 1
            if continuations > SHELL_MAX_CONTINUATIONS:
                raise ShellSyntaxError("shell_continuation_limit_exceeded")
            current += stripped[:-1]
            continue
        current += line
        output.append((current, start, index))
        if len(output) > SHELL_MAX_LOGICAL_LINES:
            raise ShellSyntaxError("shell_logical_line_limit_exceeded")
        current = ""
        continuations = 0
    if current:
        output.append((current, start, len(physical) or 1))
    return tuple(output)


def _strip_comment(text: str) -> str:
    quote = ""
    escaped = False
    depth = 0
    for index, character in enumerate(text):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in "'\"":
            quote = character
            continue
        if character == "(" and index and text[index - 1] == "$":
            depth += 1
            continue
        if character == ")" and depth:
            depth -= 1
            continue
        if character == "#" and depth == 0 and (index == 0 or text[index - 1].isspace()):
            return text[:index]
    if quote:
        raise ShellSyntaxError("shell_quote_unterminated")
    return text


def _split_commands(text: str) -> tuple[tuple[str, str, int], ...]:
    output: list[tuple[str, str, int]] = []
    start = 0
    index = 0
    quote = ""
    escaped = False
    depth = 0
    separator = ""
    while index < len(text):
        character = text[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote:
            if character == quote:
                quote = ""
            index += 1
            continue
        if character in "'\"":
            quote = character
            index += 1
            continue
        if character == "(" and index and text[index - 1] == "$":
            depth += 1
            index += 1
            continue
        if character == ")" and depth:
            depth -= 1
            index += 1
            continue
        if depth == 0 and character in ";|&":
            token = character
            width = 1
            if index + 1 < len(text) and text[index + 1] == character and character in "|&":
                token += character
                width = 2
            segment = text[start:index].strip()
            if segment:
                output.append((segment, separator, start))
            separator = token
            start = index + width
            index += width
            continue
        index += 1
    if quote:
        raise ShellSyntaxError("shell_quote_unterminated")
    segment = text[start:].strip()
    if segment:
        output.append((segment, separator, start))
    return tuple(output)


def _words(text: str) -> tuple[str, ...]:
    output: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    substitution_depth = 0
    index = 0
    while index < len(text):
        character = text[index]
        if escaped:
            current.append(character)
            escaped = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote:
            if character == quote:
                quote = ""
            else:
                current.append(character)
            index += 1
            continue
        if character in "'\"":
            quote = character
            index += 1
            continue
        if character == "$" and index + 1 < len(text) and text[index + 1] == "(":
            substitution_depth += 1
            current.extend(("$", "("))
            index += 2
            continue
        if character == ")" and substitution_depth:
            substitution_depth -= 1
            current.append(character)
            index += 1
            continue
        if character.isspace() and substitution_depth == 0:
            if current:
                output.append("".join(current))
                current = []
                if len(output) > SHELL_MAX_WORDS:
                    raise ShellSyntaxError("shell_word_limit_exceeded")
            index += 1
            continue
        current.append(character)
        index += 1
    if quote or substitution_depth:
        raise ShellSyntaxError("shell_word_structure_unterminated")
    if current:
        output.append("".join(current))
    if len(output) > SHELL_MAX_WORDS:
        raise ShellSyntaxError("shell_word_limit_exceeded")
    return tuple(output)


def _remove_redirections(text: str, line: int) -> tuple[str, tuple[ShellRedirection, ...]]:
    output: list[str] = []
    redirects: list[ShellRedirection] = []
    index = 0
    quote = ""
    escaped = False
    while index < len(text):
        character = text[index]
        if escaped:
            output.append(character)
            escaped = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            output.append(character)
            escaped = True
            index += 1
            continue
        if quote:
            output.append(character)
            if character == quote:
                quote = ""
            index += 1
            continue
        if character in "'\"":
            quote = character
            output.append(character)
            index += 1
            continue
        if character in "<>" or (character.isdigit() and index + 1 < len(text) and text[index + 1] in "<>"):
            start = index
            if character.isdigit():
                index += 1
                character = text[index]
            operator = character
            index += 1
            if index < len(text) and text[index] == character:
                operator += character
                index += 1
            while index < len(text) and text[index].isspace():
                index += 1
            target_start = index
            if index < len(text) and text[index] in "'\"":
                target_quote = text[index]
                index += 1
                while index < len(text) and text[index] != target_quote:
                    if text[index] == "\\" and target_quote != "'" and index + 1 < len(text):
                        index += 2
                    else:
                        index += 1
                if index >= len(text):
                    raise ShellSyntaxError("shell_redirection_quote_unterminated")
                index += 1
            else:
                while index < len(text) and not text[index].isspace() and text[index] not in ";|&":
                    index += 1
            target = text[target_start:index].strip("'\"")
            if target and not target.startswith("&") and not operator.startswith("<<"):
                redirects.append(ShellRedirection(operator, target, line, start))
            output.append(" ")
            continue
        output.append(character)
        index += 1
    return "".join(output), tuple(redirects)


def _condition_state(text: str, unresolved: set[str]) -> str:
    value = text.strip().casefold()
    if value in {"true", ":", "test 1 -eq 1", "[ 1 -eq 1 ]"}:
        return "entrypoint_reachable"
    if value in {"false", "test 1 -eq 0", "[ 1 -eq 0 ]"}:
        return "unreachable"
    unresolved.add("environment_dependent_condition")
    return "conditional"


def parse_shell(source: str) -> ShellScript:
    if type(source) is not str:
        raise TypeError("shell_source_invalid")
    commands: list[ShellCommand] = []
    functions: list[str] = []
    unresolved: set[str] = set()
    limitations: set[str] = set()
    scope = "<module>"
    scope_stack: list[str] = []
    condition_stack: list[str] = []
    heredoc_delimiter = ""
    for raw_line, start_line, end_line in _logical_lines(source):
        stripped_raw = raw_line.strip()
        if heredoc_delimiter:
            if stripped_raw == heredoc_delimiter:
                heredoc_delimiter = ""
            continue
        if stripped_raw.startswith("#!"):
            continue
        clean = _strip_comment(raw_line).strip()
        if not clean:
            continue
        heredoc = _HEREDOC.search(clean)
        if heredoc is not None:
            heredoc_delimiter = heredoc.group("delimiter")
        function_match = _FUNCTION.match(clean)
        if function_match is not None:
            name = function_match.group("name")
            if len(functions) >= SHELL_MAX_FUNCTIONS:
                limitations.add("function_limit_exceeded")
            else:
                functions.append(name)
            scope_stack.append(scope)
            if len(scope_stack) > SHELL_MAX_BLOCK_DEPTH:
                raise ShellSyntaxError("shell_block_depth_exceeded")
            scope = name
            clean = function_match.group("body").strip()
            if not clean:
                continue
        if clean == "}":
            if not scope_stack:
                raise ShellSyntaxError("shell_function_close_without_open")
            scope = scope_stack.pop()
            continue
        lowered = clean.casefold()
        if lowered.startswith("if ") and (lowered.endswith(" then") or lowered.endswith("; then")):
            condition_text = clean[3:]
            condition_text = re.sub(r";?\s*then\s*$", "", condition_text, flags=re.IGNORECASE)
            condition_stack.append(_condition_state(condition_text, unresolved))
            if len(condition_stack) > SHELL_MAX_BLOCK_DEPTH:
                raise ShellSyntaxError("shell_block_depth_exceeded")
            continue
        if lowered == "else":
            if not condition_stack:
                raise ShellSyntaxError("shell_else_without_if")
            current = condition_stack[-1]
            condition_stack[-1] = (
                "unreachable" if current == "entrypoint_reachable"
                else "entrypoint_reachable" if current == "unreachable"
                else "conditional"
            )
            continue
        if lowered == "fi":
            if not condition_stack:
                raise ShellSyntaxError("shell_fi_without_if")
            condition_stack.pop()
            continue
        if re.match(r"^(?:for|while|until)\b.*(?:;\s*)?do$", clean, re.IGNORECASE):
            condition_stack.append("conditional")
            unresolved.add("loop_control_flow")
            continue
        if lowered == "done":
            if not condition_stack:
                raise ShellSyntaxError("shell_done_without_loop")
            condition_stack.pop()
            continue
        if lowered.startswith("case ") and lowered.endswith(" in"):
            condition_stack.append("conditional")
            unresolved.add("case_control_flow")
            continue
        if lowered == "esac":
            if not condition_stack:
                raise ShellSyntaxError("shell_esac_without_case")
            condition_stack.pop()
            continue
        state = "entrypoint_reachable"
        if "unreachable" in condition_stack:
            state = "unreachable"
        elif "conditional" in condition_stack:
            state = "conditional"
        for segment, separator, offset in _split_commands(clean):
            body, redirections = _remove_redirections(segment, start_line)
            words = _words(body.strip())
            if not words:
                continue
            if len(commands) >= SHELL_MAX_COMMANDS:
                limitations.add("command_limit_exceeded")
                continue
            commands.append(ShellCommand(
                raw=segment[:SHELL_MAX_LINE_LENGTH],
                command=words[0],
                words=words,
                redirections=redirections,
                line=start_line,
                column=max(0, offset),
                end_line=end_line,
                end_column=min(len(raw_line), SHELL_MAX_LINE_LENGTH),
                condition_state=state,
                separator=separator,
                scope=scope,
            ))
        if clean.endswith("}") and scope_stack:
            scope = scope_stack.pop()
    if heredoc_delimiter:
        raise ShellSyntaxError("shell_heredoc_unterminated")
    if scope_stack:
        raise ShellSyntaxError("shell_function_unterminated")
    if condition_stack:
        raise ShellSyntaxError("shell_control_block_unterminated")
    return ShellScript(
        commands=tuple(commands),
        functions=tuple(functions),
        unresolved_constructs=tuple(sorted(unresolved)),
        limitations=tuple(sorted(limitations)),
    )


__all__ = (
    "SHELL_MAX_BLOCK_DEPTH",
    "SHELL_MAX_COMMANDS",
    "SHELL_MAX_CONTINUATIONS",
    "SHELL_MAX_FUNCTIONS",
    "SHELL_MAX_LINE_LENGTH",
    "SHELL_MAX_LOGICAL_LINES",
    "SHELL_MAX_PHYSICAL_LINES",
    "SHELL_MAX_WORDS",
    "ShellCommand",
    "ShellRedirection",
    "ShellScript",
    "ShellSyntaxError",
    "parse_shell",
)
