"""Bounded structural parser for Windows Batch/CMD source files.

The parser recognizes physical command lines, labels, constant IF reachability,
redirections, and static CALL/GOTO targets.  It never invokes ``cmd.exe`` or
expands the host environment.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

BATCH_CMD_MAX_PHYSICAL_LINES = 20_000
BATCH_CMD_MAX_LOGICAL_LINES = 20_000
BATCH_CMD_MAX_LINE_LENGTH = 16_384
BATCH_CMD_MAX_COMMANDS = 24_000
BATCH_CMD_MAX_LABELS = 4_096
BATCH_CMD_MAX_CONTINUATIONS = 64
BATCH_CMD_MAX_WORDS = 512

_LABEL = re.compile(r"^[A-Za-z0-9_.$?@#-]{1,128}$")
_CONSTANT_IF = re.compile(
    r"^if\s+(?P<negate>not\s+)?(?P<left>\"[^\"]*\"|[^\s=]+)=="
    r"(?P<right>\"[^\"]*\"|\S+)\s+(?P<body>.+)$",
    re.IGNORECASE,
)
_IF_EXIST = re.compile(r"^if\s+(?:not\s+)?(?:exist|defined|errorlevel|cmdextversion)\b\s*(?P<body>.*)$", re.IGNORECASE)
_FOR_BODY = re.compile(r"^for\b.*?\bdo\s+(?P<body>.+)$", re.IGNORECASE)


class BatchCmdSyntaxError(ValueError):
    """Raised when bounded structural parsing cannot safely continue."""


@dataclass(frozen=True, slots=True)
class BatchCmdRedirection:
    operator: str
    target: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class BatchCmdLabel:
    name: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class BatchCmdCommand:
    raw: str
    command: str
    words: tuple[str, ...]
    redirections: tuple[BatchCmdRedirection, ...]
    line: int
    column: int
    end_line: int
    end_column: int
    condition_state: str
    separator: str


@dataclass(frozen=True, slots=True)
class BatchCmdScript:
    commands: tuple[BatchCmdCommand, ...]
    labels: tuple[BatchCmdLabel, ...]
    unresolved_constructs: tuple[str, ...]
    limitations: tuple[str, ...]


def _has_continuation(text: str) -> bool:
    stripped = text.rstrip()
    count = 0
    for character in reversed(stripped):
        if character != "^":
            break
        count += 1
    return bool(count % 2)


def _logical_lines(source: str) -> tuple[tuple[str, int, int], ...]:
    physical = source.splitlines()
    if len(physical) > BATCH_CMD_MAX_PHYSICAL_LINES:
        raise BatchCmdSyntaxError("batch_physical_line_limit_exceeded")
    output: list[tuple[str, int, int]] = []
    current = ""
    start = 1
    continuation_count = 0
    for index, line in enumerate(physical, start=1):
        if len(line) > BATCH_CMD_MAX_LINE_LENGTH:
            raise BatchCmdSyntaxError("batch_line_length_limit_exceeded")
        if not current:
            start = index
        fragment = line
        if _has_continuation(fragment):
            continuation_count += 1
            if continuation_count > BATCH_CMD_MAX_CONTINUATIONS:
                raise BatchCmdSyntaxError("batch_continuation_limit_exceeded")
            fragment = fragment.rstrip()[:-1]
            current += fragment
            continue
        current += fragment
        output.append((current, start, index))
        if len(output) > BATCH_CMD_MAX_LOGICAL_LINES:
            raise BatchCmdSyntaxError("batch_logical_line_limit_exceeded")
        current = ""
        continuation_count = 0
    if current:
        output.append((current, start, len(physical) or 1))
    return tuple(output)


def _split_commands(text: str) -> tuple[tuple[str, str, int], ...]:
    output: list[tuple[str, str, int]] = []
    start = 0
    index = 0
    quote = False
    escaped = False
    separator = ""
    while index < len(text):
        character = text[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "^":
            escaped = True
            index += 1
            continue
        if character == '"':
            quote = not quote
            index += 1
            continue
        if not quote and character in "&|":
            token = character
            width = 1
            if index + 1 < len(text) and text[index + 1] == character:
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
    segment = text[start:].strip()
    if segment:
        output.append((segment, separator, start))
    return tuple(output)


def _unescape_word(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "^" and index + 1 < len(value):
            index += 1
        output.append(value[index])
        index += 1
    text = "".join(output)
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1]
    return text


def _words(text: str) -> tuple[str, ...]:
    output: list[str] = []
    current: list[str] = []
    quote = False
    escaped = False
    for character in text:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "^":
            escaped = True
            continue
        if character == '"':
            quote = not quote
            current.append(character)
            continue
        if character.isspace() and not quote:
            if current:
                output.append(_unescape_word("".join(current)))
                current = []
                if len(output) > BATCH_CMD_MAX_WORDS:
                    raise BatchCmdSyntaxError("batch_word_limit_exceeded")
            continue
        current.append(character)
    if escaped:
        current.append("^")
    if quote:
        raise BatchCmdSyntaxError("batch_quote_unterminated")
    if current:
        output.append(_unescape_word("".join(current)))
    if len(output) > BATCH_CMD_MAX_WORDS:
        raise BatchCmdSyntaxError("batch_word_limit_exceeded")
    return tuple(output)


def _remove_redirections(text: str, line: int) -> tuple[str, tuple[BatchCmdRedirection, ...]]:
    output: list[str] = []
    redirections: list[BatchCmdRedirection] = []
    index = 0
    quote = False
    escaped = False
    while index < len(text):
        character = text[index]
        if escaped:
            output.append(character)
            escaped = False
            index += 1
            continue
        if character == "^":
            output.append(character)
            escaped = True
            index += 1
            continue
        if character == '"':
            quote = not quote
            output.append(character)
            index += 1
            continue
        if not quote and character in "<>" or (
            not quote and character.isdigit() and index + 1 < len(text) and text[index + 1] in "<>"
        ):
            start = index
            if character.isdigit():
                index += 1
                character = text[index]
            operator = character
            index += 1
            if character == ">" and index < len(text) and text[index] == ">":
                operator = ">>"
                index += 1
            while index < len(text) and text[index].isspace():
                index += 1
            target_start = index
            if index < len(text) and text[index] == '"':
                index += 1
                while index < len(text) and text[index] != '"':
                    if text[index] == "^" and index + 1 < len(text):
                        index += 2
                    else:
                        index += 1
                if index >= len(text):
                    raise BatchCmdSyntaxError("batch_redirection_quote_unterminated")
                index += 1
            else:
                while index < len(text) and not text[index].isspace() and text[index] not in "&|":
                    index += 1
            target = _unescape_word(text[target_start:index])
            if target and not target.startswith("&"):
                redirections.append(BatchCmdRedirection(operator, target, line, start))
            output.append(" ")
            continue
        output.append(character)
        index += 1
    return "".join(output), tuple(redirections)


def _condition(segment: str, unresolved: set[str]) -> tuple[str, str]:
    match = _CONSTANT_IF.match(segment)
    if match is not None:
        left = match.group("left")
        right = match.group("right")
        body = match.group("body").strip()
        dynamic = any(marker in left + right for marker in ("%", "!"))
        if dynamic:
            unresolved.add("dynamic_if_condition")
            return body, "conditional"
        equal = left.casefold() == right.casefold()
        if match.group("negate"):
            equal = not equal
        return body, "entrypoint_reachable" if equal else "unreachable"
    match = _IF_EXIST.match(segment)
    if match is not None:
        body = match.group("body").strip()
        unresolved.add("environment_dependent_if_condition")
        return body, "conditional"
    match = _FOR_BODY.match(segment)
    if match is not None:
        unresolved.add("for_loop_control_flow")
        return match.group("body").strip(), "conditional"
    return segment, "entrypoint_reachable"


def parse_batch_cmd(source: str) -> BatchCmdScript:
    if type(source) is not str:
        raise TypeError("batch_source_invalid")
    commands: list[BatchCmdCommand] = []
    labels: list[BatchCmdLabel] = []
    unresolved: set[str] = set()
    limitations: set[str] = set()
    for raw_line, start_line, end_line in _logical_lines(source):
        stripped = raw_line.strip()
        while stripped.startswith("@"):
            stripped = stripped[1:].lstrip()
        if not stripped:
            continue
        lowered = stripped.casefold()
        if lowered == "rem" or lowered.startswith("rem ") or stripped.startswith("::"):
            continue
        if stripped.startswith(":"):
            label = stripped[1:].strip().casefold()
            if not _LABEL.fullmatch(label):
                unresolved.add("dynamic_or_invalid_label")
                continue
            if len(labels) >= BATCH_CMD_MAX_LABELS:
                limitations.add("label_limit_exceeded")
                continue
            labels.append(BatchCmdLabel(label, start_line, raw_line.find(":") + 1))
            continue
        for segment, separator, offset in _split_commands(stripped):
            body, condition_state = _condition(segment, unresolved)
            without_redirections, redirections = _remove_redirections(body, start_line)
            words = _words(without_redirections.strip())
            if not words:
                continue
            command = words[0].casefold()
            if command in {"(", ")", "else"}:
                unresolved.add("parenthesized_or_else_block")
                continue
            if len(commands) >= BATCH_CMD_MAX_COMMANDS:
                limitations.add("command_limit_exceeded")
                continue
            commands.append(BatchCmdCommand(
                raw=body[:BATCH_CMD_MAX_LINE_LENGTH],
                command=command,
                words=words,
                redirections=redirections,
                line=start_line,
                column=max(0, offset),
                end_line=end_line,
                end_column=min(len(raw_line), BATCH_CMD_MAX_LINE_LENGTH),
                condition_state=condition_state,
                separator=separator,
            ))
    return BatchCmdScript(
        commands=tuple(commands),
        labels=tuple(labels),
        unresolved_constructs=tuple(sorted(unresolved)),
        limitations=tuple(sorted(limitations)),
    )


__all__ = (
    "BATCH_CMD_MAX_COMMANDS",
    "BATCH_CMD_MAX_CONTINUATIONS",
    "BATCH_CMD_MAX_LABELS",
    "BATCH_CMD_MAX_LINE_LENGTH",
    "BATCH_CMD_MAX_LOGICAL_LINES",
    "BATCH_CMD_MAX_PHYSICAL_LINES",
    "BATCH_CMD_MAX_WORDS",
    "BatchCmdCommand",
    "BatchCmdLabel",
    "BatchCmdRedirection",
    "BatchCmdScript",
    "BatchCmdSyntaxError",
    "parse_batch_cmd",
)
