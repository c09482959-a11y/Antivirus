"""Bounded PowerShell lexical and structural parser.

This module parses source structure only. It never invokes PowerShell, expands
profiles, loads modules, or evaluates expressions.
"""
from __future__ import annotations

from dataclasses import dataclass

POWERSHELL_MAX_TOKENS = 120_000
POWERSHELL_MAX_STATEMENTS = 20_000
POWERSHELL_MAX_NESTING = 128


class PowerShellSyntaxError(ValueError):
    """Raised when bounded PowerShell structure cannot be parsed safely."""


@dataclass(frozen=True, slots=True)
class PowerShellToken:
    kind: str
    value: str
    line: int
    column: int
    end_line: int
    end_column: int
    quote: str = ""
    interpolated_variables: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PowerShellCommand:
    tokens: tuple[PowerShellToken, ...]


@dataclass(frozen=True, slots=True)
class PowerShellAssignment:
    variable: PowerShellToken
    expression: tuple[PowerShellToken, ...]


@dataclass(frozen=True, slots=True)
class PowerShellFunction:
    name: PowerShellToken
    body: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class PowerShellIf:
    keyword: PowerShellToken
    condition: tuple[PowerShellToken, ...]
    then_body: tuple[object, ...]
    else_body: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class PowerShellScript:
    statements: tuple[object, ...]
    token_count: int


def _advance(character: str, line: int, column: int) -> tuple[int, int]:
    return (line + 1, 0) if character == "\n" else (line, column + 1)


def tokenize_powershell(source: str) -> tuple[PowerShellToken, ...]:
    """Tokenize one bounded PowerShell source string without evaluation."""
    if type(source) is not str:
        raise TypeError("powershell_source_text_required")
    tokens: list[PowerShellToken] = []
    index = 0
    line = 1
    column = 0
    length = len(source)

    def append(
        kind: str,
        value: str,
        start_line: int,
        start_column: int,
        quote: str = "",
        interpolated_variables: tuple[str, ...] = (),
    ) -> None:
        if len(tokens) >= POWERSHELL_MAX_TOKENS:
            raise OverflowError("powershell_token_limit_exceeded")
        tokens.append(PowerShellToken(
            kind,
            value,
            start_line,
            start_column,
            line,
            column,
            quote,
            interpolated_variables,
        ))

    def interpolation_name(position: int) -> str:
        if position >= length or source[position] != "$":
            return ""
        cursor = position + 1
        if cursor < length and source[cursor] == "{":
            cursor += 1
            start = cursor
            while cursor < length and source[cursor] != "}":
                if source[cursor] == "\n":
                    return ""
                cursor += 1
            if cursor >= length:
                return ""
            name = source[start:cursor]
        else:
            start = cursor
            while cursor < length and (source[cursor].isalnum() or source[cursor] in "_:?"):
                cursor += 1
            name = source[start:cursor]
        return name.casefold() if name and (name[0].isalpha() or name[0] == "_") else ""

    while index < length:
        character = source[index]
        if character in " \t\r":
            line, column = _advance(character, line, column)
            index += 1
            continue
        if character == "\n":
            start_line, start_column = line, column
            line, column = _advance(character, line, column)
            index += 1
            append("newline", "\n", start_line, start_column)
            continue
        if source.startswith("<#", index):
            index += 2
            column += 2
            closed = False
            while index < length:
                if source.startswith("#>", index):
                    index += 2
                    column += 2
                    closed = True
                    break
                line, column = _advance(source[index], line, column)
                index += 1
            if not closed:
                raise PowerShellSyntaxError("powershell_block_comment_unterminated")
            continue
        if character == "#":
            while index < length and source[index] != "\n":
                line, column = _advance(source[index], line, column)
                index += 1
            continue
        if character == "`":
            start_line, start_column = line, column
            line, column = _advance(character, line, column)
            index += 1
            if index >= length:
                append("word", "`", start_line, start_column)
                continue
            escaped = source[index]
            line, column = _advance(escaped, line, column)
            index += 1
            if escaped != "\n":
                append("word", escaped, start_line, start_column)
            continue
        if source.startswith('@"', index) or source.startswith("@'", index):
            quote = source[index + 1]
            start_line, start_column = line, column
            line, column = _advance("@", line, column)
            line, column = _advance(quote, line, column)
            index += 2
            if index < length and source[index] == "\r":
                line, column = _advance(source[index], line, column)
                index += 1
            if index >= length or source[index] != "\n":
                raise PowerShellSyntaxError("powershell_here_string_header_invalid")
            line, column = _advance(source[index], line, column)
            index += 1
            value: list[str] = []
            interpolated: list[str] = []
            closed = False
            while index < length:
                if column == 0 and source.startswith(quote + "@", index):
                    line, column = _advance(quote, line, column)
                    line, column = _advance("@", line, column)
                    index += 2
                    closed = True
                    break
                current = source[index]
                if quote == '"' and current == "`" and index + 1 < length:
                    escaped = source[index + 1]
                    translations = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "`": "`", "$": "$"}
                    value.append(translations.get(escaped, escaped))
                    line, column = _advance(current, line, column)
                    line, column = _advance(escaped, line, column)
                    index += 2
                    continue
                if quote == '"' and current == "$":
                    name = interpolation_name(index)
                    if name:
                        interpolated.append(name)
                value.append(current)
                line, column = _advance(current, line, column)
                index += 1
            if not closed:
                raise PowerShellSyntaxError("powershell_here_string_unterminated")
            append(
                "string",
                "".join(value),
                start_line,
                start_column,
                "@" + quote,
                tuple(dict.fromkeys(interpolated)),
            )
            continue
        if character in "'\"":
            quote = character
            start_line, start_column = line, column
            line, column = _advance(character, line, column)
            index += 1
            value: list[str] = []
            interpolated: list[str] = []
            closed = False
            while index < length:
                current = source[index]
                if current == quote:
                    if quote == "'" and index + 1 < length and source[index + 1] == "'":
                        value.append("'")
                        index += 2
                        column += 2
                        continue
                    line, column = _advance(current, line, column)
                    index += 1
                    closed = True
                    break
                if quote == '"' and current == "`" and index + 1 < length:
                    escaped = source[index + 1]
                    translations = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "`": "`", "$": "$"}
                    value.append(translations.get(escaped, escaped))
                    line, column = _advance(current, line, column)
                    line, column = _advance(escaped, line, column)
                    index += 2
                    continue
                if quote == '"' and current == "$":
                    name = interpolation_name(index)
                    if name:
                        interpolated.append(name)
                value.append(current)
                line, column = _advance(current, line, column)
                index += 1
            if not closed:
                raise PowerShellSyntaxError("powershell_string_unterminated")
            append(
                "string",
                "".join(value),
                start_line,
                start_column,
                quote,
                tuple(dict.fromkeys(interpolated)),
            )
            continue
        if character == "$":
            start_line, start_column = line, column
            value = [character]
            line, column = _advance(character, line, column)
            index += 1
            if index < length and source[index] == "{":
                value.append("{")
                column += 1
                index += 1
                while index < length and source[index] != "}":
                    current = source[index]
                    if current == "\n":
                        raise PowerShellSyntaxError("powershell_variable_invalid")
                    value.append(current)
                    column += 1
                    index += 1
                if index >= length:
                    raise PowerShellSyntaxError("powershell_variable_unterminated")
                value.append("}")
                column += 1
                index += 1
            else:
                while index < length and (source[index].isalnum() or source[index] in "_:?"):
                    value.append(source[index])
                    column += 1
                    index += 1
            append("variable", "".join(value), start_line, start_column)
            continue
        if character in "{}()[];,|=":
            start_line, start_column = line, column
            line, column = _advance(character, line, column)
            index += 1
            append("symbol", character, start_line, start_column)
            continue
        start_line, start_column = line, column
        value = []
        while index < length:
            current = source[index]
            if current.isspace() or current in "{}()[];,|='\"#$":
                break
            if source.startswith("<#", index):
                break
            value.append(current)
            line, column = _advance(current, line, column)
            index += 1
        if not value:
            value.append(character)
            line, column = _advance(character, line, column)
            index += 1
        text = "".join(value)
        kind = "number" if text.isdigit() else "word"
        append(kind, text, start_line, start_column)
    return tuple(tokens)


class _Parser:
    def __init__(self, tokens: tuple[PowerShellToken, ...]) -> None:
        self.tokens = tokens
        self.index = 0
        self.statement_count = 0

    def parse(self) -> PowerShellScript:
        statements = self._block(stop_on_brace=False, depth=0)
        if self.index != len(self.tokens):
            raise PowerShellSyntaxError("powershell_parser_trailing_tokens")
        return PowerShellScript(statements, len(self.tokens))

    def _peek(self, offset: int = 0) -> PowerShellToken | None:
        position = self.index + offset
        return self.tokens[position] if position < len(self.tokens) else None

    def _consume(self) -> PowerShellToken:
        token = self._peek()
        if token is None:
            raise PowerShellSyntaxError("powershell_parser_unexpected_eof")
        self.index += 1
        return token

    def _skip_separators(self) -> None:
        while True:
            token = self._peek()
            if token is None or not (
                token.kind == "newline" or (token.kind == "symbol" and token.value == ";")
            ):
                return
            self.index += 1

    def _block(self, *, stop_on_brace: bool, depth: int) -> tuple[object, ...]:
        if depth > POWERSHELL_MAX_NESTING:
            raise OverflowError("powershell_nesting_limit_exceeded")
        statements: list[object] = []
        while True:
            self._skip_separators()
            token = self._peek()
            if token is None:
                if stop_on_brace:
                    raise PowerShellSyntaxError("powershell_block_unterminated")
                return tuple(statements)
            if token.kind == "symbol" and token.value == "}":
                if not stop_on_brace:
                    raise PowerShellSyntaxError("powershell_unexpected_closing_brace")
                self.index += 1
                return tuple(statements)
            statement = self._statement(depth)
            if statement is not None:
                self.statement_count += 1
                if self.statement_count > POWERSHELL_MAX_STATEMENTS:
                    raise OverflowError("powershell_statement_limit_exceeded")
                statements.append(statement)

    def _statement(self, depth: int) -> object | None:
        token = self._peek()
        if token is None:
            return None
        lower = token.value.lower() if token.kind == "word" else ""
        if lower in {"function", "filter"}:
            return self._function(depth)
        if lower == "if":
            return self._if(depth)
        tokens = self._line_tokens()
        if not tokens:
            return None
        if len(tokens) >= 2 and tokens[0].kind == "variable" and tokens[1].kind == "symbol" and tokens[1].value == "=":
            return PowerShellAssignment(tokens[0], tuple(tokens[2:]))
        return PowerShellCommand(tuple(tokens))

    def _line_tokens(self) -> list[PowerShellToken]:
        output: list[PowerShellToken] = []
        nesting = 0
        while True:
            token = self._peek()
            if token is None:
                break
            if nesting == 0 and (
                token.kind == "newline"
                or (token.kind == "symbol" and token.value in {";", "}"})
            ):
                if token.value != "}":
                    self.index += 1
                break
            token = self._consume()
            if token.kind == "symbol" and token.value in {"(", "["}:
                nesting += 1
            elif token.kind == "symbol" and token.value in {")", "]"}:
                nesting -= 1
                if nesting < 0:
                    raise PowerShellSyntaxError("powershell_group_unbalanced")
            output.append(token)
        if nesting != 0:
            raise PowerShellSyntaxError("powershell_group_unterminated")
        return output

    def _function(self, depth: int) -> PowerShellFunction:
        self._consume()
        name = self._consume()
        if name.kind not in {"word", "string"} or not name.value.strip():
            raise PowerShellSyntaxError("powershell_function_name_invalid")
        self._skip_separators()
        opening = self._consume()
        if opening.kind != "symbol" or opening.value != "{":
            raise PowerShellSyntaxError("powershell_function_block_missing")
        return PowerShellFunction(name, self._block(stop_on_brace=True, depth=depth + 1))

    def _condition(self) -> tuple[PowerShellToken, ...]:
        opening = self._peek()
        if opening is not None and opening.kind == "symbol" and opening.value == "(":
            self.index += 1
            depth = 1
            output: list[PowerShellToken] = []
            while depth:
                token = self._consume()
                if token.kind == "symbol" and token.value == "(":
                    depth += 1
                elif token.kind == "symbol" and token.value == ")":
                    depth -= 1
                    if depth == 0:
                        break
                output.append(token)
            return tuple(output)
        output = []
        while True:
            token = self._peek()
            if token is None:
                raise PowerShellSyntaxError("powershell_if_block_missing")
            if token.kind == "symbol" and token.value == "{":
                return tuple(output)
            output.append(self._consume())

    def _if(self, depth: int) -> PowerShellIf:
        keyword = self._consume()
        condition = self._condition()
        self._skip_separators()
        opening = self._consume()
        if opening.kind != "symbol" or opening.value != "{":
            raise PowerShellSyntaxError("powershell_if_block_missing")
        then_body = self._block(stop_on_brace=True, depth=depth + 1)
        self._skip_separators()
        else_body: tuple[object, ...] = ()
        token = self._peek()
        if token is not None and token.kind == "word" and token.value.lower() == "else":
            self.index += 1
            self._skip_separators()
            opening = self._consume()
            if opening.kind != "symbol" or opening.value != "{":
                raise PowerShellSyntaxError("powershell_else_block_missing")
            else_body = self._block(stop_on_brace=True, depth=depth + 1)
        return PowerShellIf(keyword, condition, then_body, else_body)


def parse_powershell(source: str) -> PowerShellScript:
    return _Parser(tokenize_powershell(source)).parse()


__all__ = (
    "POWERSHELL_MAX_NESTING",
    "POWERSHELL_MAX_STATEMENTS",
    "POWERSHELL_MAX_TOKENS",
    "PowerShellAssignment",
    "PowerShellCommand",
    "PowerShellFunction",
    "PowerShellIf",
    "PowerShellScript",
    "PowerShellSyntaxError",
    "PowerShellToken",
    "parse_powershell",
    "tokenize_powershell",
)
