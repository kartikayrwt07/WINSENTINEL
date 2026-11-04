"""Zero-eval recursive-descent boolean AST condition parser for WinSentinel.

Parses arbitrary Sigma-inspired boolean conditions containing and, or, not,
parentheses, and quantifiers (e.g. '1 of selection*', 'all of selection*',
'1 of them') into a safe abstract syntax tree (AST) without dynamic code execution.
"""

from __future__ import annotations

import fnmatch
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class RuleSyntaxError(ValueError):
    """Raised when a detection rule boolean condition contains syntax errors."""


class TokenType(str, Enum):
    """Token categories for condition expressions."""

    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    QUANTIFIER_OF = "QUANTIFIER_OF"
    IDENTIFIER = "IDENTIFIER"
    EOF = "EOF"


@dataclass(frozen=True)
class Token:
    """Lexical token with position tracking for error reporting."""

    type: TokenType
    value: str
    position: int


class ASTNode(ABC):
    """Base class for all abstract syntax tree nodes in boolean condition expressions."""

    @abstractmethod
    def evaluate(self, context: dict[str, bool]) -> bool:
        """Evaluate this AST node against a dictionary mapping selection names to match booleans."""


class IdentifierNode(ASTNode):
    """Leaf node referencing a named selection or filter block."""

    def __init__(self, name: str) -> None:
        self.name = name

    def evaluate(self, context: dict[str, bool]) -> bool:
        return bool(context.get(self.name, False))

    def __repr__(self) -> str:
        return f"IdentifierNode({self.name!r})"


class NotNode(ASTNode):
    """Unary NOT node that inverts the evaluation of its operand."""

    def __init__(self, operand: ASTNode) -> None:
        self.operand = operand

    def evaluate(self, context: dict[str, bool]) -> bool:
        return not self.operand.evaluate(context)

    def __repr__(self) -> str:
        return f"NotNode({self.operand!r})"


class AndNode(ASTNode):
    """Binary AND node with short-circuit evaluation."""

    def __init__(self, left: ASTNode, right: ASTNode) -> None:
        self.left = left
        self.right = right

    def evaluate(self, context: dict[str, bool]) -> bool:
        if not self.left.evaluate(context):
            return False
        return self.right.evaluate(context)

    def __repr__(self) -> str:
        return f"AndNode(left={self.left!r}, right={self.right!r})"


class OrNode(ASTNode):
    """Binary OR node with short-circuit evaluation."""

    def __init__(self, left: ASTNode, right: ASTNode) -> None:
        self.left = left
        self.right = right

    def evaluate(self, context: dict[str, bool]) -> bool:
        if self.left.evaluate(context):
            return True
        return self.right.evaluate(context)

    def __repr__(self) -> str:
        return f"OrNode(left={self.left!r}, right={self.right!r})"


class QuantifierNode(ASTNode):
    """Quantifier node evaluating globs over selection names (e.g. '1 of selection*', 'all of selection*')."""

    def __init__(
        self,
        quantifier: str = "1 of",
        pattern: str = "*",
        count: int | str | None = None,
    ) -> None:
        if count is not None:
            self.count: int | str = count
            if isinstance(count, int) or (isinstance(count, str) and count.isdigit()):
                self.quantifier = f"{count} of"
            elif str(count).lower() == "all":
                self.quantifier = "all of"
            else:
                self.quantifier = str(count)
        else:
            self.quantifier = quantifier
            if quantifier.lower().startswith("all"):
                self.count = "all"
            else:
                prefix = quantifier.split()[0] if " " in quantifier else "1"
                self.count = int(prefix) if prefix.isdigit() else 1
        self.pattern = pattern

    def evaluate(self, context: dict[str, bool]) -> bool:
        if self.pattern.lower() == "them":
            # In Sigma specifications, 'them' refers to all selections, excluding filters
            matched_keys = [k for k in context if not k.lower().startswith("filter")]
        else:
            matched_keys = [k for k in context if fnmatch.fnmatch(k, self.pattern)]

        if not matched_keys:
            return False

        if self.quantifier.lower().startswith("all") or self.count == "all":
            return all(bool(context[k]) for k in matched_keys)

        threshold = int(self.count) if (isinstance(self.count, int) or (isinstance(self.count, str) and self.count.isdigit())) else 1
        return sum(1 for k in matched_keys if context[k]) >= threshold

    def __repr__(self) -> str:
        return f"QuantifierNode(quantifier={self.quantifier!r}, pattern={self.pattern!r})"


class ConditionTokenizer:
    """Safe lexical analyzer for boolean condition expressions."""

    _QUANTIFIER_REGEX = re.compile(r"^(all|\d+)\s+of\b", re.IGNORECASE)
    _IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_*]+")

    def tokenize(self, expression: str) -> list[Token]:
        """Convert expression string into a sequence of Tokens ending with EOF."""
        tokens: list[Token] = []
        i = 0
        n = len(expression)

        while i < n:
            ch = expression[i]

            # Skip whitespace
            if ch.isspace():
                i += 1
                continue

            # Grouping parentheses
            if ch == "(":
                tokens.append(Token(TokenType.LPAREN, "(", i))
                i += 1
                continue
            if ch == ")":
                tokens.append(Token(TokenType.RPAREN, ")", i))
                i += 1
                continue

            remaining = expression[i:]

            # Check quantifier pattern e.g. "1 of", "all of"
            quant_match = self._QUANTIFIER_REGEX.match(remaining)
            if quant_match:
                val = quant_match.group(0)
                tokens.append(Token(TokenType.QUANTIFIER_OF, val, i))
                i += len(val)
                continue

            # Check identifier/word pattern
            ident_match = self._IDENTIFIER_REGEX.match(remaining)
            if ident_match:
                val = ident_match.group(0)
                upper = val.upper()
                pos = i
                i += len(val)

                if upper == "AND":
                    tokens.append(Token(TokenType.AND, val, pos))
                elif upper == "OR":
                    tokens.append(Token(TokenType.OR, val, pos))
                elif upper == "NOT":
                    tokens.append(Token(TokenType.NOT, val, pos))
                else:
                    tokens.append(Token(TokenType.IDENTIFIER, val, pos))
                continue

            raise RuleSyntaxError(f"Unexpected character {ch!r} at position {i}")

        tokens.append(Token(TokenType.EOF, "", n))
        return tokens


class ConditionParser:
    """Recursive-descent parser for condition expressions.

    Precedence hierarchy:
      Expression -> OrExpression
      OrExpression -> AndExpression ('or' AndExpression)*
      AndExpression -> NotExpression ('and' NotExpression)*
      NotExpression -> 'not' NotExpression | PrimaryExpression
      PrimaryExpression -> '(' Expression ')' | Quantifier Identifier | Identifier
    """

    def __init__(self) -> None:
        self._tokenizer = ConditionTokenizer()
        self._tokens: list[Token] = []
        self._pos: int = 0

    def parse(self, expression: str) -> ASTNode:
        """Parse condition string into an executable ASTNode hierarchy."""
        if expression is None or not expression.strip():
            raise RuleSyntaxError("Empty condition expression")

        self._tokens = self._tokenizer.tokenize(expression)
        self._pos = 0

        node = self._parse_expression()

        if self._current().type != TokenType.EOF:
            tok = self._current()
            raise RuleSyntaxError(
                f"Unexpected token {tok.value!r} at position {tok.position}, expected end of expression"
            )

        return node

    def _current(self) -> Token:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return self._tokens[-1]

    def _advance(self) -> Token:
        tok = self._current()
        if self._pos < len(self._tokens) - 1:
            self._pos += 1
        return tok

    def _expect(self, token_type: TokenType) -> Token:
        tok = self._current()
        if tok.type != token_type:
            raise RuleSyntaxError(
                f"Expected {token_type.value} at position {tok.position}, got {tok.type.value} ({tok.value!r})"
            )
        return self._advance()

    def _parse_expression(self) -> ASTNode:
        return self._parse_or()

    def _parse_or(self) -> ASTNode:
        node = self._parse_and()
        while self._current().type == TokenType.OR:
            self._advance()
            right = self._parse_and()
            node = OrNode(left=node, right=right)
        return node

    def _parse_and(self) -> ASTNode:
        node = self._parse_not()
        while self._current().type == TokenType.AND:
            self._advance()
            right = self._parse_not()
            node = AndNode(left=node, right=right)
        return node

    def _parse_not(self) -> ASTNode:
        if self._current().type == TokenType.NOT:
            self._advance()
            operand = self._parse_not()
            return NotNode(operand=operand)
        return self._parse_primary()

    def _parse_primary(self) -> ASTNode:
        tok = self._current()

        if tok.type == TokenType.LPAREN:
            self._advance()
            expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return expr

        if tok.type == TokenType.QUANTIFIER_OF:
            quant_tok = self._advance()
            # Handle optional parentheses e.g. '1 of (selection*)'
            if self._current().type == TokenType.LPAREN:
                self._advance()
                pattern_tok = self._expect(TokenType.IDENTIFIER)
                self._expect(TokenType.RPAREN)
            else:
                pattern_tok = self._expect(TokenType.IDENTIFIER)

            quant_str = quant_tok.value.lower()
            if "all" in quant_str:
                return QuantifierNode(quantifier="all of", pattern=pattern_tok.value, count="all")
            num = quant_str.split()[0]
            cnt = int(num) if num.isdigit() else 1
            return QuantifierNode(quantifier=f"{cnt} of", pattern=pattern_tok.value, count=cnt)

        if tok.type == TokenType.IDENTIFIER:
            ident_tok = self._advance()
            return IdentifierNode(name=ident_tok.value)

        if tok.type == TokenType.EOF:
            raise RuleSyntaxError(f"Unexpected end of expression at position {tok.position}")

        raise RuleSyntaxError(
            f"Unexpected token {tok.value!r} of type {tok.type.value} at position {tok.position}"
        )
